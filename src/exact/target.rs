use super::encryption::{encrypt_poly, rerandomize_poly_with_witness};
use std::io::{self, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream};

use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{
    combine_public_keys, test_zero, Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare,
    SecretKeyShare,
};
pub use crate::crypto::poly::poly_from_roots;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireCiphertext {
    pub c1: [u8; 32],
    pub c2: [u8; 32],
}

impl WireCiphertext {
    pub fn from_native(ct: &Ciphertext) -> Self {
        WireCiphertext {
            c1: ct.c1.compress().to_bytes(),
            c2: ct.c2.compress().to_bytes(),
        }
    }
    pub fn to_native(&self) -> Result<Ciphertext, String> {
        let c1 = CompressedRistretto::from_slice(&self.c1)
            .decompress()
            .ok_or("c1 not on curve")?;
        let c2 = CompressedRistretto::from_slice(&self.c2)
            .decompress()
            .ok_or("c2 not on curve")?;
        Ok(Ciphertext { c1, c2 })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireEncryptedPoly(pub Vec<WireCiphertext>);

/// A ciphertext vector with its canonical wire encoding. Proof transcripts bind
/// the encoding while the proof equations use the native points, so the two must
/// agree. The fields are private, and the only constructors compress a native vector
/// or decode wire bytes (decoding accepts only canonical encodings), so they always
/// do. Each point is thus compressed or decompressed once per party.
#[derive(Clone, Debug)]
pub(crate) struct EncodedPoly {
    native: EncryptedPoly,
    wire: WireEncryptedPoly,
}
impl EncodedPoly {
    pub fn from_native(native: EncryptedPoly) -> Self {
        let wire = WireEncryptedPoly::from_native(&native);
        Self { native, wire }
    }
    pub fn from_wire(wire: WireEncryptedPoly) -> Result<Self, String> {
        Ok(Self {
            native: wire.to_native()?,
            wire,
        })
    }
    pub fn native(&self) -> &EncryptedPoly {
        &self.native
    }
    pub fn wire(&self) -> &WireEncryptedPoly {
        &self.wire
    }
    #[cfg(test)]
    pub fn into_native(self) -> EncryptedPoly {
        self.native
    }
}

impl WireEncryptedPoly {
    pub fn from_native(p: &EncryptedPoly) -> Self {
        WireEncryptedPoly(p.0.iter().map(WireCiphertext::from_native).collect())
    }
    pub fn to_native(&self) -> Result<EncryptedPoly, String> {
        let cts: Result<Vec<_>, _> = self.0.iter().map(|w| w.to_native()).collect();
        Ok(EncryptedPoly(cts?))
    }
}

pub fn send_msg<T: Serialize>(stream: &mut TcpStream, msg: &T) -> io::Result<()> {
    let bytes =
        bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = (bytes.len() as u32).to_be_bytes();
    let mut bufs: &mut [IoSlice<'_>] = &mut [IoSlice::new(&len), IoSlice::new(&bytes)];
    let total = len.len() + bytes.len();
    let mut written = 0;
    while written < total {
        let n = stream.write_vectored(bufs)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "could not write message",
            ));
        }
        written += n;
        IoSlice::advance_slices(&mut bufs, n);
    }
    Ok(())
}

pub fn recv_msg<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds size limit",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(len as u64)
        .reject_trailing_bytes()
        .deserialize(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Accepted local ciphertext and its proof. Proof context is retained alongside it.
pub struct StoredPolynomial {
    pub ciphertext: WireEncryptedPoly,
    pub proof: Option<super::TPolyProof>,
    pub session: [u8; 32],
    pub round: u64,
}
impl StoredPolynomial {
    pub fn costs(&self) -> io::Result<super::measurements::StorageCosts> {
        use super::measurements::{size, StorageCosts};
        Ok(StorageCosts {
            ciphertext_bytes: size(&self.ciphertext)?,
            proof_bytes: self.proof.as_ref().map(size).transpose()?.unwrap_or(0),
        })
    }
    fn send(&self, s: &mut TcpStream) -> io::Result<()> {
        if let Some(p) = &self.proof {
            send_msg(s, &(&self.ciphertext, p))
        } else {
            send_msg(s, &self.ciphertext)
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct DeploymentMeasurement {
    pub latency_s: f64,
    pub storage: super::measurements::StorageCosts,
    pub generator_setup: super::performance::GeneratorActivity,
}
#[derive(Clone, Copy, Debug)]
pub struct InteractionMeasurement {
    pub latency_s: f64,
    pub target_time_s: f64,
    pub monitor_started_unix_ns: u128,
    pub target_stored_unix_ns: u128,
    pub communication: super::measurements::InteractionCosts,
    pub generator_setup: super::performance::GeneratorActivity,
}

pub struct Target {
    config: super::ProtocolConfig,
    t_set: Vec<Scalar>,
    sk1: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    pub state: u64,
    stored: Option<StoredPolynomial>,
    deployment: Option<DeploymentMeasurement>,
    interactions: Vec<InteractionMeasurement>,
}

impl Target {
    pub fn new(
        t_set: Vec<Scalar>,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        Target {
            config: super::ProtocolConfig::default(),
            t_set,
            sk1,
            pk1,
            pk2,
            pk,
            state: 0,
            stored: None,
            deployment: None,
            interactions: vec![],
        }
    }

    pub fn with_config(mut self, config: super::ProtocolConfig) -> Self {
        self.config = config;
        self
    }

    fn build_poly_ctext(&self, rng: &mut OsRng) -> Result<EncryptedPoly, String> {
        let coeffs = poly_from_roots(&self.t_set);
        encrypt_poly(rng, &self.pk, &coeffs)
    }

    pub fn run(&mut self, addr: &str, rounds: usize) -> io::Result<()> {
        self.config.resolve().map_err(io::Error::other)?;
        let listener = TcpListener::bind(addr)?;
        eprintln!("[Target] Listening on {addr}");
        let (stream, peer) = listener.accept()?;
        eprintln!("[Target] Monitor connected from {peer}");
        self.handle(stream, rounds)
    }

    pub fn stored_polynomial(&self) -> Option<&StoredPolynomial> {
        self.stored.as_ref()
    }
    pub fn deployment_measurement(&self) -> Option<DeploymentMeasurement> {
        self.deployment
    }
    pub fn interaction_measurements(&self) -> &[InteractionMeasurement] {
        &self.interactions
    }

    fn handle(&mut self, mut s: TcpStream, rounds: usize) -> io::Result<()> {
        use super::measurements::{size, InteractionCosts};
        use super::proofs::ProofContext;
        use std::time::Instant;
        let mut rng = OsRng;
        let config = self.config.resolve().map_err(io::Error::other)?;
        let hello = super::SessionHello::fresh_for_config(config);
        send_msg(&mut s, &hello)?;
        let peer: super::SessionHello = recv_msg(&mut s)?;
        let session = hello.session(&peer)?;
        self.interactions.clear();
        self.deployment = None;

        // Bootstrap is required in both measurement modes. No fabricated round-2 state.
        // The deployment clock excludes key generation, socket setup, and negotiation.
        let deployment_setup_start = super::performance::generator_activity();
        let deployment_start = Instant::now();
        // Each ciphertext is compressed once; storage keeps a copy of those bytes.
        let (mut current, initial_proof) = if config.pok {
            let (ct, proof) = super::proofs::encrypt_and_prove_initial(
                &mut rng,
                &self.pk,
                &self.t_set,
                &ProofContext { session, round: 1 },
            )
            .map_err(io::Error::other)?;
            (ct, Some(super::TPolyProof::Initial(proof)))
        } else {
            let ct = self.build_poly_ctext(&mut rng).map_err(io::Error::other)?;
            (EncodedPoly::from_native(ct), None)
        };
        self.stored = Some(StoredPolynomial {
            ciphertext: current.wire().clone(),
            proof: initial_proof,
            session,
            round: 1,
        });
        let deployment_s = deployment_start.elapsed().as_secs_f64();
        let deployment_setup =
            super::performance::generator_activity().since(deployment_setup_start);
        let initial = self
            .stored
            .as_ref()
            .ok_or_else(|| io::Error::other("missing deployment storage"))?;
        let initial_costs = initial.costs()?;
        self.deployment = Some(DeploymentMeasurement {
            latency_s: deployment_s,
            storage: initial_costs,
            generator_setup: deployment_setup,
        });
        if config.round1 {
            eprintln!("[Target] Deployment Latency: {} s (ciphertext + initial proof generation and storage)", super::measurements::significant(deployment_s));
            initial_costs.report();
            deployment_setup.report();
            // The monitor still verifies the deployment proof before finishing.
            initial.send(&mut s)?;
            return Ok(());
        }
        eprintln!("[Target] Initial ciphertext/proof prepared outside interaction timer");
        let mut interaction_setup_start = super::performance::generator_activity();
        initial.send(&mut s)?;
        for round in 1..=rounds {
            let reply: super::division::DivisionReply = recv_msg(&mut s)?;
            let target_start = Instant::now();
            let (next, partial) = super::division::verify_encoded(
                &self.pk,
                &self.pk1,
                &self.pk2,
                &current,
                &reply,
                &ProofContext {
                    session,
                    round: round as u64,
                },
            )
            .map_err(io::Error::other)?;
            let matched = test_zero(&self.sk1, &partial);
            let branch = usize::from(matched);
            let source = if matched { &next } else { &current };
            let (updated, witness) =
                rerandomize_poly_with_witness(&mut rng, &self.pk, source.native());
            let updated = EncodedPoly::from_native(updated);
            let proof = if config.pok {
                Some(super::TPolyProof::RerandomizationOr(
                    super::proofs::prove_rerandomization_or_encoded(
                        &mut rng,
                        &self.pk,
                        &current,
                        &next,
                        &updated,
                        branch,
                        &witness,
                        &ProofContext {
                            session,
                            round: round as u64 + 1,
                        },
                    )
                    .map_err(io::Error::other)?,
                ))
            } else {
                None
            };
            // Commit ciphertext, proof, and round together, only after monitor verification
            // and successful local proof generation. The latency ends at this storage update.
            self.stored = Some(StoredPolynomial {
                ciphertext: updated.wire().clone(),
                proof,
                session,
                round: round as u64 + 1,
            });
            let target_time_s = target_start.elapsed().as_secs_f64();
            let target_stored_unix_ns = super::measurements::unix_ns()?;
            current = updated;
            self.state += u64::from(matched);
            let latency_s = super::measurements::elapsed_seconds(
                reply.computation_started_unix_ns,
                target_stored_unix_ns,
            )?;
            let generator_setup =
                super::performance::generator_activity().since(interaction_setup_start);
            let stored = self
                .stored
                .as_ref()
                .ok_or_else(|| io::Error::other("missing updated storage"))?;
            let communication = InteractionCosts {
                initial_target_send_bytes: if round == 1 {
                    initial_costs.message_bytes()
                } else {
                    0
                },
                monitor_send_bytes: size(&reply)? + 4,
                target_storage: stored.costs()?,
            };
            self.interactions.push(InteractionMeasurement {
                latency_s,
                target_time_s,
                monitor_started_unix_ns: reply.computation_started_unix_ns,
                target_stored_unix_ns,
                communication,
                generator_setup,
            });
            eprintln!("[Target] Interaction {round} Latency: {} s (monitor target-payload receipt (before verification) -> updated ciphertext and disjunction proof stored)", super::measurements::significant(latency_s));
            eprintln!("[Target] Interaction {round} Target Time: {} s (verify monitor proof, decrypt/test match, rerandomize, generate disjunction proof and store)", super::measurements::significant(target_time_s));
            communication.report();
            generator_setup.report();
            eprintln!("[Target] match={matched} state={}", self.state);
            // Upload even the final update: the monitor verifies it before finishing.
            // Logging and size accounting above are outside the next latency interval.
            interaction_setup_start = super::performance::generator_activity();
            stored.send(&mut s)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_roots_eval_zero() {
        let roots = [Scalar::from(2u64), Scalar::from(5u64), Scalar::from(11u64)];
        let coeffs = poly_from_roots(&roots);
        for r in &roots {
            let mut val = *coeffs.last().unwrap();
            for c in coeffs[..coeffs.len() - 1].iter().rev() {
                val = val * r + c;
            }
            assert_eq!(val, Scalar::zero(), "P({r:?}) must be zero");
        }
    }
}

#[cfg(test)]
mod pok_integration_tests {
    use super::*;
    use crate::crypto::elgamal::generate_key_share;
    use crate::exact::{monitor::Monitor, ProtocolConfig};

    fn session(
        target_pok: bool,
        monitor_pok: bool,
        rounds: usize,
        roots: &[u64],
        query: u64,
    ) -> (io::Result<()>, io::Result<()>) {
        session_with_measurement_mode(target_pok, monitor_pok, rounds, roots, query, false)
    }
    fn session_with_measurement_mode(
        target_pok: bool,
        monitor_pok: bool,
        rounds: usize,
        roots: &[u64],
        query: u64,
        round1: bool,
    ) -> (io::Result<()>, io::Result<()>) {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let mut target = Target::new(
            roots.iter().copied().map(Scalar::from).collect(),
            sk1,
            pk1,
            pk2,
        )
        .with_config(ProtocolConfig {
            pok: target_pok,
            round1,
        });
        let monitor = Monitor::new(Scalar::from(query), sk2, pk1, pk2, roots.len()).with_config(
            ProtocolConfig {
                pok: monitor_pok,
                round1,
            },
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let multiplicity = roots.iter().filter(|&&r| r == query).count() as u64;
        let expected = if round1 {
            0
        } else {
            multiplicity.min(rounds as u64)
        };
        let roots_len = roots.len();
        let target_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let result = target.handle(stream, rounds);
            if result.is_ok() && target_pok == monitor_pok {
                assert_eq!(target.state, expected);
                let stored = target.stored_polynomial().unwrap();
                let deployment = target.deployment_measurement().unwrap();
                assert!(deployment.latency_s >= 0.0);
                assert_eq!(
                    deployment.storage.ciphertext_bytes,
                    8 + 64 * (roots_len as u64 + 1)
                );
                assert_eq!(deployment.storage.proof_bytes > 0, target_pok);
                assert_eq!(stored.round, if round1 { 1 } else { rounds as u64 + 1 });
                assert_eq!(
                    target.interaction_measurements().len(),
                    if round1 { 0 } else { rounds }
                );
                if target_pok {
                    assert!(matches!(
                        (&stored.proof, round1),
                        (Some(crate::exact::TPolyProof::Initial(_)), true)
                            | (Some(crate::exact::TPolyProof::RerandomizationOr(_)), false)
                    ));
                    let p = stored.proof.as_ref().unwrap();
                    let actual = bincode::serialized_size(&(&stored.ciphertext, p)).unwrap() + 4;
                    assert_eq!(stored.costs().unwrap().message_bytes(), actual);
                }
                for (i, m) in target.interaction_measurements().iter().enumerate() {
                    assert!(m.latency_s >= 0.0);
                    assert_eq!(
                        m.latency_s,
                        super::super::measurements::elapsed_seconds(
                            m.monitor_started_unix_ns,
                            m.target_stored_unix_ns
                        )
                        .unwrap()
                    );
                    assert_eq!(
                        m.communication.recurring_bytes(),
                        m.communication.monitor_send_bytes
                            + m.communication.target_storage.total_bytes()
                    );
                    assert!(m.communication.monitor_send_bytes > 0);
                    assert_eq!(
                        m.communication.initial_target_send_bytes,
                        if i == 0 {
                            deployment.storage.message_bytes()
                        } else {
                            0
                        }
                    );
                    assert_eq!(m.communication.target_storage.proof_bytes > 0, target_pok);
                }
            }
            result
        });
        let monitor_result = monitor.run(&addr.to_string(), rounds);
        (target_thread.join().unwrap(), monitor_result)
    }
    #[test]
    fn deployment_only_reports_initial_storage_and_performs_no_query() {
        for pok in [false, true] {
            let (target, monitor) = session_with_measurement_mode(pok, pok, 3, &[7, 42], 7, true);
            target.unwrap();
            monitor.unwrap();
        }
    }
    #[test]
    fn proofs_are_present_during_removal_over_three_rounds() {
        for pok in [false, true] {
            let (target, monitor) = session(pok, pok, 3, &[7, 42], 7);
            target.unwrap();
            monitor.unwrap();
        }
    }
    #[test]
    fn removal_handles_multiplicity_nonmembers_and_constant_polynomials() {
        for (roots, query) in [
            (vec![7, 7], 7),
            (vec![7], 7),
            (vec![7, 42], 99),
            (vec![], 99),
        ] {
            for pok in [false, true] {
                let (target, monitor) = session(pok, pok, 3, &roots, query);
                target.unwrap();
                monitor.unwrap();
            }
        }
    }
    #[test]
    fn mismatched_modes_rejected() {
        for modes in [(false, true), (true, false)] {
            let (target, monitor) = session(modes.0, modes.1, 1, &[7, 42], 7);
            assert!(target.is_err() || monitor.is_err());
            assert!(monitor.is_err());
        }
    }
}

#[cfg(test)]
mod rejection_tests {
    use super::*;
    use crate::{
        crypto::elgamal::generate_key_share,
        exact::{monitor::Monitor, ProtocolConfig, SessionHello, TPolyProof},
    };

    #[test]
    fn missing_and_wrong_round_proofs_reject() {
        for wrong_round in [false, true] {
            let mut rng = OsRng;
            let (_, pk1) = generate_key_share(&mut rng);
            let (sk2, pk2) = generate_key_share(&mut rng);
            let pk = combine_public_keys(&pk1, &pk2);
            let monitor =
                Monitor::new(Scalar::one(), sk2, pk1, pk2, 1).with_config(ProtocolConfig {
                    pok: true,
                    round1: false,
                });
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT as G;
                let (mut s, _) = listener.accept().unwrap();
                let hello = SessionHello::fresh();
                send_msg(&mut s, &hello).unwrap();
                let reply: SessionHello = recv_msg(&mut s).unwrap();
                let session = hello.session(&reply).unwrap();
                let set = vec![Scalar::one()];
                let randomness = vec![Scalar::from(3u64), Scalar::from(5u64)];
                let ct = EncryptedPoly(
                    poly_from_roots(&set)
                        .iter()
                        .zip(&randomness)
                        .map(|(m, r)| Ciphertext {
                            c1: r * G,
                            c2: m * G + r * pk.0,
                        })
                        .collect(),
                );
                let wire = WireEncryptedPoly::from_native(&ct);
                if wrong_round {
                    let p = super::super::proofs::generate_initial_pok(
                        &mut OsRng,
                        &pk,
                        &poly_from_roots(&set),
                        &randomness,
                        &ct,
                        &super::super::proofs::ProofContext { session, round: 1 },
                    )
                    .unwrap();
                    send_msg(&mut s, &(&wire, TPolyProof::Initial(p.clone()))).unwrap();
                    let _: super::super::division::DivisionReply = recv_msg(&mut s).unwrap();
                    send_msg(&mut s, &(wire, TPolyProof::Initial(p))).unwrap();
                } else {
                    send_msg(&mut s, &wire).unwrap();
                }
            });
            assert!(monitor
                .run(&addr.to_string(), if wrong_round { 1 } else { 2 })
                .is_err());
            peer.join().unwrap();
        }
    }

    #[test]
    fn rejected_division_does_not_increment_target_state() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        let mut target =
            Target::new(vec![Scalar::one()], sk1, pk1, pk2).with_config(ProtocolConfig {
                pok: true,
                round1: false,
            });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            assert!(target.handle(s, 1).is_err());
            assert_eq!(target.state, 0);
            assert_eq!(target.stored_polynomial().unwrap().round, 1);
            assert!(matches!(
                target.stored_polynomial().unwrap().proof,
                Some(crate::exact::TPolyProof::Initial(_))
            ));
            assert!(target.interaction_measurements().is_empty());
        });
        let mut s = TcpStream::connect(addr).unwrap();
        let hello: SessionHello = recv_msg(&mut s).unwrap();
        let peer = SessionHello::fresh();
        let session = hello.session(&peer).unwrap();
        send_msg(&mut s, &peer).unwrap();
        let (wire, _): (WireEncryptedPoly, TPolyProof) = recv_msg(&mut s).unwrap();
        let current = wire.to_native().unwrap();
        let mut reply = super::super::division::prove(
            &mut rng,
            &pk,
            &pk1,
            &pk2,
            &sk2,
            &current,
            Scalar::one(),
            &super::super::proofs::ProofContext { session, round: 1 },
        )
        .unwrap();
        reply.next.0[0].c1 = [255; 32];
        send_msg(&mut s, &reply).unwrap();
        server.join().unwrap();
    }
}
