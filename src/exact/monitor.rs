use std::io;
use std::net::TcpStream;

use crate::crypto::elgamal::{combine_public_keys, PublicKey, PublicKeyShare, SecretKeyShare};
use crate::exact::target::{recv_msg, send_msg, EncodedPoly, WireEncryptedPoly};
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;

pub struct Monitor {
    config: super::ProtocolConfig,
    m_elmt: Scalar,
    sk2: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
}

impl Monitor {
    pub fn new(
        m_elmt: Scalar,
        sk2: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        _max_degree: usize,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        Monitor {
            config: super::ProtocolConfig::default(),
            m_elmt,
            sk2,
            pk1,
            pk2,
            pk,
        }
    }

    pub fn with_config(mut self, config: super::ProtocolConfig) -> Self {
        self.config = config;
        self
    }

    fn receive_target(
        &self,
        stream: &mut TcpStream,
        pok: bool,
        context: &super::proofs::ProofContext,
        candidates: Option<(&EncodedPoly, &EncodedPoly)>,
    ) -> io::Result<(EncodedPoly, std::time::Instant, u128)> {
        let (incoming, proof): (WireEncryptedPoly, Option<super::TPolyProof>) = if pok {
            let (ct, p) = recv_msg(stream)?;
            (ct, Some(p))
        } else {
            (recv_msg(stream)?, None)
        };
        let received_at = std::time::Instant::now();
        let received_unix_ns = super::measurements::unix_ns()?;
        // Decoding accepts only canonical encodings, so proofs hash the bytes as received.
        let ciphertext = EncodedPoly::from_wire(incoming).map_err(io::Error::other)?;
        if pok {
            match (context.round, proof, candidates) {
                (1, Some(super::TPolyProof::Initial(p)), None) => {
                    super::proofs::verify_initial_pok_encoded(&self.pk, &ciphertext, &p, context)
                        .map_err(io::Error::other)?
                }
                (r, Some(super::TPolyProof::RerandomizationOr(p)), Some((old, next))) if r > 1 => {
                    super::proofs::verify_rerandomization_or_encoded(
                        &self.pk,
                        old,
                        next,
                        &ciphertext,
                        &p,
                        context,
                    )
                    .map_err(io::Error::other)?
                }
                _ => return Err(io::Error::other("missing or wrong round target proof")),
            }
        }
        Ok((ciphertext, received_at, received_unix_ns))
    }

    pub fn run(&self, addr: &str, rounds: usize) -> io::Result<()> {
        use super::proofs::ProofContext;
        let config = self.config.resolve().map_err(io::Error::other)?;
        let mut stream = TcpStream::connect(addr)?;
        let target: super::SessionHello = recv_msg(&mut stream)?;
        let hello = super::SessionHello::fresh_for_config(config);
        let session = target.session(&hello)?;
        send_msg(&mut stream, &hello)?;
        let mut rng = OsRng;
        let (mut current, mut received_at, mut received_unix_ns) = self.receive_target(
            &mut stream,
            config.pok,
            &ProofContext { session, round: 1 },
            None,
        )?;
        if config.round1 {
            eprintln!("[Monitor] Deployment ciphertext and proof accepted");
            return Ok(());
        }
        for round in 1..=rounds {
            let context = ProofContext {
                session,
                round: round as u64,
            };
            let (reply, next) = super::division::prove_with_candidate_started_at(
                &mut rng,
                &self.pk,
                &self.pk1,
                &self.pk2,
                &self.sk2,
                &current,
                self.m_elmt,
                &context,
                received_unix_ns,
            )
            .map_err(io::Error::other)?;
            let monitor_time_s = received_at.elapsed().as_secs_f64();
            eprintln!(
                "[Monitor] Interaction {round} Monitor Time: {} s (target payload received -> verification, computation and proof complete)",
                super::measurements::significant(monitor_time_s)
            );
            send_msg(&mut stream, &reply)?;
            // No computation or state advancement for a new ciphertext until its
            // OR proof verifies, including the last update of the benchmark.
            (current, received_at, received_unix_ns) = self.receive_target(
                &mut stream,
                config.pok,
                &ProofContext {
                    session,
                    round: round as u64 + 1,
                },
                Some((&current, &next)),
            )?;
            eprintln!(
                "[Monitor] Interaction {round}: updated target ciphertext and proof accepted"
            );
        }
        Ok(())
    }
}
