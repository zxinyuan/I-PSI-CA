use std::io;
use std::net::TcpStream;

use crate::crypto::elgamal::{combine_public_keys, PublicKey, PublicKeyShare, SecretKeyShare};
use crate::exact::target::{recv_msg, send_msg, WireEncryptedPoly};
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
        candidates: Option<(
            &crate::crypto::elgamal::EncryptedPoly,
            &crate::crypto::elgamal::EncryptedPoly,
        )>,
    ) -> io::Result<crate::crypto::elgamal::EncryptedPoly> {
        let (incoming, proof): (WireEncryptedPoly, Option<super::TPolyProof>) = if pok {
            let (ct, p) = recv_msg(stream)?;
            (ct, Some(p))
        } else {
            (recv_msg(stream)?, None)
        };
        let ciphertext = incoming.to_native().map_err(io::Error::other)?;
        if pok {
            match (context.round, proof, candidates) {
                (1, Some(super::TPolyProof::Initial(p)), None) => {
                    super::proofs::verify_initial_pok(&self.pk, &ciphertext, &p, context)
                        .map_err(io::Error::other)?
                }
                (r, Some(super::TPolyProof::RerandomizationOr(p)), Some((old, next))) if r > 1 => {
                    super::proofs::verify_rerandomization_or(
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
        Ok(ciphertext)
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
        let mut current = self.receive_target(
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
            let start = std::time::Instant::now();
            let (reply, next) = super::division::prove_with_candidate(
                &mut rng,
                &self.pk,
                &self.pk1,
                &self.pk2,
                &self.sk2,
                &current,
                self.m_elmt,
                &context,
            )
            .map_err(io::Error::other)?;
            let generation_ms = start.elapsed().as_secs_f64() * 1000.0;
            let bytes = super::measurements::size(&reply)? + 4;
            send_msg(&mut stream, &reply)?;
            // No computation or state advancement for a new ciphertext until its
            // OR proof verifies, including the last update of the benchmark.
            let updated = self.receive_target(
                &mut stream,
                config.pok,
                &ProofContext {
                    session,
                    round: round as u64 + 1,
                },
                Some((&current, &next)),
            )?;
            current = updated;
            eprintln!("[Monitor] Interaction {round}: proof generation={generation_ms:.3} ms send={:.9} MB; updated target proof accepted",super::measurements::mb(bytes));
        }
        Ok(())
    }
}
