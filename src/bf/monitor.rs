//! Monitor side of the authenticated RLWE target / ElGamal accumulator protocol.
use super::{
    bloom::BloomFilterConfig,
    proof::{self, RoundProof},
    rlwe::RlwePublicContext,
    target::{
        recv_msg, send_msg, MonitorToTarget, ReportBody, TargetToMonitor, WireCiphertext,
        WireEncryptedPoly, WIRE_VERSION,
    },
};
use crate::crypto::elgamal::{
    combine_public_keys, ct_add, ct_scalar_mul, eval_poly, partial_decrypt_with_witness,
    Ciphertext, PublicKey, PublicKeyShare, SecretKeyShare,
};
use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use rand::rngs::OsRng;
use rand09::Rng;
use std::{
    io,
    net::TcpStream,
    time::{Duration, Instant},
};

pub struct Monitor {
    input_y: Scalar,
    bf_config: BloomFilterConfig,
    sk2: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
}
impl Monitor {
    pub fn new(
        input_y: Scalar,
        bf_config: BloomFilterConfig,
        sk2: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        _max_degree: usize,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        Self {
            input_y,
            bf_config,
            sk2,
            pk1,
            pk2,
            pk,
        }
    }
    /// Select another query while retaining this session's ElGamal key share.
    pub fn set_input(&mut self, input: Scalar) -> Result<(), String> {
        super::bloom::scalar_positions_checked(input, self.bf_config)?;
        self.input_y = input;
        Ok(())
    }
    pub fn compute_round(&self, incoming: &TargetToMonitor) -> Result<MonitorToTarget, String> {
        super::protocol_hash::validate(self.bf_config)?;
        if incoming.version != WIRE_VERSION
            || incoming.bf_config != self.bf_config
            || incoming.round == 0
            || incoming.accum_degree > 100_000
            || incoming.accum.0.len() != incoming.accum_degree + 1
        {
            return Err("invalid BF round configuration".into());
        }
        // Authenticate the native key and source before exposing a query to
        // them. Parameter/fingerprint checks alone cannot prevent substitution.
        proof::verify_target(incoming, &self.pk1, &self.pk2)?;
        let public = RlwePublicContext::from_bytes(&incoming.rlwe_context)?;
        public.validate_protocol_for(self.bf_config)?;
        let source = public.from_wire(&incoming.t_poly_ct)?;
        if source.coefficient_count() != self.bf_config.bloom_filter_size + 1 {
            return Err("target polynomial must contain m+1 coefficients".into());
        }
        let hashes = super::protocol_hash::weights(self.input_y, self.bf_config)?;
        let current = incoming.accum.to_native()?;
        let encoded = super::protocol_hash::encode_positions(self.input_y, self.bf_config)?;
        let mut rng = OsRng;
        let mut native_rng = rand09::rng();
        let logical_mask = loop {
            let r = std::array::from_fn(|_| native_rng.random_range(0..public.plaintext_modulus()));
            if r != [0; 3] {
                break r;
            }
        };
        let hashes = super::extension::mask_hashes(&hashes, logical_mask)?;
        let mask = loop {
            let m = Scalar::random(&mut rng);
            if m != Scalar::zero() {
                break m;
            }
        };
        let scaled = ct_add(
            &ct_scalar_mul(&eval_poly(&current, &encoded), &mask),
            &Ciphertext {
                c1: mask * RISTRETTO_BASEPOINT_POINT,
                c2: mask * self.pk.0,
            },
        );
        let (partial, rho) = partial_decrypt_with_witness(&mut rng, &self.sk2, &self.pk1, &scaled);
        let next = super::accumulator::insert_candidate(&current, encoded);
        let mut outputs = Vec::new();
        let mut witnesses = Vec::new();
        for hash in &hashes {
            let (output, mut witness) =
                public.evaluate_sample(&source, hash, 1, &mut native_rng)?;
            witness.logical_mask = Some(logical_mask);
            outputs.push(output);
            witnesses.push(witness);
        }
        let report = ReportBody {
            version: WIRE_VERSION,
            session: incoming.session,
            round: incoming.round,
            accum_next: WireEncryptedPoly::from_native(&next),
            accum_eval_masked: WireCiphertext::from_native(&scaled),
            accum_eval_ctext: WireCiphertext::from_native(&partial),
            m_poly_ctext: outputs,
        };
        let context = proof::context(incoming, &report, &self.pk1, &self.pk2)?;
        let (evaluation, gamma) = super::evaluation_proof::prove(
            &mut rng,
            &context,
            &public,
            &source,
            self.bf_config,
            self.input_y,
            &report.m_poly_ctext,
            &witnesses,
        )?;
        let accumulator = super::accumulator_proof::prove(
            &mut rng,
            &context,
            self.bf_config,
            &self.pk,
            &self.pk1,
            &self.pk2,
            &current,
            &next,
            &scaled,
            &partial,
            self.input_y,
            gamma,
            evaluation.commitments[0],
            mask,
            *self.sk2.as_scalar(),
            rho,
        )?;
        Ok(MonitorToTarget {
            report,
            round_proof: RoundProof {
                evaluation,
                accumulator,
            },
        })
    }
    pub fn run(&self, addr: &str, rounds: usize) -> io::Result<()> {
        let start = Instant::now();
        let mut stream = loop {
            match TcpStream::connect(addr) {
                Ok(s) => break s,
                Err(e)
                    if e.kind() == io::ErrorKind::ConnectionRefused
                        && start.elapsed() < Duration::from_secs(30) =>
                {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(e),
            }
        };
        let mut identity = None;
        for round in 1..=rounds {
            let incoming: TargetToMonitor = recv_msg(&mut stream)?;
            let id = (
                incoming.session,
                sha2::Sha256::digest(&incoming.rlwe_context),
            );
            if incoming.round != round as u64 || identity.as_ref().is_some_and(|old| old != &id) {
                return Err(io::Error::other("BF session changed or round was replayed"));
            }
            identity = Some(id);
            let start = Instant::now();
            let reply = self.compute_round(&incoming).map_err(io::Error::other)?;
            send_msg(&mut stream, &reply)?;
            eprintln!(
                "[Monitor] Round {round}: proved in {:.3}s; report bytes={}",
                start.elapsed().as_secs_f64(),
                bincode::serialized_size(&reply).map_err(io::Error::other)?
            );
        }
        Ok(())
    }
}
use sha2::Digest;
