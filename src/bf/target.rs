use std::io::{self, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream};

use bincode::Options;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::bf::bloom::BloomFilterConfig;
use crate::bf::proof as bfproof;
use crate::crypto::elgamal::{
    combine_public_keys, encrypt_one, encrypt_zero, rerandomize_poly_with_witness, test_zero,
    Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};

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

impl WireEncryptedPoly {
    pub fn from_native(p: &EncryptedPoly) -> Self {
        WireEncryptedPoly(p.0.iter().map(WireCiphertext::from_native).collect())
    }
    pub fn to_native(&self) -> Result<EncryptedPoly, String> {
        let cts: Result<Vec<_>, _> = self.0.iter().map(|w| w.to_native()).collect();
        Ok(EncryptedPoly(cts?))
    }
}

use super::rlwe::{
    generate_keys_with_profile, PackedRlweCiphertext, RlweProfile, RlwePublicContext,
    RlweSecretKey, WirePackedRlweCiphertext, WireSampledRlweEvaluation,
};
pub const WIRE_VERSION: u32 = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetToMonitor {
    pub version: u32,
    pub session: [u8; 32],
    pub round: u64,
    pub bf_config: BloomFilterConfig,
    pub accum_degree: usize,
    pub rlwe_context: Vec<u8>,
    pub t_poly_ct: WirePackedRlweCiphertext,
    pub accum: WireEncryptedPoly,
    pub authentication: Option<crate::crypto::sigma::PolyScalarMulProof>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportBody {
    pub version: u32,
    pub session: [u8; 32],
    pub round: u64,
    pub accum_next: WireEncryptedPoly,
    pub accum_eval_masked: WireCiphertext,
    pub accum_eval_ctext: WireCiphertext,
    pub m_poly_ctext: Vec<WireSampledRlweEvaluation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorToTarget {
    pub report: ReportBody,
    pub round_proof: bfproof::RoundProof,
}
const MAX_FRAME_BYTES: usize = 128 << 20;

fn message_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .reject_trailing_bytes()
}

pub fn send_msg<T: Serialize>(stream: &mut TcpStream, msg: &T) -> io::Result<()> {
    let size = bincode::serialized_size(msg).map_err(io::Error::other)?;
    if size > MAX_FRAME_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BF message exceeds frame limit",
        ));
    }
    let bytes = message_options()
        .serialize(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = (bytes.len() as u32).to_be_bytes();
    let mut bufs: &mut [IoSlice<'_>] = &mut [IoSlice::new(&len), IoSlice::new(&bytes)];
    let total = len.len() + bytes.len();
    let mut written = 0;
    while written < total {
        let n = stream.write_vectored(bufs)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "BF connection closed during send",
            ));
        }
        written += n;
        IoSlice::advance_slices(&mut bufs, n);
    }
    Ok(())
}

pub fn recv_msg<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> io::Result<T> {
    read_message(stream)
}

fn read_message<R: Read, T: for<'de> Deserialize<'de>>(stream: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BF message exceeds frame limit",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    message_options()
        .deserialize(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub use crate::crypto::poly::poly_from_roots;

pub struct Target {
    bf_config: BloomFilterConfig,
    accum_degree: usize,
    sk1: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    pub state: u64,
    rlwe_public: RlwePublicContext,
    rlwe_secret: RlweSecretKey,
    coefficients: zeroize::Zeroizing<Vec<u64>>,
    accumulator: EncryptedPoly,
    session: [u8; 32],
    next_round: u64,
    pending: Option<(TargetToMonitor, PackedRlweCiphertext)>,
}
impl Target {
    pub fn new(
        config: BloomFilterConfig,
        degree: usize,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
    ) -> Self {
        super::protocol_hash::validate(config).expect("valid BF configuration");
        let positions = (1..=config.bloom_filter_size as u64)
            .map(Scalar::from)
            .collect::<Vec<_>>();
        Self::from_marked_positions(config, degree, sk1, pk1, pk2, &positions)
            .expect("valid BF target parameters")
    }
    pub fn from_inputs(
        config: BloomFilterConfig,
        degree: usize,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        inputs: &[Scalar],
    ) -> Result<Self, String> {
        super::protocol_hash::validate(config)?;
        let mut positions = Vec::new();
        for &input in inputs {
            positions.extend(super::bloom::scalar_positions_checked(input, config)?);
        }
        Self::from_marked_positions(config, degree, sk1, pk1, pk2, &positions)
    }
    pub fn from_marked_positions(
        config: BloomFilterConfig,
        degree: usize,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        positions: &[Scalar],
    ) -> Result<Self, String> {
        Self::with_profile(
            config,
            degree,
            sk1,
            pk1,
            pk2,
            positions,
            RlweProfile::for_buckets(config.bloom_filter_size)?,
        )
    }
    fn with_profile(
        config: BloomFilterConfig,
        degree: usize,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        positions: &[Scalar],
        profile: RlweProfile,
    ) -> Result<Self, String> {
        super::protocol_hash::validate(config)?;
        if degree > 100_000 {
            return Err("BF accumulator capacity exceeds 100000".into());
        }
        let mut roots = zeroize::Zeroizing::new(Vec::with_capacity(positions.len()));
        for &position in positions {
            let value = super::bloom::scalar_to_usize(position);
            if value == 0
                || value > config.bloom_filter_size
                || Scalar::from(value as u64) != position
            {
                return Err("marked position outside Bloom domain".into());
            }
            roots.push(value as u64);
        }
        roots.sort_unstable();
        roots.dedup();
        let (rlwe_public, rlwe_secret) = generate_keys_with_profile(&mut rand09::rng(), profile)?;
        rlwe_public.validate_protocol_for(config)?;
        let polynomial = zeroize::Zeroizing::new(rlwe_public.polynomial_from_roots(&roots)?);
        let mut coefficients = zeroize::Zeroizing::new(vec![0; config.bloom_filter_size + 1]);
        coefficients[..polynomial.len()].copy_from_slice(&polynomial);
        let pk = combine_public_keys(&pk1, &pk2);
        let mut rng = OsRng;
        let mut accumulator = vec![encrypt_one(&mut rng, &pk)];
        while accumulator.len() < degree + 1 {
            accumulator.push(encrypt_zero(&mut rng, &pk));
        }
        let mut session = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut session);
        Ok(Self {
            bf_config: config,
            accum_degree: degree,
            sk1,
            pk1,
            pk2,
            pk,
            state: 0,
            rlwe_public,
            rlwe_secret,
            coefficients,
            accumulator: EncryptedPoly(accumulator),
            session,
            next_round: 1,
            pending: None,
        })
    }
    /// A fresh encryption of the retained plaintext polynomial on every round
    /// maintains the circuit-privacy source-noise bound without accumulation.
    pub fn prepare_round(&mut self) -> Result<TargetToMonitor, String> {
        if self.pending.is_none() {
            let source = self
                .rlwe_public
                .encrypt(&self.coefficients, &mut rand09::rng())?;
            let mut message = TargetToMonitor {
                version: WIRE_VERSION,
                session: self.session,
                round: self.next_round,
                bf_config: self.bf_config,
                accum_degree: self.accum_degree,
                rlwe_context: self.rlwe_public.to_bytes()?,
                t_poly_ct: source.to_wire(),
                accum: WireEncryptedPoly::from_native(&self.accumulator),
                authentication: None,
            };
            message.authentication = Some(bfproof::authenticate_target(
                &mut OsRng,
                &message,
                self.sk1.as_scalar(),
                &self.pk1,
                &self.pk2,
            )?);
            self.pending = Some((message, source));
        }
        Ok(self.pending.as_ref().unwrap().0.clone())
    }

    /// Verify both linked proofs before decrypting or changing any target state.
    pub fn process_round(&mut self, message: &MonitorToTarget) -> Result<bool, String> {
        let (incoming, source) = self.pending.as_ref().ok_or("no BF round is pending")?;
        let report = &message.report;
        if report.version != WIRE_VERSION
            || report.session != self.session
            || report.round != self.next_round
        {
            return Err("BF report version, session, or round mismatch".into());
        }
        if report.accum_next.0.len() != self.accumulator.0.len() + 1
            || report.m_poly_ctext.len() != super::protocol_hash::REPETITIONS
        {
            return Err("invalid BF report dimensions".into());
        }
        for value in &report.m_poly_ctext {
            self.rlwe_public.validate_sample(value)?;
        }
        let next = report.accum_next.to_native()?;
        let scaled = report.accum_eval_masked.to_native()?;
        let partial = report.accum_eval_ctext.to_native()?;
        let context = bfproof::context(incoming, report, &self.pk1, &self.pk2)?;
        let item = *message
            .round_proof
            .evaluation
            .commitments
            .first()
            .ok_or("missing shared item commitment")?;
        super::accumulator_proof::verify(
            &context,
            self.bf_config,
            &self.pk,
            &self.pk1,
            &self.pk2,
            &self.accumulator,
            &next,
            &scaled,
            &partial,
            item,
            &message.round_proof.accumulator,
        )?;
        let verified = super::evaluation_proof::verify(
            &context,
            &self.rlwe_public,
            source,
            self.bf_config,
            &report.m_poly_ctext,
            &message.round_proof.evaluation,
        )?;
        if verified.to_bytes() != item {
            return Err("BF proof input commitments differ".into());
        }
        let mut member = true;
        for value in &report.m_poly_ctext {
            member &= self.rlwe_secret.decrypt_sample(&self.rlwe_public, value)? == 0;
        }
        let matched = member && !test_zero(&self.sk1, &partial);
        if matched && self.state >= self.accum_degree as u64 {
            return Err("BF accumulator capacity exhausted".into());
        }
        let next_round = self
            .next_round
            .checked_add(1)
            .ok_or("BF round counter exhausted")?;
        let adopted = if matched {
            EncryptedPoly(next.0[..self.accumulator.0.len()].to_vec())
        } else {
            self.accumulator.clone()
        };
        let (adopted, _) = rerandomize_poly_with_witness(&mut OsRng, &self.pk, &adopted);
        self.accumulator = adopted;
        self.state += u64::from(matched);
        self.next_round = next_round;
        self.pending = None;
        Ok(matched)
    }

    pub fn run(&mut self, addr: &str, rounds: usize) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        eprintln!("[Target] Listening on {addr}");
        let (mut stream, _) = listener.accept()?;
        for round in 1..=rounds {
            let incoming = self.prepare_round().map_err(io::Error::other)?;
            send_msg(&mut stream, &incoming)?;
            let report: MonitorToTarget = recv_msg(&mut stream)?;
            let started = std::time::Instant::now();
            let matched = self.process_round(&report).map_err(io::Error::other)?;
            eprintln!(
                "[Target] Round {round}: verified in {:.3}s; new match={matched}; count={}",
                started.elapsed().as_secs_f64(),
                self.state
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bf::monitor::Monitor, crypto::elgamal::generate_key_share};
    fn setup(
        profile: RlweProfile,
        buckets: usize,
        hashes: usize,
        capacity: usize,
    ) -> (Target, Monitor) {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let config = BloomFilterConfig {
            bloom_filter_size: buckets,
            hash_count: hashes,
            target_marked_count: 4,
        };
        let positions = [1u64, 2, 3]
            .into_iter()
            .flat_map(|item| super::super::bloom::scalar_positions(Scalar::from(item), config))
            .collect::<Vec<_>>();
        let target =
            Target::with_profile(config, capacity, sk1, pk1, pk2, &positions, profile).unwrap();
        let monitor = Monitor::new(Scalar::from(2u64), config, sk2, pk1, pk2, capacity);
        (target, monitor)
    }
    #[test]
    fn authenticated_source_rejects_key_substitution_and_mutated_rounds() {
        let (mut target, monitor) = setup(RlweProfile::ProofTest, 33, 2, 2);
        let incoming = target.prepare_round().unwrap();
        bfproof::verify_target(&incoming, &target.pk1, &target.pk2).unwrap();
        let (other, _) =
            generate_keys_with_profile(&mut rand09::rng(), RlweProfile::ProofTest).unwrap();
        for mutation in 0..8 {
            let mut bad = incoming.clone();
            match mutation {
                0 => bad.authentication = None,
                1 => bad.authentication.as_mut().unwrap().s_y += Scalar::one(),
                2 => {
                    bad.rlwe_context = other.to_bytes().unwrap();
                    bad.t_poly_ct = other
                        .encrypt_bloom_positions(bad.bf_config, &[2, 5], &mut rand09::rng())
                        .unwrap()
                        .to_wire();
                }
                3 => {
                    bad.t_poly_ct = target
                        .rlwe_public
                        .encrypt_bloom_positions(bad.bf_config, &[3, 7], &mut rand09::rng())
                        .unwrap()
                        .to_wire()
                }
                4 => bad.session[0] ^= 1,
                5 => bad.round += 1,
                6 => {
                    let mut ct = bad.accum.0[0].to_native().unwrap();
                    ct.c2 += curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
                    bad.accum.0[0] = WireCiphertext::from_native(&ct);
                }
                _ => bad.bf_config.target_marked_count += 1,
            }
            assert!(
                bfproof::verify_target(&bad, &target.pk1, &target.pk2).is_err(),
                "accepted source mutation {mutation}"
            );
            assert!(monitor.compute_round(&bad).is_err());
        }
        // Authentication evidence is not a semantic input to the evaluation
        // relation; replacing a valid signature nonce preserves its body bytes.
        let before = bincode::serialize(&bfproof::target_statement(&incoming)).unwrap();
        let mut signed = incoming.clone();
        signed.authentication = Some(
            bfproof::authenticate_target(
                &mut OsRng,
                &signed,
                target.sk1.as_scalar(),
                &target.pk1,
                &target.pk2,
            )
            .unwrap(),
        );
        bfproof::verify_target(&signed, &target.pk1, &target.pk2).unwrap();
        assert_eq!(
            before,
            bincode::serialize(&bfproof::target_statement(&signed)).unwrap()
        );
        #[derive(Serialize)]
        struct PreviousStatement<'a> {
            version: u32,
            session: [u8; 32],
            round: u64,
            bf_config: BloomFilterConfig,
            accum_degree: usize,
            rlwe_context: &'a Vec<u8>,
            t_poly_ct: &'a WirePackedRlweCiphertext,
            accum: &'a WireEncryptedPoly,
        }
        let previous = PreviousStatement {
            version: incoming.version,
            session: incoming.session,
            round: incoming.round,
            bf_config: incoming.bf_config,
            accum_degree: incoming.accum_degree,
            rlwe_context: &incoming.rlwe_context,
            t_poly_ct: &incoming.t_poly_ct,
            accum: &incoming.accum,
        };
        assert_eq!(
            before,
            bincode::serialize(&previous).unwrap(),
            "authentication must preserve the complete evaluation statement encoding"
        );
    }
    #[test]
    fn default_target_uses_the_authenticated_adaptive_packing_plan() {
        for buckets in [1000, 20000] {
            let mut rng = OsRng;
            let (sk1, pk1) = generate_key_share(&mut rng);
            let (_, pk2) = generate_key_share(&mut rng);
            let config = BloomFilterConfig {
                bloom_filter_size: buckets,
                hash_count: 2,
                target_marked_count: 2,
            };
            let positions = [Scalar::from(2u64), Scalar::from(5u64)];
            let mut target =
                Target::from_marked_positions(config, 1, sk1, pk1, pk2, &positions).unwrap();
            let plan = super::super::packing_plan::PackingPlan::for_buckets(buckets).unwrap();
            let message = target.prepare_round().unwrap();
            let public = RlwePublicContext::from_bytes(&message.rlwe_context).unwrap();
            assert_eq!(public.ring_dimension(), plan.ring_dimension);
            let source = public.from_wire(&message.t_poly_ct).unwrap();
            assert_eq!(source.block_count(), plan.ciphertext_count);
            assert_eq!(source.coefficient_count(), buckets + 1);
            bfproof::verify_target(&message, &pk1, &pk2).unwrap();
        }
    }

    #[test]
    fn production_100k_source_authentication() {
        let (mut target, _) = setup(RlweProfile::Protocol100k, 100_000, 20, 1);
        let incoming = target.prepare_round().unwrap();
        bfproof::verify_target(&incoming, &target.pk1, &target.pk2).unwrap();
        let bytes = message_options().serialize(&incoming).unwrap();
        assert!(bytes.len() < MAX_FRAME_BYTES);
        let decoded: TargetToMonitor = message_options().deserialize(&bytes).unwrap();
        bfproof::verify_target(&decoded, &target.pk1, &target.pk2).unwrap();
    }
    #[test]
    fn authenticated_rounds_reject_tampering_replays_and_repeated_counts() {
        let (mut target, mut monitor) = setup(RlweProfile::ProofTest, 33, 2, 2);
        let incoming = target.prepare_round().unwrap();
        // Exercise the actual framed protocol with an independently imported
        // monitor context, including public-key and ciphertext transport.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let reply = std::thread::scope(|scope| {
            let monitor = &monitor;
            let peer = scope.spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                let incoming: TargetToMonitor = recv_msg(&mut stream).unwrap();
                let report = monitor.compute_round(&incoming).unwrap();
                send_msg(&mut stream, &report).unwrap();
            });
            let (mut stream, _) = listener.accept().unwrap();
            send_msg(&mut stream, &incoming).unwrap();
            let report: MonitorToTarget = recv_msg(&mut stream).unwrap();
            peer.join().unwrap();
            report
        });
        for mutation in 0..7 {
            let mut bad = reply.clone();
            match mutation {
                0 => bad.report.session[0] ^= 1,
                1 => bad.report.round += 1,
                2 => bad.report.m_poly_ctext[0].b[0] ^= 1,
                3 => {
                    bad.report.m_poly_ctext.pop();
                }
                4 => bad.round_proof.accumulator.z_gamma[0] ^= 1,
                5 => bad.round_proof.evaluation.commitments[0][0] ^= 1,
                _ => {
                    let mut ct = bad.report.accum_next.0[0].to_native().unwrap();
                    ct.c2 += curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
                    bad.report.accum_next.0[0] = WireCiphertext::from_native(&ct);
                }
            }
            assert!(
                target.process_round(&bad).is_err(),
                "accepted mutation {mutation}"
            );
            assert_eq!(target.state, 0);
            assert_eq!(target.next_round, 1);
        }
        let bytes = message_options().serialize(&reply).unwrap();
        let roundtrip: MonitorToTarget = message_options().deserialize(&bytes).unwrap();
        assert!(target.process_round(&roundtrip).unwrap());
        assert_eq!(target.state, 1);
        assert!(target.process_round(&reply).is_err());
        // Repeated matches do not count again.
        let incoming = target.prepare_round().unwrap();
        assert!(target.process_round(&reply).is_err());
        let repeat = monitor.compute_round(&incoming).unwrap();
        assert_ne!(
            reply.round_proof.evaluation.commitments[0],
            repeat.round_proof.evaluation.commitments[0]
        );
        for candidate in 1..=super::super::bloom::usable_input_span(target.bf_config) {
            let dictionary = (Scalar::from(candidate as u64)
                * curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes();
            assert_ne!(reply.round_proof.evaluation.commitments[0], dictionary);
        }
        assert!(monitor.set_input(Scalar::zero()).is_err());
        assert!(!target.process_round(&repeat).unwrap());
        assert_eq!(target.state, 1);
        monitor.set_input(Scalar::from(4u64)).unwrap();
        let incoming = target.prepare_round().unwrap();
        let miss = monitor.compute_round(&incoming).unwrap();
        assert!(!target.process_round(&miss).unwrap());
        assert_eq!(target.state, 1);
        monitor.set_input(Scalar::from(3u64)).unwrap();
        let incoming = target.prepare_round().unwrap();
        let distinct = monitor.compute_round(&incoming).unwrap();
        assert!(target.process_round(&distinct).unwrap());
        assert_eq!(target.state, 2);
        monitor.set_input(Scalar::from(1u64)).unwrap();
        let incoming = target.prepare_round().unwrap();
        let full = monitor.compute_round(&incoming).unwrap();
        assert!(target
            .process_round(&full)
            .unwrap_err()
            .contains("capacity exhausted"));
        assert_eq!(target.state, 2);
        assert_eq!(target.next_round, 5);
    }
    #[test]
    fn bloom_false_positive_retains_the_bloom_membership_semantics() {
        let config = BloomFilterConfig {
            bloom_filter_size: 25,
            hash_count: 2,
            target_marked_count: 4,
        };
        let items = [Scalar::from(2u64), Scalar::from(11u64)];
        let positions = items
            .into_iter()
            .flat_map(|item| super::super::bloom::scalar_positions(item, config))
            .collect::<Vec<_>>();
        let query = Scalar::from(5u64);
        assert!(!items.contains(&query));
        assert!(super::super::bloom::scalar_is_member(
            query, &positions, config
        ));
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let mut target =
            Target::with_profile(config, 1, sk1, pk1, pk2, &positions, RlweProfile::ProofTest)
                .unwrap();
        let monitor = Monitor::new(query, config, sk2, pk1, pk2, 1);
        let incoming = target.prepare_round().unwrap();
        let report = monitor.compute_round(&incoming).unwrap();
        assert!(target.process_round(&report).unwrap());
        assert_eq!(target.state, 1);
    }
    #[test]
    #[ignore = "full production 100k RLWE/Bulletproof report; expensive"]
    fn authenticated_production_100k_report() {
        production_report(100_000);
    }

    #[test]
    #[ignore = "full production 1000-bucket proof latency benchmark; expensive"]
    fn authenticated_production_1000_report() {
        production_report(1000);
    }

    fn production_report(buckets: usize) {
        let start = std::time::Instant::now();
        let (mut target, monitor) =
            setup(RlweProfile::for_buckets(buckets).unwrap(), buckets, 20, 1);
        eprintln!(
            "{buckets}-bucket setup (keys/root polynomial/accumulator): {:.3}s; hashes=20",
            start.elapsed().as_secs_f64()
        );
        let start = std::time::Instant::now();
        let incoming = target.prepare_round().unwrap();
        eprintln!(
            "{buckets}-bucket source encryption: {:.3}s",
            start.elapsed().as_secs_f64()
        );
        eprintln!(
            "{buckets}-bucket target ciphertext bytes={}; public context bytes={}",
            bincode::serialized_size(&incoming.t_poly_ct).unwrap(),
            incoming.rlwe_context.len()
        );
        assert_eq!(
            target.pending.as_ref().unwrap().1.coefficient_count(),
            buckets + 1
        );
        assert_eq!(
            target.pending.as_ref().unwrap().1.block_count(),
            (buckets + 1).div_ceil(target.rlwe_public.ring_dimension())
        );
        let start = std::time::Instant::now();
        let report = monitor.compute_round(&incoming).unwrap();
        let bytes = bincode::serialized_size(&report).unwrap();
        eprintln!(
            "{buckets}-bucket proving: {:.3}s; report bytes={bytes}",
            start.elapsed().as_secs_f64()
        );
        assert!(bytes < MAX_FRAME_BYTES as u64);
        let start = std::time::Instant::now();
        assert!(target.process_round(&report).unwrap());
        assert_eq!(target.state, 1);
        eprintln!(
            "{buckets}-bucket verification: {:.3}s",
            start.elapsed().as_secs_f64()
        );
    }
    #[test]
    fn frame_decoder_rejects_oversize_truncation_and_trailing_bytes() {
        assert!(read_message::<_, u32>(&mut std::io::Cursor::new(
            ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes()
        ))
        .is_err());
        assert!(read_message::<_, u32>(&mut std::io::Cursor::new([0, 0, 0, 4, 1])).is_err());
        let mut bytes = vec![0, 0, 0, 5];
        bytes.extend([1, 0, 0, 0, 9]);
        assert!(read_message::<_, u32>(&mut std::io::Cursor::new(bytes)).is_err());
    }
}
