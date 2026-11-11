//! Native coefficient-packed BFV/RLWE operations for the BF protocol.
//!
//! The accepted protocol selects a secure packing dimension, coefficient extraction and the
//! complete `evaluation_proof` verifier. Trace-based arithmetic profiles remain
//! reference/test helpers; their outputs are distinct wire types. See RLWE.md.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

use bincode::Options;
use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, EvaluationKey, EvaluationKeyBuilder,
    Plaintext, PublicKey, SecretKey,
};
use fhe_math::zq::Modulus;
use fhe_math::{
    rns::RnsContext,
    rq::{traits::TryConvertFrom, Poly, Representation},
};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter,
    Serialize as FheSerialize,
};
use num_bigint::BigUint;
use prost::Message;
use rand09::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::bloom::{scalar_positions, scalar_to_usize, usable_input_span, BloomFilterConfig};
use super::circuit_privacy::{divide_and_floor, PrivacyBudget, ERROR_VARIANCE, RETAINED_LIMBS};
use curve25519_dalek_ng::scalar::Scalar;

pub const PLAINTEXT_MODULUS: u64 = 65537;
pub const RING_DIMENSION: usize = 4096;
pub const BLOOM_PLAINTEXT_MODULUS: u64 = 2_305_843_009_211_596_801;
pub const BLOOM_RING_DIMENSION: usize = 8192;
pub const CIRCUIT_PRIVACY_RING_DIMENSION: usize = 16384;
pub const PROTOCOL_PLAINTEXT_MODULUS: u64 = 36_028_796_991_700_993;
pub const PROTOCOL_MODULI: [u64; 6] = [
    4611686018427322369,
    4611686018427289601,
    4611686018425815041,
    4611686018424733697,
    4611686018423881729,
    4611686018423390209,
];
/// Three independent hash sums: random-oracle cancellation is at most t^-3.
pub const MEMBERSHIP_REPETITIONS: usize = 3;
pub(crate) const WEIGHT_DOMAIN: &[u8] = b"i-psi-ca/bf/rlwe/item-weight/v2";
/// Fixed proof shape hides rejection indices. For the wide field, four rejected
/// attempts have probability below 2^-160 per weight in the random-oracle model.
pub const MAX_HASH_ATTEMPTS: usize = 4;
const VERSION: u32 = 4;
pub(crate) const MAX_COEFFICIENTS: usize = 1 << 20;
const MAX_BLOCK_BYTES: usize = 4 << 20;
const MAX_PUBLIC_CONTEXT_BYTES: usize = 128 << 20;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
#[cfg(test)]
fn field_mul(a: u64, b: u64, modulus: u64) -> u64 {
    (a as u128 * b as u128 % modulus as u128) as u64
}

#[derive(Clone, Copy, Debug)]
pub enum RlweProfile {
    /// Retained solely for agreement with the Go packing oracle.
    GoReference,
    /// Distinct bucket indices past 100k and a wider exact plaintext field.
    Bloom100k,
    /// Terminal divide-and-floor with a proved conservative noise budget.
    /// Conditional on honest keys and freshly encrypted source blocks.
    CircuitPrivacy100k,
    /// Circuit-private scalar extraction, without automorphism keys.
    Protocol100k,
    /// Same plaintext/privacy policy with dimension chosen by the packing planner.
    ProtocolSized { ring_dimension: usize },
    #[cfg(test)]
    ProofTest,
}

impl RlweProfile {
    pub fn for_buckets(buckets: usize) -> Result<Self, String> {
        let plan = super::packing_plan::PackingPlan::for_buckets(buckets)?;
        Ok(if plan.ring_dimension == CIRCUIT_PRIVACY_RING_DIMENSION {
            Self::Protocol100k
        } else {
            Self::ProtocolSized {
                ring_dimension: plan.ring_dimension,
            }
        })
    }
    fn layout(self) -> (usize, u64, &'static [usize]) {
        match self {
            Self::GoReference => (RING_DIMENSION, PLAINTEXT_MODULUS, &[36, 36, 37]),
            Self::Bloom100k => (BLOOM_RING_DIMENSION, BLOOM_PLAINTEXT_MODULUS, &[62, 62, 62]),
            Self::Protocol100k => (
                CIRCUIT_PRIVACY_RING_DIMENSION,
                PROTOCOL_PLAINTEXT_MODULUS,
                &[62; 6],
            ),
            Self::ProtocolSized { ring_dimension } => {
                (ring_dimension, PROTOCOL_PLAINTEXT_MODULUS, &[62; 6])
            }
            #[cfg(test)]
            Self::ProofTest => (16, PROTOCOL_PLAINTEXT_MODULUS, &[62; 6]),
            Self::CircuitPrivacy100k => (
                CIRCUIT_PRIVACY_RING_DIMENSION,
                BLOOM_PLAINTEXT_MODULUS,
                &[62; 7],
            ),
        }
    }
}

fn protocol_parameters(degree: usize) -> Result<Arc<BfvParameters>, String> {
    if !super::packing_plan::PROTOCOL_RING_DIMENSIONS.contains(&degree) {
        return Err("unsupported protocol ring dimension or insufficient security".into());
    }
    type Cache = BTreeMap<usize, Arc<BfvParameters>>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| "protocol parameter cache poisoned")?;
    if let Some(parameters) = cache.get(&degree) {
        return Ok(parameters.clone());
    }
    let mut builder = BfvParametersBuilder::new();
    builder
        .set_degree(degree)
        .set_plaintext_modulus(PROTOCOL_PLAINTEXT_MODULUS)
        .set_variance(ERROR_VARIANCE);
    if degree == CIRCUIT_PRIVACY_RING_DIMENSION {
        builder.set_moduli(&PROTOCOL_MODULI);
    } else {
        builder.set_moduli_sizes(&[62; 6]);
    }
    let parameters = builder.build_arc().map_err(err)?;
    let q: BigUint = parameters
        .moduli()
        .iter()
        .map(|&q| BigUint::from(q))
        .product();
    super::packing_plan::validate_modulus_size(degree, q.bits() as usize)?;
    PrivacyBudget::calculate_sampled(
        degree,
        PROTOCOL_PLAINTEXT_MODULUS,
        parameters.moduli(),
        MAX_COEFFICIENTS,
        MEMBERSHIP_REPETITIONS,
    )?;
    cache.insert(degree, parameters.clone());
    Ok(parameters)
}

fn parameters(profile: RlweProfile) -> Result<Arc<BfvParameters>, String> {
    let (degree, plaintext, moduli_sizes) = profile.layout();
    if matches!(
        profile,
        RlweProfile::Protocol100k | RlweProfile::ProtocolSized { .. }
    ) {
        return protocol_parameters(degree);
    }
    #[cfg(test)]
    if matches!(profile, RlweProfile::ProofTest) {
        return BfvParametersBuilder::new()
            .set_degree(degree)
            .set_plaintext_modulus(plaintext)
            .set_moduli(&PROTOCOL_MODULI)
            .set_variance(ERROR_VARIANCE)
            .build_arc()
            .map_err(err);
    }
    BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(plaintext)
        .set_moduli_sizes(moduli_sizes)
        .set_variance(ERROR_VARIANCE)
        .build_arc()
        .map_err(err)
}

/// Public evaluation context. Contains public and automorphism keys only.
pub struct RlwePublicContext {
    field: Modulus,
    pub(crate) parameters: Arc<BfvParameters>,
    pk: PublicKey,
    evaluation_key: Option<EvaluationKey>,
    id: [u8; 32],
    // Keep the exact transmitted encoding. EvaluationKey serializes a HashMap,
    // so reserialization after import need not preserve its entry order.
    wire: WireRlwePublicContext,
}

/// Target-owned secret. Intentionally has no serialization or Debug implementation.
pub struct RlweSecretKey {
    sk: SecretKey,
    id: [u8; 32],
}

pub struct PackedRlweCiphertext {
    pub(crate) blocks: Vec<Ciphertext>,
    pub(crate) coefficient_count: usize,
    id: [u8; 32],
}

/// Scalar coefficient extraction under the same target secret, after terminal
/// sanitization. No other c0 coefficients (and hence plaintexts) are returned.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireSampledRlweEvaluation {
    pub(crate) version: u32,
    pub(crate) id: [u8; 32],
    pub(crate) b: Vec<u64>,
    pub(crate) a: Vec<Vec<u64>>,
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct SampleEvaluationWitness {
    pub mask: u64,
    pub logical_mask: Option<[u64; 3]>,
    pub weights: Vec<i64>,
    pub u: Vec<i64>,
    pub e1: Vec<i64>,
    pub e0: i64,
    pub remainder_a: Vec<Vec<u64>>,
    pub remainder_b: Vec<u64>,
}

/// A constant-polynomial ciphertext, distinct from encrypted coefficients.
pub struct RlweEvaluation {
    ct: Ciphertext,
    id: [u8; 32],
}

/// Only the final sanitized ciphertext can be transported through this type.
/// No unsanitized intermediate or privacy-transform randomness is exposed.
pub struct SanitizedRlweEvaluation {
    ct: Ciphertext,
    id: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct WireSanitizedRlweEvaluation {
    version: u32,
    id: [u8; 32],
    ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WirePackedRlweCiphertext {
    version: u32,
    id: [u8; 32],
    coefficient_count: usize,
    blocks: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WireRlwePublicContext {
    version: u32,
    ring_dimension: u64,
    plaintext_modulus: u64,
    ciphertext_moduli: Vec<u64>,
    public_key: Vec<u8>,
    evaluation_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct WireRlweEvaluation {
    version: u32,
    id: [u8; 32],
    ciphertext: Vec<u8>,
}

fn wire_options(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
}

fn context_id(wire: &WireRlwePublicContext) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"i-psi-ca/bf/packed-bfv/v4");
    hash.update(wire.version.to_le_bytes());
    hash.update(wire.ring_dimension.to_le_bytes());
    hash.update(wire.plaintext_modulus.to_le_bytes());
    hash.update((wire.ciphertext_moduli.len() as u64).to_le_bytes());
    for q in &wire.ciphertext_moduli {
        hash.update(q.to_le_bytes());
    }
    for bytes in [&wire.public_key, &wire.evaluation_key] {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize().into()
}

pub fn generate_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(RlwePublicContext, RlweSecretKey), String> {
    generate_keys_with_profile(rng, RlweProfile::Bloom100k)
}

/// Encryption-only Go oracle profile; its field cannot label 100k buckets.
pub fn generate_reference_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(RlwePublicContext, RlweSecretKey), String> {
    generate_keys_with_profile(rng, RlweProfile::GoReference)
}

pub fn generate_keys_with_profile<R: RngCore + CryptoRng>(
    rng: &mut R,
    profile: RlweProfile,
) -> Result<(RlwePublicContext, RlweSecretKey), String> {
    let parameters = parameters(profile)?;
    let sk = SecretKey::random(&parameters, rng);
    let pk = PublicKey::new(&sk, rng);
    let evaluation_key = if profile.layout().1 == PROTOCOL_PLAINTEXT_MODULUS {
        None
    } else {
        Some(
            EvaluationKeyBuilder::new(&sk)
                .map_err(err)?
                .enable_inner_sum()
                .map_err(err)?
                .build(rng)
                .map_err(err)?,
        )
    };
    let wire = WireRlwePublicContext {
        version: VERSION,
        ring_dimension: parameters.degree() as u64,
        plaintext_modulus: profile.layout().1,
        ciphertext_moduli: parameters.moduli().to_vec(),
        public_key: pk.to_bytes(),
        evaluation_key: evaluation_key
            .as_ref()
            .map(FheSerialize::to_bytes)
            .unwrap_or_default(),
    };
    let id = context_id(&wire);
    Ok((
        RlwePublicContext {
            field: Modulus::new(wire.plaintext_modulus).map_err(err)?,
            parameters,
            pk,
            evaluation_key,
            id,
            wire,
        },
        RlweSecretKey { sk, id },
    ))
}

impl RlwePublicContext {
    pub(crate) fn validate_protocol(&self) -> Result<(), String> {
        let degree = self.ring_dimension();
        let expected = {
            #[cfg(test)]
            if degree == 16 {
                parameters(RlweProfile::ProofTest)?
            } else {
                protocol_parameters(degree)?
            }
            #[cfg(not(test))]
            protocol_parameters(degree)?
        };
        if self.plaintext_modulus() != PROTOCOL_PLAINTEXT_MODULUS
            || self.parameters.moduli() != expected.moduli()
        {
            return Err("BF requires the protocol RLWE profile".into());
        }
        PrivacyBudget::calculate_sampled(
            degree,
            PROTOCOL_PLAINTEXT_MODULUS,
            self.parameters.moduli(),
            MAX_COEFFICIENTS,
            MEMBERSHIP_REPETITIONS,
        )?;
        Ok(())
    }

    pub(crate) fn validate_protocol_for(&self, config: BloomFilterConfig) -> Result<(), String> {
        self.validate_protocol()?;
        #[cfg(test)]
        if self.ring_dimension() == 16 {
            return Ok(());
        }
        let expected = super::packing_plan::PackingPlan::for_buckets(config.bloom_filter_size)?;
        if self.ring_dimension() != expected.ring_dimension {
            return Err("RLWE dimension does not match the Bloom packing plan".into());
        }
        Ok(())
    }

    pub(crate) fn public_key_ciphertext(&self) -> Result<Ciphertext, String> {
        let proto =
            fhe::proto::bfv::PublicKey::decode(self.wire.public_key.as_slice()).map_err(err)?;
        Ciphertext::from_bytes(
            &proto.c.ok_or("missing encryption key")?.encode_to_vec(),
            &self.parameters,
        )
        .map_err(err)
    }

    pub(crate) fn coefficient_rows(ct: &Ciphertext, component: usize) -> Vec<Vec<u64>> {
        let mut p = ct[component].clone();
        p.change_representation(Representation::PowerBasis);
        p.coefficients()
            .outer_iter()
            .map(|row| row.to_vec())
            .collect()
    }

    pub(crate) fn evaluate_sample<R: RngCore + CryptoRng>(
        &self,
        source: &PackedRlweCiphertext,
        hashes: &[(u64, u64)],
        mask: u64,
        rng: &mut R,
    ) -> Result<(WireSampledRlweEvaluation, SampleEvaluationWitness), String> {
        self.validate_protocol()?;
        if source.id != self.id
            || source.coefficient_count == 0
            || mask == 0
            || mask >= self.plaintext_modulus()
            || hashes.is_empty()
            || hashes.iter().any(|&(p, h)| {
                p == 0 || p >= self.plaintext_modulus() || h >= self.plaintext_modulus()
            })
        {
            return Err("invalid sampled-evaluation witness".into());
        }
        let n = self.ring_dimension();
        let t = self.plaintext_modulus();
        let mut powers = vec![1u64; hashes.len()];
        let mut weights = Vec::with_capacity(source.coefficient_count);
        let mut aggregate = None;
        for (b, ct) in source.blocks.iter().enumerate() {
            let count = (source.coefficient_count - b * n).min(n);
            let mut polynomial = zeroize::Zeroizing::new(vec![0i64; n]);
            for j in 0..count {
                let mut sum = 0;
                for (power, &(position, hash)) in powers.iter_mut().zip(hashes) {
                    sum = self.field.add(sum, self.field.mul(hash, *power));
                    *power = self.field.mul(*power, position);
                }
                let value = self.field.mul(sum, mask);
                let centered = if value > t / 2 {
                    -((t - value) as i64)
                } else {
                    value as i64
                };
                let weight = if j == 0 { centered } else { -centered };
                weights.push(weight);
                polynomial[if j == 0 { 0 } else { n - j }] = weight;
            }
            let mut w = Poly::try_convert_from(
                polynomial.as_slice(),
                ct[0].ctx(),
                false,
                Representation::PowerBasis,
            )
            .map_err(err)?;
            w.change_representation(Representation::Ntt);
            let product =
                Ciphertext::new(vec![&ct[0] * &w, &ct[1] * &w], &self.parameters).map_err(err)?;
            match &mut aggregate {
                Some(sum) => *sum += &product,
                None => aggregate = Some(product),
            }
        }
        let ctx = self.parameters.context_at_level(0).map_err(err)?;
        // Same native coins and equations as fhe::PublicKey::try_encrypt(0).
        // Retain the witnesses instead of discarding them inside that method.
        let u = zeroize::Zeroizing::new(
            Poly::small(ctx, Representation::Ntt, ERROR_VARIANCE, rng).map_err(err)?,
        );
        let e0 = zeroize::Zeroizing::new(
            Poly::small(ctx, Representation::Ntt, ERROR_VARIANCE, rng).map_err(err)?,
        );
        let e1 = zeroize::Zeroizing::new(
            Poly::small(ctx, Representation::Ntt, ERROR_VARIANCE, rng).map_err(err)?,
        );
        let pk = self.public_key_ciphertext()?;
        let mut z0 = &pk[0] * u.as_ref();
        z0 += e0.as_ref();
        let mut z1 = &pk[1] * u.as_ref();
        z1 += e1.as_ref();
        let zero = Ciphertext::new(vec![z0, z1], &self.parameters).map_err(err)?;
        let full = aggregate.ok_or("empty source")? + &zero;
        let q = ctx.moduli()[0];
        let small = |p: &Poly| -> Vec<i64> {
            let mut p = p.clone();
            p.change_representation(Representation::PowerBasis);
            p.coefficients()
                .row(0)
                .iter()
                .map(|&v| {
                    if v > q / 2 {
                        -((q - v) as i64)
                    } else {
                        v as i64
                    }
                })
                .collect()
        };
        let divisor: BigUint = self.parameters.moduli()[RETAINED_LIMBS..]
            .iter()
            .map(|&q| BigUint::from(q))
            .product();
        let limbs = (divisor.bits() as usize).div_ceil(32);
        let mut remainder_a = vec![vec![0; n]; limbs];
        let mut power = full[1].clone();
        power.change_representation(Representation::PowerBasis);
        for (i, value) in Vec::<BigUint>::from(&power).into_iter().enumerate() {
            let digits = (value % &divisor).to_u32_digits();
            for l in 0..limbs {
                remainder_a[l][i] = digits.get(l).copied().unwrap_or(0) as u64;
            }
        }
        let mut power = full[0].clone();
        power.change_representation(Representation::PowerBasis);
        let digits = (Vec::<BigUint>::from(&power)[0].clone() % &divisor).to_u32_digits();
        let remainder_b = (0..limbs)
            .map(|i| digits.get(i).copied().unwrap_or(0) as u64)
            .collect();
        let sanitized = divide_and_floor(&full, &self.parameters, RETAINED_LIMBS)?;
        let b = Self::coefficient_rows(&sanitized, 0)
            .iter()
            .map(|row| row[0])
            .collect();
        let a = Self::coefficient_rows(&sanitized, 1);
        let output = WireSampledRlweEvaluation {
            version: VERSION,
            id: self.id,
            b,
            a,
        };
        Ok((
            output,
            SampleEvaluationWitness {
                mask,
                logical_mask: None,
                weights,
                u: small(&u),
                e1: small(&e1),
                e0: small(&e0)[0],
                remainder_a,
                remainder_b,
            },
        ))
    }

    pub(crate) fn validate_sample(&self, value: &WireSampledRlweEvaluation) -> Result<(), String> {
        self.validate_protocol()?;
        if value.version != VERSION
            || value.id != self.id
            || value.a.len() != RETAINED_LIMBS
            || value.b.len() != RETAINED_LIMBS
        {
            return Err("incompatible sampled RLWE output".into());
        }
        for (i, (&b, a)) in value.b.iter().zip(&value.a).enumerate() {
            let q = self.parameters.moduli()[i];
            if b >= q || a.len() != self.ring_dimension() || a.iter().any(|&v| v >= q) {
                return Err("noncanonical sampled RLWE output".into());
            }
        }
        Ok(())
    }

    /// Public material only. No target secret is serialized by this API.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        wire_options(MAX_PUBLIC_CONTEXT_BYTES as u64)
            .serialize(&self.wire)
            .map_err(err)
    }

    /// Imports an independently usable monitor context, with a fixed parameter
    /// policy. A syntactically valid key is not a proof of honest key generation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_PUBLIC_CONTEXT_BYTES {
            return Err("invalid RLWE public context size".into());
        }
        let wire: WireRlwePublicContext = wire_options(MAX_PUBLIC_CONTEXT_BYTES as u64)
            .deserialize(bytes)
            .map_err(err)?;
        let profile = match (wire.ring_dimension as usize, wire.plaintext_modulus) {
            (RING_DIMENSION, PLAINTEXT_MODULUS) => RlweProfile::GoReference,
            (BLOOM_RING_DIMENSION, BLOOM_PLAINTEXT_MODULUS) => RlweProfile::Bloom100k,
            (CIRCUIT_PRIVACY_RING_DIMENSION, BLOOM_PLAINTEXT_MODULUS) => {
                RlweProfile::CircuitPrivacy100k
            }
            (CIRCUIT_PRIVACY_RING_DIMENSION, PROTOCOL_PLAINTEXT_MODULUS) => {
                RlweProfile::Protocol100k
            }
            (degree, PROTOCOL_PLAINTEXT_MODULUS)
                if super::packing_plan::PROTOCOL_RING_DIMENSIONS.contains(&degree) =>
            {
                RlweProfile::ProtocolSized {
                    ring_dimension: degree,
                }
            }
            #[cfg(test)]
            (16, PROTOCOL_PLAINTEXT_MODULUS) => RlweProfile::ProofTest,
            _ => return Err("unsupported RLWE parameter profile".into()),
        };
        let parameters = parameters(profile)?;
        if wire.version != VERSION
            || wire.ciphertext_moduli != parameters.moduli()
            || wire.public_key.is_empty()
            || wire.public_key.len() > MAX_BLOCK_BYTES
        {
            return Err("incompatible or malformed RLWE public context".into());
        }
        // The library's PublicKey decoder permits ciphertexts with more than
        // two components, whereas encryption uses exactly the first two.
        // Enforce the supported shape before constructing the public key.
        let proto = fhe::proto::bfv::PublicKey::decode(wire.public_key.as_slice()).map_err(err)?;
        let pk_ct = proto.c.ok_or("missing public key ciphertext")?;
        let pk_ct = Ciphertext::from_bytes(&pk_ct.encode_to_vec(), &parameters).map_err(err)?;
        if pk_ct.len() != 2 || pk_ct[0].ctx() != parameters.context_at_level(0).map_err(err)? {
            return Err("invalid public key ciphertext shape".into());
        }
        let pk = PublicKey::from_bytes(&wire.public_key, &parameters).map_err(err)?;
        if pk.to_bytes() != wire.public_key {
            return Err("noncanonical public key encoding".into());
        }
        let evaluation_key = if profile.layout().1 == PROTOCOL_PLAINTEXT_MODULUS {
            if !wire.evaluation_key.is_empty() {
                return Err("sample extraction needs no Galois keys".into());
            }
            None
        } else {
            let proto = fhe::proto::bfv::EvaluationKey::decode(wire.evaluation_key.as_slice())
                .map_err(err)?;
            if proto.ciphertext_level != 0 || proto.evaluation_key_level != 0 {
                return Err("unsupported evaluation key levels".into());
            }
            let evaluation_key =
                EvaluationKey::from_bytes(&wire.evaluation_key, &parameters).map_err(err)?;
            if !evaluation_key.supports_inner_sum() {
                return Err("missing required automorphism keys".into());
            }
            Some(evaluation_key)
        };
        let id = context_id(&wire);
        Ok(Self {
            field: Modulus::new(wire.plaintext_modulus).map_err(err)?,
            parameters,
            pk,
            evaluation_key,
            id,
            wire,
        })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.id
    }

    /// Validates the exact public noise/modulus budget for the terminal
    /// transformation. This does not prove the honesty of imported keys/CTs.
    pub fn circuit_privacy_budget(&self) -> Result<PrivacyBudget, String> {
        if self.plaintext_modulus() == PROTOCOL_PLAINTEXT_MODULUS {
            self.validate_protocol()?;
            return PrivacyBudget::calculate_sampled(
                self.ring_dimension(),
                self.plaintext_modulus(),
                self.parameters.moduli(),
                MAX_COEFFICIENTS,
                MEMBERSHIP_REPETITIONS,
            );
        }
        if self.ring_dimension() != CIRCUIT_PRIVACY_RING_DIMENSION
            || self.parameters.moduli().len() != 7
        {
            return Err("circuit privacy requires the CircuitPrivacy100k profile".into());
        }
        PrivacyBudget::calculate(
            self.ring_dimension(),
            self.plaintext_modulus(),
            self.parameters.moduli(),
            MAX_COEFFICIENTS,
            MEMBERSHIP_REPETITIONS,
        )
    }

    pub fn sanitized_evaluation_from_wire(
        &self,
        wire: &WireSanitizedRlweEvaluation,
    ) -> Result<SanitizedRlweEvaluation, String> {
        self.circuit_privacy_budget()?;
        if wire.version != VERSION
            || wire.id != self.id
            || wire.ciphertext.is_empty()
            || wire.ciphertext.len() > MAX_BLOCK_BYTES
        {
            return Err("incompatible sanitized evaluation".into());
        }
        let ct = Ciphertext::from_bytes(&wire.ciphertext, &self.parameters).map_err(err)?;
        let context = self
            .parameters
            .context_at_level(self.parameters.moduli().len() - RETAINED_LIMBS)
            .map_err(err)?;
        if ct.len() != 2 || ct[0].ctx() != context || ct.to_bytes() != wire.ciphertext {
            return Err("noncanonical sanitized evaluation or wrong terminal level".into());
        }
        Ok(SanitizedRlweEvaluation { ct, id: self.id })
    }

    /// Rerandomize then discard all but two modulus limbs via exact floor.
    /// The budget assumes fresh honest source ciphertexts; a future report must
    /// prove source/key bounds and the complete evaluation/transformation.
    pub fn evaluate_membership_sanitized<R: RngCore + CryptoRng>(
        &self,
        source: &PackedRlweCiphertext,
        input: Scalar,
        config: BloomFilterConfig,
        rng: &mut R,
    ) -> Result<Vec<SanitizedRlweEvaluation>, String> {
        self.circuit_privacy_budget()?;
        let raw = self.evaluate_membership(source, input, config, rng)?;
        let zero = self.encode(&[0])?;
        raw.into_iter()
            .map(|evaluation| {
                let rerandomized = evaluation.ct + &self.pk.try_encrypt(&zero, rng).map_err(err)?;
                Ok(SanitizedRlweEvaluation {
                    ct: divide_and_floor(&rerandomized, &self.parameters, RETAINED_LIMBS)?,
                    id: self.id,
                })
            })
            .collect()
    }

    pub fn plaintext_modulus(&self) -> u64 {
        self.wire.plaintext_modulus
    }
    pub fn ring_dimension(&self) -> usize {
        self.parameters.degree()
    }

    /// Build the root polynomial directly in this plaintext field. Converting
    /// coefficients from the Ristretto field would not preserve the roots.
    pub fn polynomial_from_roots(&self, roots: &[u64]) -> Result<Vec<u64>, String> {
        if roots.len() >= MAX_COEFFICIENTS {
            return Err("too many polynomial roots".into());
        }
        super::rlwe_polynomial::from_roots(roots, self.plaintext_modulus())
    }

    /// Polynomial roots are the marked bucket numbers. Padding makes ciphertext
    /// size depend on the public bucket count, rather than the target density.
    pub fn encrypt_bloom_positions<R: RngCore + CryptoRng>(
        &self,
        config: BloomFilterConfig,
        marked_positions: &[u64],
        rng: &mut R,
    ) -> Result<PackedRlweCiphertext, String> {
        config.validate()?;
        if config.bloom_filter_size >= MAX_COEFFICIENTS
            || config.bloom_filter_size as u64 >= self.plaintext_modulus()
            || marked_positions
                .iter()
                .any(|&i| i == 0 || i > config.bloom_filter_size as u64)
        {
            return Err("Bloom domain does not fit the RLWE parameters".into());
        }
        let mut roots = zeroize::Zeroizing::new(marked_positions.to_vec());
        roots.sort_unstable();
        roots.dedup();
        let coefficients = zeroize::Zeroizing::new(self.polynomial_from_roots(&roots)?);
        let mut padded = zeroize::Zeroizing::new(vec![0; config.bloom_filter_size + 1]);
        padded[..coefficients.len()].copy_from_slice(&coefficients);
        self.encrypt(&padded, rng)
    }

    fn encode(&self, values: &[u64]) -> Result<Plaintext, String> {
        Plaintext::try_encode(values, Encoding::poly(), &self.parameters).map_err(err)
    }

    fn decode_ciphertext(&self, bytes: &[u8]) -> Result<Ciphertext, String> {
        if bytes.is_empty() || bytes.len() > MAX_BLOCK_BYTES {
            return Err("invalid ciphertext size".into());
        }
        let ct = Ciphertext::from_bytes(bytes, &self.parameters).map_err(err)?;
        if ct.len() != 2
            || ct[0].ctx() != self.parameters.context_at_level(0).map_err(err)?
            || ct.to_bytes() != bytes
        {
            return Err("noncanonical or unsupported ciphertext".into());
        }
        Ok(ct)
    }

    pub fn evaluation_from_wire(
        &self,
        wire: &WireRlweEvaluation,
    ) -> Result<RlweEvaluation, String> {
        if wire.version != VERSION || wire.id != self.id {
            return Err("incompatible RLWE version, parameters, or key".into());
        }
        Ok(RlweEvaluation {
            ct: self.decode_ciphertext(&wire.ciphertext)?,
            id: self.id,
        })
    }

    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        coefficients: &[u64],
        rng: &mut R,
    ) -> Result<PackedRlweCiphertext, String> {
        if coefficients.is_empty() || coefficients.len() > MAX_COEFFICIENTS {
            return Err("unsupported coefficient count".into());
        }
        if coefficients.iter().any(|&c| c >= self.plaintext_modulus()) {
            return Err("coefficient is not a canonical plaintext field element".into());
        }
        let blocks = coefficients
            .chunks(self.ring_dimension())
            .map(|chunk| self.pk.try_encrypt(&self.encode(chunk)?, rng).map_err(err))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(PackedRlweCiphertext {
            blocks,
            coefficient_count: coefficients.len(),
            id: self.id,
        })
    }

    /// Adds independent public-key encryptions of zero to every coefficient block.
    /// This preserves plaintexts but is not a circuit-privacy noise-flooding scheme.
    pub fn rerandomize<R: RngCore + CryptoRng>(
        &self,
        source: &PackedRlweCiphertext,
        rng: &mut R,
    ) -> Result<PackedRlweCiphertext, String> {
        if source.id != self.id {
            return Err("incompatible RLWE key".into());
        }
        let zero = self.encode(&[0])?;
        let blocks = source
            .blocks
            .iter()
            .map(|ct| Ok(ct + &self.pk.try_encrypt(&zero, rng).map_err(err)?))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(PackedRlweCiphertext {
            blocks,
            coefficient_count: source.coefficient_count,
            id: self.id,
        })
    }

    /// Strict, context-bound decoding. This validates structure, not provenance.
    pub fn from_wire(
        &self,
        wire: &WirePackedRlweCiphertext,
    ) -> Result<PackedRlweCiphertext, String> {
        if wire.version != VERSION || wire.id != self.id {
            return Err("incompatible RLWE version, parameters, or key".into());
        }
        if wire.coefficient_count == 0
            || wire.coefficient_count > MAX_COEFFICIENTS
            || wire.blocks.len() != wire.coefficient_count.div_ceil(self.ring_dimension())
        {
            return Err("invalid packing shape".into());
        }
        let blocks = wire
            .blocks
            .iter()
            .map(|bytes| self.decode_ciphertext(bytes))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(PackedRlweCiphertext {
            blocks,
            coefficient_count: wire.coefficient_count,
            id: self.id,
        })
    }

    /// Computes r * sum_i h_i P(i), with no secret-key access.
    ///
    /// For a block A(X), choose W[0]=w[0], W[N-j]=-w[j]. Then
    /// constant(A*W mod (X^N+1)) = sum_j A[j] w[j]. Homomorphic
    /// inner-sum is the ring trace: it kills nonconstant coefficients and
    /// multiplies the constant by N. Dividing the weights by N compensates.
    pub fn evaluate(
        &self,
        source: &PackedRlweCiphertext,
        positions_and_weights: &[(u64, u64)],
        r: u64,
    ) -> Result<RlweEvaluation, String> {
        if source.id != self.id {
            return Err("incompatible RLWE key".into());
        }
        if r == 0
            || r >= self.plaintext_modulus()
            || positions_and_weights.is_empty()
            || positions_and_weights
                .iter()
                .any(|&(i, h)| i >= self.plaintext_modulus() || h >= self.plaintext_modulus())
        {
            return Err("invalid field evaluation witness".into());
        }
        let inv_n = self
            .field
            .inv(self.ring_dimension() as u64)
            .ok_or("ring dimension is not invertible in the plaintext field")?;
        let mut powers = vec![1; positions_and_weights.len()];
        let mut result: Option<Ciphertext> = None;
        for (block_index, block) in source.blocks.iter().enumerate() {
            let count = (source.coefficient_count - block_index * self.ring_dimension())
                .min(self.ring_dimension());
            let mut weights = vec![0; self.ring_dimension()];
            for j in 0..count {
                let mut w = 0;
                for (power, &(position, h)) in powers.iter_mut().zip(positions_and_weights) {
                    w = self.field.add(w, self.field.mul(h, *power));
                    *power = self.field.mul(*power, position);
                }
                w = self.field.mul(self.field.mul(w, r), inv_n);
                if j == 0 {
                    weights[0] = w;
                } else {
                    weights[self.ring_dimension() - j] = self.field.neg(w);
                }
            }
            let product = block * &self.encode(&weights)?;
            match &mut result {
                Some(ct) => *ct += &product,
                None => result = Some(product),
            }
        }
        let ct = self
            .evaluation_key
            .as_ref()
            .ok_or("this profile uses scalar coefficient extraction")?
            .computes_inner_sum(&result.ok_or("empty ciphertext")?)
            .map_err(err)?;
        Ok(RlweEvaluation { ct, id: self.id })
    }

    pub fn evaluate_item<R: RngCore + CryptoRng>(
        &self,
        source: &PackedRlweCiphertext,
        input: Scalar,
        config: BloomFilterConfig,
        rng: &mut R,
    ) -> Result<RlweEvaluation, String> {
        let weights = item_weights_in_field(input, config, self.plaintext_modulus())?;
        self.evaluate(
            source,
            &weights,
            rng.random_range(1..self.plaintext_modulus()),
        )
    }
}

impl RlwePublicContext {
    /// Repeating a mask alone cannot reduce cancellation; each repetition uses
    /// independent, domain-separated hash weights for the same private input.
    pub fn evaluate_membership<R: RngCore + CryptoRng>(
        &self,
        source: &PackedRlweCiphertext,
        input: Scalar,
        config: BloomFilterConfig,
        rng: &mut R,
    ) -> Result<Vec<RlweEvaluation>, String> {
        if self.plaintext_modulus() != BLOOM_PLAINTEXT_MODULUS {
            return Err("membership evaluation requires the wide Bloom profile".into());
        }
        (0..MEMBERSHIP_REPETITIONS)
            .map(|repetition| {
                let weights = item_weights_for_repetition(
                    input,
                    config,
                    self.plaintext_modulus(),
                    repetition as u64,
                )?;
                self.evaluate(
                    source,
                    &weights,
                    rng.random_range(1..self.plaintext_modulus()),
                )
            })
            .collect()
    }
}

impl PackedRlweCiphertext {
    pub fn coefficient_count(&self) -> usize {
        self.coefficient_count
    }
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
    pub fn to_wire(&self) -> WirePackedRlweCiphertext {
        WirePackedRlweCiphertext {
            version: VERSION,
            id: self.id,
            coefficient_count: self.coefficient_count,
            blocks: self.blocks.iter().map(FheSerialize::to_bytes).collect(),
        }
    }
}

impl RlweEvaluation {
    pub fn to_wire(&self) -> WireRlweEvaluation {
        WireRlweEvaluation {
            version: VERSION,
            id: self.id,
            ciphertext: self.ct.to_bytes(),
        }
    }
}

impl SanitizedRlweEvaluation {
    pub fn to_wire(&self) -> WireSanitizedRlweEvaluation {
        WireSanitizedRlweEvaluation {
            version: VERSION,
            id: self.id,
            ciphertext: self.ct.to_bytes(),
        }
    }
}

impl RlweSecretKey {
    pub(crate) fn decrypt_sample(
        &self,
        public: &RlwePublicContext,
        value: &WireSampledRlweEvaluation,
    ) -> Result<u64, String> {
        public.validate_sample(value)?;
        if self.id != public.id {
            return Err("RLWE secret/public key mismatch".into());
        }
        let moduli = &public.parameters.moduli()[..RETAINED_LIMBS];
        let rns = RnsContext::new(moduli).map_err(err)?;
        let ctx = public
            .parameters
            .context_at_level(public.parameters.moduli().len() - RETAINED_LIMBS)
            .map_err(err)?;
        let a = (0..public.ring_dimension())
            .map(|i| {
                rns.lift(
                    value
                        .a
                        .iter()
                        .map(|row| row[i])
                        .collect::<Vec<_>>()
                        .as_slice()
                        .into(),
                )
            })
            .collect::<Vec<_>>();
        let b = vec![rns.lift(value.b.as_slice().into())];
        let mut a = Poly::try_convert_from(a.as_slice(), ctx, false, Representation::PowerBasis)
            .map_err(err)?;
        let mut b = Poly::try_convert_from(b.as_slice(), ctx, false, Representation::PowerBasis)
            .map_err(err)?;
        a.change_representation(Representation::Ntt);
        b.change_representation(Representation::Ntt);
        let ct = Ciphertext::new(vec![b, a], &public.parameters).map_err(err)?;
        let pt = self.sk.try_decrypt(&ct).map_err(err)?;
        Ok(Vec::<u64>::try_decode(&pt, Encoding::poly()).map_err(err)?[0])
    }
    pub fn decrypt_sanitized_membership(
        &self,
        results: &[SanitizedRlweEvaluation],
    ) -> Result<bool, String> {
        if results.len() != MEMBERSHIP_REPETITIONS {
            return Err("invalid sanitized membership repetition count".into());
        }
        let mut member = true;
        for result in results {
            if result.id != self.id {
                return Err("incompatible RLWE key".into());
            }
            let pt = self.sk.try_decrypt(&result.ct).map_err(err)?;
            let values = Vec::<u64>::try_decode(&pt, Encoding::poly()).map_err(err)?;
            if values[1..].iter().any(|&v| v != 0) {
                return Err("evaluation is not constant".into());
            }
            member &= values[0] == 0;
        }
        Ok(member)
    }
    /// Arithmetic predicate only: callers still need a complete report proof.
    pub fn decrypt_membership(&self, results: &[RlweEvaluation]) -> Result<bool, String> {
        if results.len() != MEMBERSHIP_REPETITIONS {
            return Err("invalid membership repetition count".into());
        }
        let values = results
            .iter()
            .map(|r| self.decrypt_evaluation(r))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(values.iter().all(|&value| value == 0))
    }
    pub fn decrypt_coefficients(&self, source: &PackedRlweCiphertext) -> Result<Vec<u64>, String> {
        if source.id != self.id {
            return Err("incompatible RLWE key".into());
        }
        let mut out = Vec::new();
        for ct in &source.blocks {
            let pt = self.sk.try_decrypt(ct).map_err(err)?;
            out.extend(Vec::<u64>::try_decode(&pt, Encoding::poly()).map_err(err)?);
        }
        if out[source.coefficient_count..].iter().any(|&x| x != 0) {
            return Err("nonzero coefficient padding".into());
        }
        out.truncate(source.coefficient_count);
        Ok(out)
    }

    /// Arithmetic test helper; calling this does not authenticate a report.
    pub fn decrypt_evaluation(&self, result: &RlweEvaluation) -> Result<u64, String> {
        if result.id != self.id {
            return Err("incompatible RLWE key".into());
        }
        let pt = self.sk.try_decrypt(&result.ct).map_err(err)?;
        let values = Vec::<u64>::try_decode(&pt, Encoding::poly()).map_err(err)?;
        if values[1..].iter().any(|&x| x != 0) {
            return Err("evaluation is not a constant polynomial".into());
        }
        Ok(values[0])
    }
}

/// Canonical Bloom-bit-vector hashing, with rejection sampling into F_65537.
pub fn item_weights(input: Scalar, config: BloomFilterConfig) -> Result<Vec<(u64, u64)>, String> {
    item_weights_in_field(input, config, PLAINTEXT_MODULUS)
}

pub fn item_weights_in_field(
    input: Scalar,
    config: BloomFilterConfig,
    modulus: u64,
) -> Result<Vec<(u64, u64)>, String> {
    item_weights_for_repetition(input, config, modulus, 0)
}

pub fn item_weights_for_repetition(
    input: Scalar,
    config: BloomFilterConfig,
    modulus: u64,
    repetition: u64,
) -> Result<Vec<(u64, u64)>, String> {
    if ![PLAINTEXT_MODULUS, BLOOM_PLAINTEXT_MODULUS].contains(&modulus) {
        return Err("unsupported plaintext field".into());
    }
    config.validate()?;
    let raw = scalar_to_usize(input);
    if config.bloom_filter_size >= modulus as usize
        || config.bloom_filter_size >= MAX_COEFFICIENTS
        || raw == 0
        || raw > usable_input_span(config)
        || Scalar::from(raw as u64) != input
    {
        return Err("input or Bloom domain cannot be represented faithfully".into());
    }
    let mut positions: Vec<u64> = scalar_positions(input, config)
        .into_iter()
        .map(|s| scalar_to_usize(s) as u64)
        .collect();
    positions.sort_unstable();
    positions.dedup();
    let bits = super::bloom::scalar_bloom_bits(input, config)?;
    positions
        .into_iter()
        .map(|i| {
            for counter in 0..MAX_HASH_ATTEMPTS as u64 {
                let mut hash = Sha256::new();
                hash.update(WEIGHT_DOMAIN);
                hash.update(modulus.to_le_bytes());
                hash.update(repetition.to_le_bytes());
                hash.update((config.bloom_filter_size as u64).to_le_bytes());
                hash.update((config.hash_count as u64).to_le_bytes());
                hash.update(&bits);
                hash.update(i.to_le_bytes());
                hash.update(counter.to_le_bytes());
                let digest = hash.finalize();
                let candidate = u64::from_le_bytes(digest[..8].try_into().unwrap());
                let limit = u64::MAX - u64::MAX % modulus;
                if candidate < limit {
                    return Ok((i, candidate % modulus));
                }
            }
            Err("hash-to-field rejection limit exhausted; no biased fallback is allowed".into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mul(a: u64, b: u64) -> u64 {
        field_mul(a, b, PLAINTEXT_MODULUS)
    }
    use std::time::Instant;

    fn direct(coefficients: &[u64], weights: &[(u64, u64)], r: u64) -> u64 {
        mul(
            r,
            weights.iter().fold(0, |sum, &(i, h)| {
                let p = coefficients
                    .iter()
                    .rev()
                    .fold(0, |acc, &c| (mul(acc, i) + c) % PLAINTEXT_MODULUS);
                (sum + mul(h, p)) % PLAINTEXT_MODULUS
            }),
        )
    }

    #[test]
    fn go_reference_and_weighted_evaluation() {
        let mut rng = rand09::rng();
        let start = Instant::now();
        let (public, secret) = generate_reference_keys(&mut rng).unwrap();
        eprintln!("RLWE key generation: {:?}", start.elapsed());
        // Generated by running packing/polynomial.go, unmodified, in a temporary
        // Go main package. These are coefficient vectors, not batching slots.
        let fixtures: &[(&[u64], &[u64])] = &[
            (&[3, 17], &[51, 65517, 1]),
            (&[3, 7, 17], &[65180, 191, 65510, 1]),
            (
                &[1, 2, 3, 4, 5, 6, 7, 8],
                &[40320, 21490, 52587, 63790, 22449, 61001, 546, 65501, 1],
            ),
        ];
        for &(roots, coefficients) in fixtures {
            let start = Instant::now();
            let ct = public.encrypt(coefficients, &mut rng).unwrap();
            eprintln!("packing + encryption: {:?}", start.elapsed());
            assert_eq!(secret.decrypt_coefficients(&ct).unwrap(), coefficients);
            let rerandomized = public.rerandomize(&ct, &mut rng).unwrap();
            assert_ne!(ct.to_wire().blocks, rerandomized.to_wire().blocks);
            assert_eq!(
                secret.decrypt_coefficients(&rerandomized).unwrap(),
                coefficients
            );
            let bytes = bincode::serialize(&ct.to_wire()).unwrap();
            let wire = bincode::deserialize(&bytes).unwrap();
            let ct = public.from_wire(&wire).unwrap();
            eprintln!("packed ciphertext: {} bytes", bytes.len());
            for positions in [
                vec![(roots[0], 23), (roots[1], 91)],
                vec![(9, 431), (33, 271)],
                vec![(0, 0), (65536, 65536)],
            ] {
                for r in [1, 65536] {
                    let expected = direct(coefficients, &positions, r);
                    let start = Instant::now();
                    let result = public.evaluate(&ct, &positions, r).unwrap();
                    eprintln!(
                        "homomorphic evaluation: {:?}; output: {} bytes",
                        start.elapsed(),
                        result.ct.to_bytes().len()
                    );
                    assert_eq!(secret.decrypt_evaluation(&result).unwrap(), expected);
                }
            }
        }
    }

    #[test]
    fn packing_boundaries_and_global_powers() {
        let mut rng = rand09::rng();
        let (public, secret) = generate_reference_keys(&mut rng).unwrap();
        for len in [
            RING_DIMENSION - 1,
            RING_DIMENSION,
            RING_DIMENSION + 1,
            2 * RING_DIMENSION + 1,
        ] {
            let coefficients: Vec<u64> = (0..len)
                .map(|j| (j as u64 * 7919 + 123) % PLAINTEXT_MODULUS)
                .collect();
            let ct = public.encrypt(&coefficients, &mut rng).unwrap();
            assert_eq!(ct.blocks.len(), len.div_ceil(RING_DIMENSION));
            assert_eq!(secret.decrypt_coefficients(&ct).unwrap(), coefficients);
            let weights = [(13, 48831), (91, 65536), (0, 15)];
            let result = public.evaluate(&ct, &weights, 52427).unwrap();
            assert_eq!(
                secret.decrypt_evaluation(&result).unwrap(),
                direct(&coefficients, &weights, 52427)
            );
        }
    }

    #[test]
    fn malformed_wire_and_incompatible_keys_rejected() {
        let mut rng = rand09::rng();
        let (public, secret) = generate_reference_keys(&mut rng).unwrap();
        let (other, other_secret) = generate_reference_keys(&mut rng).unwrap();
        assert!(public.encrypt(&[], &mut rng).is_err());
        assert!(public.encrypt(&[65537], &mut rng).is_err());
        let ct = public.encrypt(&[1, 2, 3], &mut rng).unwrap();
        assert!(other.from_wire(&ct.to_wire()).is_err());
        assert!(other.evaluate(&ct, &[(1, 1)], 1).is_err());
        assert!(other_secret.decrypt_coefficients(&ct).is_err());
        assert!(public.evaluate(&ct, &[], 1).is_err());
        assert!(public.evaluate(&ct, &[(1, 1)], 0).is_err());
        assert!(public.evaluate(&ct, &[(65537, 1)], 1).is_err());
        for variant in 0..6 {
            let mut wire = ct.to_wire();
            match variant {
                0 => wire.version += 1,
                1 => wire.id[0] ^= 1,
                2 => wire.coefficient_count = 0,
                3 => wire.blocks.clear(),
                4 => wire.blocks[0] = vec![255; 20],
                _ => wire.coefficient_count = RING_DIMENSION + 1,
            }
            assert!(public.from_wire(&wire).is_err());
        }
        let result = public.evaluate(&ct, &[(1, 1)], 1).unwrap();
        assert!(other_secret.decrypt_evaluation(&result).is_err());
        assert_eq!(secret.decrypt_evaluation(&result).unwrap(), 6);
    }

    #[test]
    fn bloom_hashing_and_item_evaluation() {
        let config = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 3,
            target_marked_count: 8,
        };
        let weights = item_weights(Scalar::from(3u64), config).unwrap();
        assert_eq!(
            weights.iter().map(|p| p.0).collect::<Vec<_>>(),
            vec![3, 7, 11]
        );
        assert_eq!(weights, item_weights(Scalar::from(3u64), config).unwrap());
        assert_ne!(weights, item_weights(Scalar::from(4u64), config).unwrap());
        assert!(item_weights(Scalar::zero(), config).is_err());
        assert!(item_weights(Scalar::from(11u64), config).is_err());
        let large = BloomFilterConfig {
            bloom_filter_size: 65537,
            ..config
        };
        assert!(item_weights(Scalar::one(), large).is_err());
        let mut rng = rand09::rng();
        let (public, secret) = generate_reference_keys(&mut rng).unwrap();
        // P=(X-3)(X-7)(X-11), all positions of input=3 are roots.
        let ct = public.encrypt(&[65306, 131, 65516, 1], &mut rng).unwrap();
        for _ in 0..3 {
            let result = public
                .evaluate_item(&ct, Scalar::from(3u64), config, &mut rng)
                .unwrap();
            assert_eq!(secret.decrypt_evaluation(&result).unwrap(), 0);
        }
        let expected = direct(
            &[65306, 131, 65516, 1],
            &item_weights(Scalar::from(4u64), config).unwrap(),
            1,
        );
        let result = public
            .evaluate(&ct, &item_weights(Scalar::from(4u64), config).unwrap(), 1)
            .unwrap();
        assert_eq!(secret.decrypt_evaluation(&result).unwrap(), expected);
        assert_ne!(expected, 0);
    }

    #[test]
    fn maximum_capacity_noise_regression() {
        let mut rng = rand09::rng();
        let (public, secret) = generate_reference_keys(&mut rng).unwrap();
        let coefficients = vec![PLAINTEXT_MODULUS - 1; MAX_COEFFICIENTS];
        let weights = [(65536, 65536), (317, 65535), (1, 32768)];
        let ct = public.encrypt(&coefficients, &mut rng).unwrap();
        assert_eq!(secret.decrypt_coefficients(&ct).unwrap(), coefficients);
        let result = public.evaluate(&ct, &weights, 65536).unwrap();
        assert_eq!(
            secret.decrypt_evaluation(&result).unwrap(),
            direct(&coefficients, &weights, 65536)
        );
        // The library's diagnostic is variable-time; only expose it in tests.
        let noise = unsafe { secret.sk.measure_noise(&result.ct).unwrap() };
        let q_bits: f64 = public
            .parameters
            .moduli()
            .iter()
            .map(|&q| (q as f64).log2())
            .sum();
        let limit = q_bits - (2.0 * PLAINTEXT_MODULUS as f64).log2();
        eprintln!("maximum capacity: {} coefficients; noise: {noise} bits; approximate decoding limit: {limit:.1} bits", coefficients.len());
        assert!((noise as f64) < limit);
    }

    #[test]
    fn independent_monitor_context_and_result_transport() {
        let mut rng = rand09::rng();
        let (target_public, target_secret) = generate_reference_keys(&mut rng).unwrap();
        let bytes = target_public.to_bytes().unwrap();
        let monitor = RlwePublicContext::from_bytes(&bytes).unwrap();
        assert_eq!(monitor.to_bytes().unwrap(), bytes);
        assert_eq!(monitor.fingerprint(), target_public.fingerprint());
        let config = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 3,
            target_marked_count: 8,
        };
        // No secret-key object is passed to the reconstructed monitor context.
        for input in [3u64, 4] {
            let coefficients = [65306, 131, 65516, 1];
            let source = target_public.encrypt(&coefficients, &mut rng).unwrap();
            let source_bytes = bincode::serialize(&source.to_wire()).unwrap();
            let monitor_source = monitor
                .from_wire(&bincode::deserialize(&source_bytes).unwrap())
                .unwrap();
            let weights = item_weights(Scalar::from(input), config).unwrap();
            let output = monitor.evaluate(&monitor_source, &weights, 49153).unwrap();
            let output_bytes = bincode::serialize(&output.to_wire()).unwrap();
            let output = target_public
                .evaluation_from_wire(&bincode::deserialize(&output_bytes).unwrap())
                .unwrap();
            assert_eq!(
                target_secret.decrypt_evaluation(&output).unwrap(),
                direct(&coefficients, &weights, 49153)
            );
            let result = monitor
                .evaluate_item(&monitor_source, Scalar::from(input), config, &mut rng)
                .unwrap();
            let result = target_public
                .evaluation_from_wire(&result.to_wire())
                .unwrap();
            assert_eq!(
                target_secret.decrypt_evaluation(&result).unwrap() == 0,
                input == 3
            );
        }
    }

    #[test]
    fn public_context_and_evaluation_shape_validation() {
        let mut rng = rand09::rng();
        let (public, _) = generate_reference_keys(&mut rng).unwrap();
        let mut bytes = public.to_bytes().unwrap();
        bytes.push(0);
        assert!(RlwePublicContext::from_bytes(&bytes).is_err());
        assert!(RlwePublicContext::from_bytes(&[]).is_err());
        for variant in 0..10 {
            let mut wire = public.wire.clone();
            match variant {
                0 => wire.version += 1,
                1 => wire.ring_dimension *= 2,
                2 => wire.plaintext_modulus += 1,
                3 => wire.ciphertext_moduli[0] += 1,
                4 => wire.public_key.clear(),
                5 => wire.evaluation_key.clear(),
                6 => wire.public_key = vec![255; 16],
                7 => wire.evaluation_key = vec![255; 16],
                8 => {
                    let mut key =
                        fhe::proto::bfv::PublicKey::decode(wire.public_key.as_slice()).unwrap();
                    let ct = key.c.as_mut().unwrap();
                    ct.c.push(ct.c[0].clone());
                    wire.public_key = key.encode_to_vec();
                }
                _ => {
                    wire.evaluation_key = fhe::proto::bfv::EvaluationKey::default().encode_to_vec()
                }
            }
            let bytes = wire_options(MAX_PUBLIC_CONTEXT_BYTES as u64)
                .serialize(&wire)
                .unwrap();
            assert!(
                RlwePublicContext::from_bytes(&bytes).is_err(),
                "invalid context variant {variant}"
            );
        }
        let source = public.encrypt(&[1, 2, 3], &mut rng).unwrap();
        let result = public.evaluate(&source, &[(2, 1)], 1).unwrap();
        for variant in 0..4 {
            let mut wire = result.to_wire();
            match variant {
                0 => wire.version += 1,
                1 => wire.id[0] ^= 1,
                2 => wire.ciphertext = vec![255; 20],
                _ => wire.ciphertext.clear(),
            }
            assert!(public.evaluation_from_wire(&wire).is_err());
        }
    }

    #[test]
    fn wide_profile_supports_100k_bloom_buckets_and_roots() {
        let mut rng = rand09::rng();
        let start = Instant::now();
        let (public, secret) = generate_keys(&mut rng).unwrap();
        eprintln!("100k profile key generation: {:?}", start.elapsed());
        let config = BloomFilterConfig {
            bloom_filter_size: 100_000,
            hash_count: 1,
            target_marked_count: 100_000,
        };
        let roots: Vec<u64> = (1..=100_000).collect();
        let start = Instant::now();
        let ct = public
            .encrypt_bloom_positions(config, &roots, &mut rng)
            .unwrap();
        eprintln!(
            "100k root polynomial, packing and encryption: {:?}",
            start.elapsed()
        );
        assert_eq!(ct.coefficient_count(), 100_001);
        assert_eq!(ct.block_count(), 13);
        // Distinct bucket labels on both sides of the old 65537 boundary.
        let weights = [
            (65_537, BLOOM_PLAINTEXT_MODULUS - 1),
            (100_000, 234_567_891),
        ];
        let start = Instant::now();
        let result = public
            .evaluate(&ct, &weights, BLOOM_PLAINTEXT_MODULUS - 1)
            .unwrap();
        assert_eq!(secret.decrypt_evaluation(&result).unwrap(), 0);
        eprintln!("100k weighted root evaluation: {:?}", start.elapsed());
        // At zero, P(0) is nonzero since none of its roots is zero.
        let result = public.evaluate(&ct, &[(0, 1)], 1).unwrap();
        assert_ne!(secret.decrypt_evaluation(&result).unwrap(), 0);
        let monitor = RlwePublicContext::from_bytes(&public.to_bytes().unwrap()).unwrap();
        let source = monitor.from_wire(&ct.to_wire()).unwrap();
        let result = monitor
            .evaluate_item(&source, Scalar::from(100_000u64), config, &mut rng)
            .unwrap();
        let result = public.evaluation_from_wire(&result.to_wire()).unwrap();
        assert_eq!(secret.decrypt_evaluation(&result).unwrap(), 0);
        let noise = unsafe { secret.sk.measure_noise(&result.ct).unwrap() };
        eprintln!("100k profile output noise: {noise} bits");
    }

    #[test]
    fn wide_field_exact_arithmetic_density_padding_and_domain_separation() {
        let mut rng = rand09::rng();
        let (public, secret) =
            generate_keys_with_profile(&mut rng, RlweProfile::Bloom100k).unwrap();
        let config = BloomFilterConfig {
            bloom_filter_size: 100_000,
            hash_count: 3,
            target_marked_count: 10,
        };
        let roots = [30_000, 60_001, 90_002];
        let ct = public
            .encrypt_bloom_positions(config, &roots, &mut rng)
            .unwrap();
        assert_eq!(ct.coefficient_count(), 100_001);
        assert_eq!(ct.block_count(), 13);
        let result = public
            .evaluate_item(&ct, Scalar::from(30_000u64), config, &mut rng)
            .unwrap();
        assert_eq!(secret.decrypt_evaluation(&result).unwrap(), 0);
        let weights =
            item_weights_in_field(Scalar::from(30_001u64), config, BLOOM_PLAINTEXT_MODULUS)
                .unwrap();
        let coefficients = public.polynomial_from_roots(&roots).unwrap();
        let r = BLOOM_PLAINTEXT_MODULUS - 1;
        let expected = field_mul(
            r,
            weights.iter().fold(0, |sum, &(i, h)| {
                let value = coefficients.iter().rev().fold(0, |acc, &c| {
                    (field_mul(acc, i, BLOOM_PLAINTEXT_MODULUS) + c) % BLOOM_PLAINTEXT_MODULUS
                });
                (sum + field_mul(h, value, BLOOM_PLAINTEXT_MODULUS)) % BLOOM_PLAINTEXT_MODULUS
            }),
            BLOOM_PLAINTEXT_MODULUS,
        );
        let result = public.evaluate(&ct, &weights, r).unwrap();
        assert_eq!(secret.decrypt_evaluation(&result).unwrap(), expected);
        assert_ne!(expected, 0);
        let matches = public
            .evaluate_membership(&ct, Scalar::from(30_000u64), config, &mut rng)
            .unwrap();
        assert!(secret.decrypt_membership(&matches).unwrap());
        let misses = public
            .evaluate_membership(&ct, Scalar::from(30_001u64), config, &mut rng)
            .unwrap();
        assert!(!secret.decrypt_membership(&misses).unwrap());
        assert!(secret.decrypt_membership(&misses[..2]).is_err());
        let hashes0 = item_weights_for_repetition(
            Scalar::from(30_001u64),
            config,
            BLOOM_PLAINTEXT_MODULUS,
            0,
        )
        .unwrap();
        let hashes1 = item_weights_for_repetition(
            Scalar::from(30_001u64),
            config,
            BLOOM_PLAINTEXT_MODULUS,
            1,
        )
        .unwrap();
        assert_ne!(hashes0, hashes1);
        assert!(item_weights(Scalar::from(30_000u64), config).is_err());
        assert!(public
            .encrypt_bloom_positions(config, &[100_001], &mut rng)
            .is_err());
        let (reference, _) = generate_reference_keys(&mut rng).unwrap();
        assert!(reference.from_wire(&ct.to_wire()).is_err());
        assert!(reference
            .encrypt_bloom_positions(config, &roots, &mut rng)
            .is_err());
    }
}
#[cfg(test)]
mod privacy_tests {
    use super::*;
    #[test]
    fn production_field_handles_100k_distinct_roots_and_dense_packing() {
        let mut rng = rand09::rng();
        let (public, secret) =
            generate_keys_with_profile(&mut rng, RlweProfile::Protocol100k).unwrap();
        let roots = (1..=100_000).collect::<Vec<_>>();
        let coefficients = public.polynomial_from_roots(&roots).unwrap();
        assert_eq!(coefficients.len(), 100_001);
        assert_eq!(coefficients[100_000], 1);
        let source = public.encrypt(&coefficients, &mut rng).unwrap();
        assert_eq!(source.block_count(), 7);
        assert_eq!(secret.decrypt_coefficients(&source).unwrap(), coefficients);
        let f = Modulus::new(public.plaintext_modulus()).unwrap();
        for position in [1u64, 100_000, 100_001] {
            let value = coefficients
                .iter()
                .rev()
                .fold(0, |sum, &c| f.add(f.mul(sum, position), c));
            assert_eq!(value == 0, position <= 100_000);
            let (output, _) = public
                .evaluate_sample(&source, &[(position, 7)], 17, &mut rng)
                .unwrap();
            assert_eq!(
                secret.decrypt_sample(&public, &output).unwrap(),
                f.mul(119, value)
            );
        }
    }
    #[test]
    fn sampled_evaluation_uses_only_the_scalar_and_supports_100k_buckets() {
        let mut rng = rand09::rng();
        for profile in [RlweProfile::ProofTest, RlweProfile::Protocol100k] {
            let (public, secret) = generate_keys_with_profile(&mut rng, profile).unwrap();
            let monitor = RlwePublicContext::from_bytes(&public.to_bytes().unwrap()).unwrap();
            let buckets = if public.ring_dimension() == 16 {
                9
            } else {
                100_000
            };
            let config = BloomFilterConfig {
                bloom_filter_size: buckets,
                hash_count: 2,
                target_marked_count: 2,
            };
            let source = public
                .encrypt_bloom_positions(config, &[2, 5], &mut rng)
                .unwrap();
            let source = monitor.from_wire(&source.to_wire()).unwrap();
            assert!(public.evaluation_key.is_none());
            for (item, member) in [(2, true), (3, false)] {
                let weights =
                    super::super::protocol_hash::weights(Scalar::from(item as u64), config)
                        .unwrap();
                let mut all_zero = true;
                for weights in weights {
                    let (output, _) = monitor
                        .evaluate_sample(&source, &weights, 17, &mut rng)
                        .unwrap();
                    let decoded = secret.decrypt_sample(&public, &output).unwrap();
                    all_zero &= decoded == 0;
                    let t = public.plaintext_modulus();
                    let f = Modulus::new(t).unwrap();
                    let expected = weights.iter().fold(0, |sum, &(p, h)| {
                        f.add(sum, f.mul(h, f.mul(f.sub(p, 2), f.sub(p, 5))))
                    });
                    assert_eq!(decoded, f.mul(17, expected));
                }
                assert_eq!(all_zero, member);
            }
        }
    }
    #[test]
    fn sanitized_100k_membership_transport_and_parameter_budget() {
        let mut rng = rand09::rng();
        let started = std::time::Instant::now();
        let (public, secret) =
            generate_keys_with_profile(&mut rng, RlweProfile::CircuitPrivacy100k).unwrap();
        let budget = public.circuit_privacy_budget().unwrap();
        eprintln!(
            "privacy profile: keygen {:?}, evaluated bound {} bits, dropped divisor {} bits",
            started.elapsed(),
            budget.evaluated_noise_bound.bits(),
            budget.divisor.bits()
        );
        let encoded = public.to_bytes().unwrap();
        eprintln!("privacy profile public context: {} bytes", encoded.len());
        let monitor = RlwePublicContext::from_bytes(&encoded).unwrap();
        let config = BloomFilterConfig {
            bloom_filter_size: 100_000,
            hash_count: 2,
            target_marked_count: 2,
        };
        let source = public
            .encrypt_bloom_positions(config, &[2, 5], &mut rng)
            .unwrap();
        assert_eq!(source.block_count(), 7);
        let source = monitor.from_wire(&source.to_wire()).unwrap();
        for (item, member) in [(2, true), (3, false)] {
            let results = monitor
                .evaluate_membership_sanitized(&source, Scalar::from(item as u64), config, &mut rng)
                .unwrap();
            assert!(results
                .iter()
                .all(|r| r.ct[0].ctx().moduli().len() == RETAINED_LIMBS));
            let results = results
                .into_iter()
                .map(|r| {
                    let wire = r.to_wire();
                    assert!(wire.ciphertext.len() < 600_000);
                    public.sanitized_evaluation_from_wire(&wire).unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(
                secret.decrypt_sanitized_membership(&results).unwrap(),
                member
            );
            let mut wrong_key = results[0].to_wire();
            wrong_key.id[0] ^= 1;
            assert!(public.sanitized_evaluation_from_wire(&wrong_key).is_err());
        }
        let raw = monitor
            .evaluate_membership(&source, Scalar::from(2u64), config, &mut rng)
            .unwrap();
        let wrong_level = WireSanitizedRlweEvaluation {
            version: VERSION,
            id: public.id,
            ciphertext: raw[0].ct.to_bytes(),
        };
        assert!(public.sanitized_evaluation_from_wire(&wrong_level).is_err());
        assert!(public
            .evaluation_from_wire(&WireRlweEvaluation {
                version: VERSION,
                id: public.id,
                ciphertext: monitor
                    .evaluate_membership_sanitized(&source, Scalar::from(2u64), config, &mut rng)
                    .unwrap()[0]
                    .ct
                    .to_bytes()
            })
            .is_err());
    }
}

#[cfg(test)]
mod adaptive_packing_tests {
    use super::*;

    #[test]
    fn adaptive_32k_profile_transports_and_evaluates_one_packed_ciphertext() {
        let mut rng = rand09::rng();
        let config = BloomFilterConfig {
            bloom_filter_size: 20000,
            hash_count: 2,
            target_marked_count: 2,
        };
        let profile = RlweProfile::for_buckets(config.bloom_filter_size).unwrap();
        let (public, secret) = generate_keys_with_profile(&mut rng, profile).unwrap();
        assert_eq!(public.ring_dimension(), 32768);
        public.validate_protocol_for(config).unwrap();
        assert_ne!(public.parameters.moduli(), PROTOCOL_MODULI);
        let budget = public.circuit_privacy_budget().unwrap();
        assert_eq!(budget.statistical_bits, 128);
        let roots = [2, 5];
        let source = public
            .encrypt_bloom_positions(config, &roots, &mut rng)
            .unwrap();
        assert_eq!(source.coefficient_count(), 20001);
        assert_eq!(source.block_count(), 1);
        let source_wire = source.to_wire();
        assert!(source_wire.blocks.iter().all(|b| b.len() < MAX_BLOCK_BYTES));
        let monitor = RlwePublicContext::from_bytes(&public.to_bytes().unwrap()).unwrap();
        monitor.validate_protocol_for(config).unwrap();
        let source = monitor.from_wire(&source_wire).unwrap();
        let field = Modulus::new(PROTOCOL_PLAINTEXT_MODULUS).unwrap();
        for item in [2u64, 3] {
            let hashes = super::super::protocol_hash::weights(Scalar::from(item), config).unwrap();
            let hashes = super::super::extension::mask_hashes(&hashes, [7, 11, 13]).unwrap();
            let mut decoded = Vec::new();
            for row in &hashes {
                let expected = row.iter().fold(0, |sum, &(position, h)| {
                    let p = roots
                        .iter()
                        .fold(1, |p, &root| field.mul(p, field.sub(position, root)));
                    field.add(sum, field.mul(h, p))
                });
                let (out, _) = monitor.evaluate_sample(&source, row, 1, &mut rng).unwrap();
                let actual = secret.decrypt_sample(&public, &out).unwrap();
                assert_eq!(actual, expected);
                decoded.push(actual);
            }
            assert_eq!(decoded.iter().all(|&v| v == 0), item == 2);
        }
        let smaller = BloomFilterConfig {
            bloom_filter_size: 1000,
            ..config
        };
        assert!(monitor.validate_protocol_for(smaller).is_err());
        let mut wrong = public.wire.clone();
        wrong.ciphertext_moduli = PROTOCOL_MODULI.to_vec();
        assert!(RlwePublicContext::from_bytes(
            &wire_options(MAX_PUBLIC_CONTEXT_BYTES as u64)
                .serialize(&wrong)
                .unwrap()
        )
        .is_err());
    }

    #[test]
    fn production_profiles_reject_small_insecure_and_unsupported_dimensions() {
        for ring_dimension in [16, 1024, 2048, 4096, 8192, 65536] {
            assert!(generate_keys_with_profile(
                &mut rand09::rng(),
                RlweProfile::ProtocolSized { ring_dimension }
            )
            .is_err());
        }
    }
}
