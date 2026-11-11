//! PKC 2019 proofs of native RLWE linear relations, linked through blinded
//! Pedersen openings to generic Bulletproof item/hash/weight constraints.
use super::{
    bloom::{scalar_positions_checked, BloomFilterConfig},
    constraints::constrain_positions,
    field_constraints::{range, FieldVariable},
    proof_values::{Assignments, Bound},
    protocol_hash,
    rlwe::{
        PackedRlweCiphertext, RlwePublicContext, SampleEvaluationWitness,
        WireSampledRlweEvaluation, PROTOCOL_PLAINTEXT_MODULUS,
    },
};
use bulletproofs::{
    r1cs::{
        ConstraintSystem, LinearCombination as LC, Prover, R1CSError, R1CSProof,
        RandomizableConstraintSystem, RandomizedConstraintSystem, Variable, Verifier,
    },
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};
use fhe_math::zq::Modulus;
use merlin::Transcript;
use num_bigint::{BigInt, BigUint};
use num_traits::{ToPrimitive, Zero};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ops::Range,
    sync::{Arc, Mutex, OnceLock},
};
fn error(e: impl std::fmt::Display) -> R1CSError {
    R1CSError::GadgetError {
        description: e.to_string(),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireEvaluationProof {
    pub commitments: Vec<[u8; 32]>,
    pub ring: Vec<super::pkc_evaluation::WireRingProof>,
    pub arithmetic: Vec<u8>,
}
#[derive(Clone)]
pub(crate) struct RepLayout {
    pub w: Range<usize>,
    pub rec: Range<usize>,
    pub u: Range<usize>,
    pub ra: Range<usize>,
    pub rb: Range<usize>,
}
#[derive(Clone)]
pub(crate) struct Layout {
    pub bounds: Vec<Bound>,
    pub reps: Vec<RepLayout>,
    pub n: usize,
    pub count: usize,
    pub limbs: usize,
}
impl Layout {
    fn new(public: &RlwePublicContext, config: BloomFilterConfig) -> Result<Self, String> {
        protocol_hash::validate(config)?;
        public.validate_protocol_for(config)?;
        let n = public.ring_dimension();
        let count = config.bloom_filter_size + 1;
        let divisor: BigUint = public.parameters.moduli()[2..]
            .iter()
            .map(|&q| BigUint::from(q))
            .product();
        let limbs = (divisor.bits() as usize).div_ceil(32);
        super::pkc_evaluation::validate_decode_bound(
            n,
            count,
            limbs,
            public.plaintext_modulus(),
            public.parameters.moduli(),
        )?;
        let mut bounds = vec![Bound::None];
        let mut reps = Vec::new();
        let mut add = |kind, count| {
            let start = bounds.len();
            bounds.resize(start + count, kind);
            start..start + count
        };
        for _ in 0..protocol_hash::REPETITIONS {
            reps.push(RepLayout {
                w: add(Bound::Signed(56), count),
                rec: add(Bound::Signed(61), count),
                u: add(Bound::Signed(8), n),
                ra: add(Bound::Signed(32), limbs * n),
                rb: add(Bound::Signed(32), limbs),
            });
        }
        Ok(Self {
            bounds,
            reps,
            n,
            count,
            limbs,
        })
    }
}
pub(crate) struct PublicData {
    pub source0: Vec<Vec<Vec<u64>>>,
    pub source1: Vec<Vec<Vec<u64>>>,
    pub pk0: Vec<Vec<u64>>,
    pub pk1: Vec<Vec<u64>>,
    pub moduli: Vec<u64>,
    pub divisor: BigUint,
    pub outputs: Vec<WireSampledRlweEvaluation>,
}
impl PublicData {
    fn new(
        public: &RlwePublicContext,
        source: &PackedRlweCiphertext,
        config: BloomFilterConfig,
        outputs: &[WireSampledRlweEvaluation],
    ) -> Result<Self, String> {
        if source.coefficient_count() != config.bloom_filter_size + 1
            || outputs.len() != protocol_hash::REPETITIONS
        {
            return Err("evaluation dimensions mismatch".into());
        }
        public.from_wire(&source.to_wire())?;
        for output in outputs {
            public.validate_sample(output)?;
        }
        let pk = public.public_key_ciphertext()?;
        Ok(Self {
            source0: source
                .blocks
                .iter()
                .map(|ct| RlwePublicContext::coefficient_rows(ct, 0))
                .collect(),
            source1: source
                .blocks
                .iter()
                .map(|ct| RlwePublicContext::coefficient_rows(ct, 1))
                .collect(),
            pk0: RlwePublicContext::coefficient_rows(&pk, 0),
            pk1: RlwePublicContext::coefficient_rows(&pk, 1),
            moduli: public.parameters.moduli().to_vec(),
            divisor: public.parameters.moduli()[2..]
                .iter()
                .map(|&q| BigUint::from(q))
                .product(),
            outputs: outputs.to_vec(),
        })
    }
}
fn characteristic(positions: &[u64]) -> Vec<u64> {
    let f = Modulus::new(PROTOCOL_PLAINTEXT_MODULUS).unwrap();
    let mut c = vec![1];
    for &position in positions {
        let mut next = vec![0; c.len() + 1];
        for (j, &a) in c.iter().enumerate() {
            next[j] = f.add(next[j], a);
            next[j + 1] = f.sub(next[j + 1], f.mul(position, a));
        }
        c = next;
    }
    c
}
/// Absorb fresh e into the rounding residual R-e and encode balanced base-2^32
/// digits. The proof needs bounded residuals, not the exact sanitizer's floor.
fn residual(
    digits: impl Iterator<Item = u64>,
    error: i64,
    limbs: usize,
) -> Result<Vec<i64>, String> {
    let mut value =
        BigInt::from(BigUint::new(digits.map(|v| v as u32).collect())) - BigInt::from(error);
    let base = BigInt::from(1u64 << 32);
    let half = BigInt::from(1u64 << 31);
    let mut result = Vec::with_capacity(limbs);
    for _ in 0..limbs {
        let mut digit = &value % &base;
        if digit < -&half {
            digit += &base;
        }
        if digit >= half {
            digit -= &base;
        }
        value = (value - &digit) / &base;
        result.push(digit.to_i64().ok_or("residual limb overflow")?);
    }
    if !value.is_zero() {
        return Err("residual exceeds proof budget".into());
    }
    Ok(result)
}
fn fill<R: RngCore + CryptoRng>(
    rng: &mut R,
    layout: &Layout,
    _data: &PublicData,
    item: Scalar,
    positions: &[u64],
    witnesses: &[SampleEvaluationWitness],
) -> Result<Assignments, String> {
    if witnesses.len() != layout.reps.len() {
        return Err("evaluation witness repetition count mismatch".into());
    }
    let mut values = Assignments::new();
    values.scalar(rng, item);
    let c = characteristic(positions);
    let t = BigInt::from(PROTOCOL_PLAINTEXT_MODULUS);
    for (l, witness) in layout.reps.iter().zip(witnesses) {
        let n = layout.n;
        if witness.weights.len() != layout.count
            || witness.u.len() != n
            || witness.e1.len() != n
            || witness.remainder_a.len() != layout.limbs
            || witness.remainder_a.iter().any(|p| p.len() != n)
            || witness.remainder_b.len() != layout.limbs
        {
            return Err("invalid private evaluation witness dimensions".into());
        }
        for &v in &witness.weights {
            values.signed(rng, v, 56)?;
        }
        let e = witness
            .weights
            .iter()
            .enumerate()
            .map(|(j, &v)| BigInt::from(if j % n == 0 { v } else { -v }))
            .collect::<Vec<_>>();
        for j in 0..layout.count {
            let q = if j < positions.len() {
                0
            } else {
                let value = c
                    .iter()
                    .enumerate()
                    .fold(BigInt::zero(), |s, (i, &c)| s + BigInt::from(c) * &e[j - i]);
                if &value % &t != BigInt::zero() {
                    return Err("native coefficient recurrence is inconsistent".into());
                }
                (value / &t)
                    .to_i64()
                    .ok_or("recurrence quotient overflow")?
            };
            values.signed(rng, q, 61)?;
        }
        for &v in &witness.u {
            values.signed(rng, v, 8)?;
        }
        let columns = (0..n)
            .map(|j| {
                residual(
                    witness.remainder_a.iter().map(|r| r[j]),
                    witness.e1[j],
                    layout.limbs,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        for limb in 0..layout.limbs {
            for column in &columns {
                values.signed(rng, column[limb], 32)?;
            }
        }
        for v in residual(
            witness.remainder_b.iter().copied(),
            witness.e0,
            layout.limbs,
        )? {
            values.signed(rng, v, 32)?;
        }
        if values.values.len() != l.rb.end {
            return Err("internal evaluation layout mismatch".into());
        }
    }
    Ok(values)
}
fn constant<CS: ConstraintSystem>(
    cs: &mut CS,
    value: u64,
    proving: bool,
) -> Result<FieldVariable, R1CSError> {
    let variable =
        FieldVariable::allocate(cs, PROTOCOL_PLAINTEXT_MODULUS, proving.then_some(value))?;
    cs.constrain(LC::from(variable.variable()) - Scalar::from(value));
    Ok(variable)
}
fn eval(coefficients: &[LC], alpha: Scalar) -> LC {
    // Horner evaluation of symbolic LCs repeatedly rescales every accumulated
    // term, taking quadratic work. Scale each sparse coefficient only once.
    let mut result = LC::default();
    let mut power = Scalar::one();
    for coefficient in coefficients {
        result = result + power * coefficient.clone();
        power *= alpha;
    }
    result
}
fn constrain_frontend<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    vars: &[Variable],
    layout: &Layout,
    config: BloomFilterConfig,
    assignment: Option<&Assignments>,
    witnesses: Option<&[SampleEvaluationWitness]>,
) -> Result<(), R1CSError> {
    constrain_frontend_traced(cs, vars, layout, config, assignment, witnesses, |_, _| {})
}

fn constrain_frontend_traced<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    vars: &[Variable],
    layout: &Layout,
    config: BloomFilterConfig,
    assignment: Option<&Assignments>,
    witnesses: Option<&[SampleEvaluationWitness]>,
    mut trace: impl FnMut(&'static str, usize),
) -> Result<(), R1CSError> {
    let proving = assignment.is_some();
    let y = assignment.map(|a| a.values[0]);
    let positions_assignment = y
        .map(|y| scalar_positions_checked(y, config))
        .transpose()
        .map_err(error)?;
    let positions = (0..config.hash_count)
        .map(|j| cs.allocate(positions_assignment.as_ref().map(|p| p[j])))
        .collect::<Result<Vec<_>, _>>()?;
    constrain_positions(cs, vars[0], &positions, config, y)?;
    trace("positions", cs.metrics().multipliers);
    let hashes = protocol_hash::constrain(cs, vars[0], &positions, config, y)?;
    trace("hashes", cs.metrics().multipliers);
    let t = PROTOCOL_PLAINTEXT_MODULUS;
    let positions = positions
        .into_iter()
        .enumerate()
        .map(|(j, p)| {
            FieldVariable::constrain(
                cs,
                p,
                t,
                positions_assignment
                    .as_ref()
                    .map(|p| super::bloom::scalar_to_usize(p[j]) as u64),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let one = constant(cs, 1, proving)?;
    let zero = constant(cs, 0, proving)?;
    let mut characteristic = vec![one.clone()];
    for position in &positions {
        let mut next = vec![one.clone()];
        for j in 1..=characteristic.len() {
            let product = position.multiply(cs, &characteristic[j - 1])?;
            next.push(
                characteristic
                    .get(j)
                    .unwrap_or(&zero)
                    .subtract(cs, &product)?,
            );
        }
        characteristic = next;
    }
    trace("characteristic", cs.metrics().multipliers);
    let initial = config.hash_count.min(layout.count);
    let mut powers = vec![vec![one.clone()]; config.hash_count];
    for (i, position) in positions.iter().enumerate() {
        for j in 1..initial {
            let next = powers[i][j - 1].multiply(cs, position)?;
            powers[i].push(next);
        }
    }
    trace("powers", cs.metrics().multipliers);
    let mask_assignment = if let Some(witnesses) = witnesses {
        let mask = witnesses
            .first()
            .and_then(|w| w.logical_mask)
            .ok_or_else(|| error("missing common extension-field mask"))?;
        if witnesses
            .iter()
            .any(|w| w.logical_mask != Some(mask) || w.mask != 1)
        {
            return Err(error("inconsistent extension-field mask witnesses"));
        }
        Some(mask)
    } else {
        None
    };
    let masks = (0..3)
        .map(|i| FieldVariable::allocate(cs, t, mask_assignment.map(|r| r[i])))
        .collect::<Result<Vec<_>, _>>()?;
    // Canonical coordinates are nonnegative and 3*t^2 < l. Their sum of
    // squares is zero in F_l iff the logical extension-field mask is zero.
    let mut norm = LC::default();
    for mask in &masks {
        norm = norm
            + cs.multiply(mask.variable().into(), mask.variable().into())
                .2;
    }
    let norm_assignment = mask_assignment.map(|r| {
        r.into_iter().fold(Scalar::zero(), |sum, r| {
            let r = Scalar::from(r);
            sum + r * r
        })
    });
    let inverse = cs.allocate(norm_assignment.map(|v| v.invert()))?;
    let unit = cs.multiply(norm, inverse.into()).2;
    cs.constrain(LC::from(unit) - Scalar::one());
    let mut masked = vec![Vec::new(); 3];
    for i in 0..config.hash_count {
        let h = hashes.iter().map(|row| row[i].clone()).collect::<Vec<_>>();
        let product = super::extension::constrain_product(cs, &masks, &h)?;
        for (row, value) in masked.iter_mut().zip(product) {
            row.push(value);
        }
    }
    trace("mask", cs.metrics().multipliers);
    for (rep, l) in layout.reps.iter().enumerate() {
        let sequence = (0..layout.count)
            .map(|j| {
                if j % layout.n == 0 {
                    LC::from(vars[l.w.start + j])
                } else {
                    -LC::from(vars[l.w.start + j])
                }
            })
            .collect::<Vec<_>>();
        for j in 0..initial {
            let column = powers.iter().map(|row| row[j].clone()).collect::<Vec<_>>();
            let sum = FieldVariable::sum_products(cs, &masked[rep], &column)?;
            let quotient = assignment.map(|a| {
                let w = a.encoded[l.w.start + j] as i128 - (1i128 << 55);
                let e = if j % layout.n == 0 { w } else { -w };
                let expected = sum.assignment().unwrap() as i128;
                ((e - expected) / (t as i128) + 512) as u64
            });
            let q = cs.allocate(quotient.map(Scalar::from))?;
            range(cs, q.into(), quotient, 10)?;
            cs.constrain(
                sequence[j].clone()
                    - sum.variable()
                    - Scalar::from(t) * (LC::from(q) - Scalar::from(512u64)),
            );
        }
        trace("initial moments", cs.metrics().multipliers);
        let coefficient = |cs: &mut CS, j: usize| {
            let mut value = LC::default();
            for (i, c) in characteristic.iter().enumerate() {
                if let Some(e) = j.checked_sub(i).and_then(|i| sequence.get(i)) {
                    value = value + cs.multiply(c.variable().into(), e.clone()).2;
                }
            }
            value
        };
        let low = (0..initial).map(|j| coefficient(cs, j)).collect::<Vec<_>>();
        let high = (layout.count..layout.count + config.hash_count)
            .map(|j| coefficient(cs, j))
            .collect::<Vec<_>>();
        trace("recurrence boundaries", cs.metrics().multipliers);
        let quotients = (0..layout.count)
            .map(|j| LC::from(vars[l.rec.start + j]))
            .collect::<Vec<_>>();
        let characteristic = characteristic
            .iter()
            .map(|c| LC::from(c.variable()))
            .collect::<Vec<_>>();
        let count = layout.count;
        cs.specify_randomized_constraints(move |cs| {
            let alpha = cs.challenge_scalar(b"bf-weight-integer-recurrence-v1");
            let product = cs
                .multiply(eval(&characteristic, alpha), eval(&sequence, alpha))
                .2;
            let mut shift = Scalar::one();
            for _ in 0..count {
                shift *= alpha;
            }
            cs.constrain(
                LC::from(product)
                    - eval(&low, alpha)
                    - shift * eval(&high, alpha)
                    - Scalar::from(t) * eval(&quotients, alpha),
            );
            Ok(())
        })?;
    }
    Ok(())
}

fn transcript(context: &[u8; 32], config: BloomFilterConfig) -> Transcript {
    let mut t = Transcript::new(b"bf-pkc-rlwe-evaluation-v3");
    t.append_message(b"context", context);
    t.append_u64(b"buckets", config.bloom_filter_size as u64);
    t.append_u64(b"hashes", config.hash_count as u64);
    t.append_u64(b"density", config.target_marked_count as u64);
    t
}
fn arithmetic_capacity(gates: usize, config: BloomFilterConfig) -> Result<usize, String> {
    protocol_hash::validate(config)?;
    let deferred = protocol_hash::REPETITIONS + 16;
    let capacity = gates
        .checked_add(deferred)
        .and_then(usize::checked_next_power_of_two)
        .ok_or("proof capacity overflow")?;
    if capacity > (1 << 24) {
        return Err("arithmetic proof exceeds implementation capacity".into());
    }
    Ok(capacity)
}
fn generators(gates: usize, config: BloomFilterConfig) -> Result<Arc<BulletproofGens>, String> {
    let capacity = arithmetic_capacity(gates, config)?;
    static CACHE: OnceLock<Mutex<BTreeMap<usize, Arc<BulletproofGens>>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| "proof generator cache poisoned")?;
    if let Some((_, g)) = cache.range(capacity..).next() {
        return Ok(g.clone());
    }
    let g = Arc::new(BulletproofGens::new(capacity, 1));
    cache.insert(capacity, g.clone());
    Ok(g)
}

pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    context: &[u8; 32],
    public: &RlwePublicContext,
    source: &PackedRlweCiphertext,
    config: BloomFilterConfig,
    item: Scalar,
    outputs: &[WireSampledRlweEvaluation],
    witnesses: &[SampleEvaluationWitness],
) -> Result<(WireEvaluationProof, Scalar), String> {
    #[cfg(test)]
    let started = std::time::Instant::now();
    let layout = Arc::new(Layout::new(public, config)?);
    let data = Arc::new(PublicData::new(public, source, config, outputs)?);
    let positions = scalar_positions_checked(item, config)?
        .into_iter()
        .map(|p| super::bloom::scalar_to_usize(p) as u64)
        .collect::<Vec<_>>();
    let values = fill(rng, &layout, &data, item, &positions, witnesses)?;
    #[cfg(test)]
    eprintln!(
        "RLWE proof: {} shared values; witness preparation {:.3}s",
        layout.bounds.len(),
        started.elapsed().as_secs_f64()
    );
    let pc = PedersenGens::default();
    let mut t = transcript(context, config);
    let mut p = Prover::new(&pc, &mut t);
    let mut commitments = Vec::with_capacity(layout.bounds.len());
    let mut variables = Vec::with_capacity(layout.bounds.len());
    for (&value, &blind) in values.values.iter().zip(&values.blinds) {
        let (c, v) = p.commit(value, blind);
        commitments.push(c.to_bytes());
        variables.push(v);
    }
    #[cfg(test)]
    eprintln!(
        "RLWE proof: commitments ready at {:.3}s",
        started.elapsed().as_secs_f64()
    );
    constrain_frontend(
        &mut p,
        &variables,
        &layout,
        config,
        Some(&values),
        Some(witnesses),
    )
    .map_err(|e| e.to_string())?;
    let g = generators(p.metrics().multipliers, config)?;
    let arithmetic = p.prove(&g).map_err(|e| e.to_string())?.to_bytes();
    #[cfg(test)]
    eprintln!(
        "RLWE proof: arithmetic argument ready at {:.3}s",
        started.elapsed().as_secs_f64()
    );
    let ring = super::pkc_evaluation::prove(
        rng,
        context,
        &pc,
        &layout,
        &data,
        &values,
        &commitments,
        &arithmetic,
    )?;
    #[cfg(test)]
    eprintln!(
        "RLWE proof: PKC relations and commitment links ready at {:.3}s",
        started.elapsed().as_secs_f64()
    );
    Ok((
        WireEvaluationProof {
            commitments,
            ring,
            arithmetic,
        },
        values.blinds[0],
    ))
}

pub(crate) fn verify(
    context: &[u8; 32],
    public: &RlwePublicContext,
    source: &PackedRlweCiphertext,
    config: BloomFilterConfig,
    outputs: &[WireSampledRlweEvaluation],
    proof: &WireEvaluationProof,
) -> Result<CompressedRistretto, String> {
    let layout = Arc::new(Layout::new(public, config)?);
    if proof.commitments.len() != layout.bounds.len() || proof.arithmetic.len() > 32768 {
        return Err("malformed RLWE evaluation proof dimensions".into());
    }
    let data = Arc::new(PublicData::new(public, source, config, outputs)?);
    let pc = PedersenGens::default();
    super::pkc_evaluation::verify(
        context,
        &pc,
        &layout,
        &data,
        &proof.commitments,
        &proof.arithmetic,
        &proof.ring,
    )?;
    let mut t = transcript(context, config);
    let mut v = Verifier::new(&mut t);
    let variables = proof
        .commitments
        .iter()
        .map(|&c| v.commit(CompressedRistretto(c)))
        .collect::<Vec<_>>();
    constrain_frontend(&mut v, &variables, &layout, config, None, None)
        .map_err(|e| e.to_string())?;
    let g = generators(v.metrics().multipliers, config)?;
    v.verify(
        &R1CSProof::from_bytes(&proof.arithmetic).map_err(|e| e.to_string())?,
        &pc,
        &g,
    )
    .map_err(|e| e.to_string())?;
    Ok(CompressedRistretto(proof.commitments[0]))
}

#[cfg(test)]
mod tests {
    use super::super::rlwe::{generate_keys_with_profile, RlweProfile};
    use super::*;
    #[test]
    fn complete_evaluation_rejects_ciphertext_tampering_and_a_genuine_wrong_zero() {
        let (public, secret) =
            generate_keys_with_profile(&mut rand09::rng(), RlweProfile::ProofTest).unwrap();
        let config = BloomFilterConfig {
            bloom_filter_size: 9,
            hash_count: 2,
            target_marked_count: 2,
        };
        let source = public
            .encrypt_bloom_positions(config, &[2, 5], &mut rand09::rng())
            .unwrap();
        let context = [1u8; 32];
        let item = Scalar::from(3u64);
        for (logical_mask, forged) in [
            ([17, 18, 19], false),
            ([0, 1, 0], false),
            ([17, 18, 19], true),
            ([0, 0, 0], true),
        ] {
            let raw = protocol_hash::weights(item, config).unwrap();
            let mut weights = if logical_mask == [0; 3] {
                raw
            } else {
                super::super::extension::mask_hashes(&raw, logical_mask).unwrap()
            };
            if forged {
                for weights in &mut weights {
                    for (_, h) in weights {
                        *h = 0;
                    }
                }
            }
            let mut outputs = Vec::new();
            let mut witnesses = Vec::new();
            for weights in &weights {
                let (out, mut w) = public
                    .evaluate_sample(&source, weights, 1, &mut rand09::rng())
                    .unwrap();
                w.logical_mask = Some(logical_mask);
                outputs.push(out);
                witnesses.push(w);
            }
            assert_eq!(
                outputs
                    .iter()
                    .all(|out| secret.decrypt_sample(&public, out).unwrap() == 0),
                forged
            );
            let (proof, blind) = prove(
                &mut rand::rngs::OsRng,
                &context,
                &public,
                &source,
                config,
                item,
                &outputs,
                &witnesses,
            )
            .unwrap();
            let verified = verify(&context, &public, &source, config, &outputs, &proof);
            assert_eq!(verified.is_ok(), !forged, "{verified:?}");
            if forged {
                continue;
            }
            assert_eq!(
                verified.unwrap(),
                PedersenGens::default().commit(item, blind).compress()
            );
            assert!(verify(&[2; 32], &public, &source, config, &outputs, &proof).is_err());
            let mut changed = outputs.clone();
            changed[0].b[0] = (changed[0].b[0] + 1) % public.parameters.moduli()[0];
            assert!(verify(&context, &public, &source, config, &changed, &proof).is_err());
            let mut changed = outputs.clone();
            changed[0].a[0][3] = (changed[0].a[0][3] + 1) % public.parameters.moduli()[0];
            assert!(verify(&context, &public, &source, config, &changed, &proof).is_err());
            assert!(verify(&context, &public, &source, config, &outputs[..2], &proof).is_err());
            let altered_source = public
                .encrypt_bloom_positions(config, &[3, 7], &mut rand09::rng())
                .unwrap();
            assert!(verify(&context, &public, &altered_source, config, &outputs, &proof).is_err());
        }
    }
    #[test]
    fn plaintext_relation_accepts_bounded_rounding_without_exact_floor() {
        let (public, secret) =
            generate_keys_with_profile(&mut rand09::rng(), RlweProfile::ProofTest).unwrap();
        let config = BloomFilterConfig {
            bloom_filter_size: 3,
            hash_count: 1,
            target_marked_count: 1,
        };
        let source = public
            .encrypt_bloom_positions(config, &[3], &mut rand09::rng())
            .unwrap();
        let item = Scalar::one();
        let logical_mask = [7, 11, 13];
        let hashes = super::super::extension::mask_hashes(
            &protocol_hash::weights(item, config).unwrap(),
            logical_mask,
        )
        .unwrap();
        let mut outputs = Vec::new();
        let mut witnesses = Vec::new();
        for h in &hashes {
            let (out, mut witness) = public
                .evaluate_sample(&source, h, 1, &mut rand09::rng())
                .unwrap();
            witness.logical_mask = Some(logical_mask);
            outputs.push(out);
            witnesses.push(witness);
        }
        let expected = secret.decrypt_sample(&public, &outputs[0]).unwrap();
        // Subtracting one from BOTH retained residues changes the floor result
        // but preserves its decoded plaintext. R' = R + D satisfies the new
        // relation; an exact [0,D) remainder check would incorrectly exclude it.
        for prime in 0..2 {
            let q = public.parameters.moduli()[prime];
            outputs[0].b[prime] = (outputs[0].b[prime] + q - 1) % q;
        }
        assert_eq!(
            secret.decrypt_sample(&public, &outputs[0]).unwrap(),
            expected
        );
        let d: BigUint = public.parameters.moduli()[2..]
            .iter()
            .map(|&q| BigUint::from(q))
            .product();
        let r = BigUint::new(witnesses[0].remainder_b.iter().map(|&v| v as u32).collect());
        let digits = (r + &d).to_u32_digits();
        witnesses[0].remainder_b = (0..8)
            .map(|j| digits.get(j).copied().unwrap_or(0) as u64)
            .collect();
        let context = [43; 32];
        let (proof, _) = prove(
            &mut rand::rngs::OsRng,
            &context,
            &public,
            &source,
            config,
            item,
            &outputs,
            &witnesses,
        )
        .unwrap();
        verify(&context, &public, &source, config, &outputs, &proof).unwrap();
    }
    /// Counts the real active circuits without generating expensive proofs.
    #[test]
    #[ignore = "proof cost audit; assembles the production circuit without proving"]
    fn audit_proof_costs() {
        let (public, _) =
            generate_keys_with_profile(&mut rand09::rng(), RlweProfile::Protocol100k).unwrap();
        for buckets in [1000, 100_000] {
            let config = BloomFilterConfig {
                bloom_filter_size: buckets,
                hash_count: 20,
                target_marked_count: buckets / 2,
            };
            let layout = Layout::new(&public, config).unwrap();
            let started = std::time::Instant::now();
            let roots = (1..=config.target_marked_count as u64).collect::<Vec<_>>();
            let source = public
                .encrypt_bloom_positions(config, &roots, &mut rand09::rng())
                .unwrap();
            eprintln!("AUDIT m={buckets}: native source construction+encryption {:.3}s, blocks={}, bytes={}, raw ElGamal bytes={}", started.elapsed().as_secs_f64(), source.block_count(), bincode::serialized_size(&source.to_wire()).unwrap(), 64 * (buckets + 1));
            let mut transcript = Transcript::new(b"bf-cost-audit-only");
            let mut verifier = Verifier::new(&mut transcript);
            let variables = layout
                .bounds
                .iter()
                .map(|_| verifier.commit(CompressedRistretto([0; 32])))
                .collect::<Vec<_>>();
            let mut previous = 0;
            constrain_frontend_traced(
                &mut verifier,
                &variables,
                &layout,
                config,
                None,
                None,
                |stage, total| {
                    eprintln!(
                        "AUDIT m={buckets}: {stage}: {} multipliers",
                        total - previous
                    );
                    previous = total;
                },
            )
            .unwrap();
            eprintln!("AUDIT m={buckets}: shared commitments={}, bytes={}, arithmetic multipliers={}, generator capacity={}",layout.bounds.len(),layout.bounds.len()*32,verifier.metrics().multipliers,arithmetic_capacity(verifier.metrics().multipliers,config).unwrap());
            super::super::pkc_evaluation::audit_costs(&layout);
        }
    }

    #[test]
    fn generator_capacity_includes_deferred_recurrences() {
        let config = BloomFilterConfig {
            bloom_filter_size: 100_000,
            hash_count: 64,
            target_marked_count: 50_000,
        };
        // The sparse frontend leaves only three recurrence multipliers for
        // the randomized phase, with a small allocation margin.
        assert_eq!(arithmetic_capacity(65_520, config).unwrap(), 131_072);
    }
    #[test]
    fn manifest_supports_adaptive_dimensions_without_unbounded_frames() {
        for buckets in [32767, 100000] {
            let (public, _) = generate_keys_with_profile(
                &mut rand09::rng(),
                RlweProfile::for_buckets(buckets).unwrap(),
            )
            .unwrap();
            let config = BloomFilterConfig {
                bloom_filter_size: buckets,
                hash_count: 20,
                target_marked_count: buckets / 2,
            };
            let layout = Layout::new(&public, config).unwrap();
            let max_accumulator_bytes = 192 * (100000 + 1) + 4096;
            assert!(layout.bounds.len() * 35 + 1_000_000 + max_accumulator_bytes < (128 << 20));
            assert_eq!(layout.reps[0].w.len(), buckets + 1);
            if buckets == 100000 {
                assert_eq!(layout.bounds.len(), 1_042_399);
            }
        }
    }
}
