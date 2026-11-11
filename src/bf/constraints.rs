//! Arithmetic constraints linking the private monitor item to its entire Bloom
//! vector. This is not a proof of the RLWE evaluation or SHA-256 computation.
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, R1CSError, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable,
};
use curve25519_dalek_ng::scalar::Scalar;

use super::bloom::{hash_params, usable_input_span, BloomFilterConfig};

fn gadget_error(description: impl Into<String>) -> R1CSError {
    R1CSError::GadgetError {
        description: description.into(),
    }
}

fn boolean<CS: ConstraintSystem>(
    cs: &mut CS,
    assignment: Option<Scalar>,
) -> Result<Variable, R1CSError> {
    let (a, b, product) = cs.allocate_multiplier(assignment.map(|v| (v, Scalar::one() - v)))?;
    cs.constrain(LinearCombination::from(product));
    cs.constrain(LinearCombination::from(a) + b - Scalar::one());
    Ok(a)
}

fn range_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    value: LinearCombination,
    assignment: Option<Scalar>,
    bits: usize,
) -> Result<Vec<Variable>, R1CSError> {
    let bytes = assignment.map(|s| s.to_bytes());
    let mut sum = LinearCombination::default();
    let mut variables = Vec::with_capacity(bits);
    for i in 0..bits {
        let bit = boolean(
            cs,
            bytes.map(|b| Scalar::from(((b[i / 8] >> (i % 8)) & 1) as u64)),
        )?;
        sum = sum + Scalar::from(1u64 << i) * LinearCombination::from(bit);
        variables.push(bit);
    }
    cs.constrain(sum - value);
    Ok(variables)
}

pub(crate) fn bounded_input_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    y: Variable,
    assignment: Option<Scalar>,
    config: BloomFilterConfig,
) -> Result<(), R1CSError> {
    config.validate().map_err(gadget_error)?;
    let upper = usable_input_span(config);
    let bits = (usize::BITS - upper.saturating_sub(1).leading_zeros()) as usize;
    let upper = Scalar::from(upper as u64);
    range_gadget(
        cs,
        LinearCombination::from(y) - Scalar::one(),
        assignment.map(|y| y - Scalar::one()),
        bits,
    )?;
    range_gadget(
        cs,
        LinearCombination::from(upper) - y,
        assignment.map(|y| upper - y),
        bits,
    )?;
    Ok(())
}

/// The sparse Bloom set is determined by these affine positions. No separate
/// bit-vector witness or fingerprint is needed when only the positions are used.
#[cfg(feature = "experimental-rlwe")]
pub(crate) fn constrain_positions<CS: ConstraintSystem>(
    cs: &mut CS,
    item: Variable,
    positions: &[Variable],
    config: BloomFilterConfig,
    assignment: Option<Scalar>,
) -> Result<(), R1CSError> {
    if positions.len() != config.hash_count {
        return Err(gadget_error("incorrect Bloom position count"));
    }
    bounded_input_gadget(cs, item, assignment, config)?;
    for (j, &position) in positions.iter().enumerate() {
        let (slope, intercept) = hash_params(j);
        cs.constrain(
            LinearCombination::from(position) - slope * LinearCombination::from(item) - intercept,
        );
    }
    Ok(())
}

/// Multipliers added by the full bit vector, bounded positions and fingerprint,
/// excluding the input bounds, which the BF capacity planner already counts.
#[cfg(test)]
pub(crate) fn bloom_multipliers(config: BloomFilterConfig) -> usize {
    let bits = (usize::BITS - config.bloom_filter_size.leading_zeros()) as usize;
    config.bloom_filter_size.saturating_add(
        config
            .hash_count
            .saturating_mul(bits.saturating_mul(2).saturating_sub(1)),
    )
}

/// The returned variables must be reused by subsequent hashing/weight gadgets;
/// proving consistency of an unrelated witness vector would not link proofs.
pub struct BloomVariables {
    /// Bucket 1 is bits[0], matching the canonical little-endian byte encoding.
    pub bits: Vec<Variable>,
    /// The same bounded position bits used by the randomized identity check.
    pub position_bits: Vec<Vec<Variable>>,
    pub(crate) config: BloomFilterConfig,
}

impl BloomVariables {
    /// The public configuration under which these variables were constrained.
    pub fn config(&self) -> BloomFilterConfig {
        self.config
    }

    pub fn position_bytes(&self) -> Vec<Vec<LinearCombination>> {
        self.position_bits
            .iter()
            .map(|bits| {
                (0..8)
                    .map(|byte| {
                        bits.iter().skip(byte * 8).take(8).enumerate().fold(
                            LinearCombination::default(),
                            |sum, (i, &bit)| {
                                sum + Scalar::from(1u64 << i) * LinearCombination::from(bit)
                            },
                        )
                    })
                    .collect()
            })
            .collect()
    }
    /// Reuse these exact linear combinations in the hashing gadget or in
    /// equality constraints to external byte commitments. The final byte's
    /// unused high bits are constants zero, not unconstrained witnesses.
    pub fn bytes(&self) -> Vec<LinearCombination> {
        self.bits
            .chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(LinearCombination::default(), |sum, (i, &bit)| {
                        sum + Scalar::from(1u64 << i) * LinearCombination::from(bit)
                    })
            })
            .collect()
    }
}

/// Enforces the existing affine Bloom hashes p_j=(j+1)y+j, a bounded integer y,
/// Boolean Bloom bits, exactly k marked buckets, and equality of that bit vector
/// to the set of p_j. Bounded positive y makes these positions distinct.
///
/// A randomized polynomial identity avoids k full scans of a large bit vector:
/// sum_i bit_i*a^(i+1) = sum_j a^p_j. All bits and exponent bits are allocated
/// before Bulletproofs commits phase-one witness variables and samples a.
/// A false identity has degree <= m and acceptance probability <= m/|F|,
/// in addition to the underlying argument's soundness error. No positions or
/// Bloom bits become public. This uses the library's randomized R1CS phase.
pub fn constrain_bloom_consistency<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    item: Variable,
    positions: &[Variable],
    config: BloomFilterConfig,
    item_assignment: Option<Scalar>,
    bit_assignments: Option<&[Scalar]>,
) -> Result<BloomVariables, R1CSError> {
    config.validate().map_err(gadget_error)?;
    if positions.len() != config.hash_count
        || bit_assignments.is_some_and(|b| b.len() != config.bloom_filter_size)
    {
        return Err(gadget_error(
            "Bloom consistency witness dimensions do not match the configuration",
        ));
    }
    bounded_input_gadget(cs, item, item_assignment, config)?;
    let mut bits = Vec::with_capacity(config.bloom_filter_size);
    let mut population = LinearCombination::default();
    for i in 0..config.bloom_filter_size {
        let bit = boolean(cs, bit_assignments.map(|b| b[i]))?;
        population = population + bit;
        bits.push(bit);
    }
    cs.constrain(population - Scalar::from(config.hash_count as u64));

    let bit_length = (usize::BITS - config.bloom_filter_size.leading_zeros()) as usize;
    let mut exponents = Vec::with_capacity(positions.len());
    for (j, &position) in positions.iter().enumerate() {
        let (slope, intercept) = hash_params(j);
        cs.constrain(
            LinearCombination::from(position) - slope * LinearCombination::from(item) - intercept,
        );
        exponents.push(range_gadget(
            cs,
            position.into(),
            item_assignment.map(|y| slope * y + intercept),
            bit_length,
        )?);
    }
    let position_bits = exponents.clone();
    let fingerprint_bits = bits.clone();
    cs.specify_randomized_constraints(move |cs| {
        let alpha = cs.challenge_scalar(b"bf-item-bit-vector-identity-v1");
        let mut power = alpha;
        let mut fingerprint = LinearCombination::default();
        for bit in fingerprint_bits {
            fingerprint = fingerprint + power * LinearCombination::from(bit);
            power *= alpha;
        }
        for exponent_bits in exponents {
            let mut power = alpha;
            let mut value = LinearCombination::from(Scalar::one());
            for (j, bit) in exponent_bits.into_iter().enumerate() {
                let factor = LinearCombination::from(Scalar::one())
                    + (power - Scalar::one()) * LinearCombination::from(bit);
                value = if j == 0 {
                    factor
                } else {
                    cs.multiply(value, factor).2.into()
                };
                power *= power;
            }
            fingerprint = fingerprint - value;
        }
        cs.constrain(fingerprint);
        Ok(())
    })?;
    Ok(BloomVariables {
        bits,
        position_bits,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::{
        r1cs::{Prover, R1CSProof, Verifier},
        BulletproofGens, PedersenGens,
    };
    use curve25519_dalek_ng::ristretto::CompressedRistretto;
    use merlin::Transcript;
    use rand::rngs::OsRng;
    use std::time::Instant;

    #[derive(Clone)]
    struct Commitments {
        item: CompressedRistretto,
        positions: Vec<CompressedRistretto>,
        bytes: Vec<CompressedRistretto>,
    }

    fn transcript(config: BloomFilterConfig, context: u64) -> Transcript {
        let mut transcript = Transcript::new(b"bf-bloom-consistency-arithmetic-test-v1");
        transcript.append_u64(b"buckets", config.bloom_filter_size as u64);
        transcript.append_u64(b"hash-count", config.hash_count as u64);
        transcript.append_u64(b"context", context);
        transcript
    }

    fn assignments(
        item: u64,
        config: BloomFilterConfig,
    ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
        let item = Scalar::from(item);
        let packed = super::super::bloom::scalar_bloom_bits(item, config).unwrap();
        let positions = super::super::bloom::scalar_positions_checked(item, config).unwrap();
        let bits = (0..config.bloom_filter_size)
            .map(|i| Scalar::from(((packed[i / 8] >> (i % 8)) & 1) as u64))
            .collect();
        let bytes = packed.into_iter().map(|b| Scalar::from(b as u64)).collect();
        (positions, bits, bytes)
    }

    fn prove(
        pc: &PedersenGens,
        bp: &BulletproofGens,
        config: BloomFilterConfig,
        item: u64,
        positions: &[Scalar],
        bits: &[Scalar],
        bytes: &[Scalar],
    ) -> (R1CSProof, Commitments) {
        let mut rng = OsRng;
        let mut transcript = transcript(config, 1);
        let mut prover = Prover::new(pc, &mut transcript);
        let (item_commitment, item_variable) =
            prover.commit(Scalar::from(item), Scalar::random(&mut rng));
        let mut position_commitments = Vec::new();
        let mut position_variables = Vec::new();
        for &position in positions {
            let (commitment, variable) = prover.commit(position, Scalar::random(&mut rng));
            position_commitments.push(commitment);
            position_variables.push(variable);
        }
        let mut byte_commitments = Vec::new();
        let mut byte_variables = Vec::new();
        for &byte in bytes {
            let (commitment, variable) = prover.commit(byte, Scalar::random(&mut rng));
            byte_commitments.push(commitment);
            byte_variables.push(variable);
        }
        let bloom = constrain_bloom_consistency(
            &mut prover,
            item_variable,
            &position_variables,
            config,
            Some(Scalar::from(item)),
            Some(bits),
        )
        .unwrap();
        for (byte, variable) in bloom.bytes().into_iter().zip(byte_variables) {
            prover.constrain(byte - variable);
        }
        let proof = prover.prove(bp).unwrap();
        (
            proof,
            Commitments {
                item: item_commitment,
                positions: position_commitments,
                bytes: byte_commitments,
            },
        )
    }

    fn verify(
        pc: &PedersenGens,
        bp: &BulletproofGens,
        config: BloomFilterConfig,
        context: u64,
        proof: &R1CSProof,
        commitments: &Commitments,
    ) -> bool {
        if commitments.positions.len() != config.hash_count
            || commitments.bytes.len() != config.bloom_filter_size.div_ceil(8)
        {
            return false;
        }
        let mut transcript = transcript(config, context);
        let mut verifier = Verifier::new(&mut transcript);
        let item = verifier.commit(commitments.item);
        let positions: Vec<_> = commitments
            .positions
            .iter()
            .map(|&c| verifier.commit(c))
            .collect();
        let bytes: Vec<_> = commitments
            .bytes
            .iter()
            .map(|&c| verifier.commit(c))
            .collect();
        let bloom =
            constrain_bloom_consistency(&mut verifier, item, &positions, config, None, None)
                .unwrap();
        for (byte, variable) in bloom.bytes().into_iter().zip(bytes) {
            verifier.constrain(byte - variable);
        }
        verifier.verify(proof, pc, bp).is_ok()
    }

    #[test]
    fn rejects_inconsistent_item_positions_bits_and_byte_encoding() {
        let config = BloomFilterConfig {
            bloom_filter_size: 35,
            hash_count: 3,
            target_marked_count: 15,
        };
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(crate::bf::bp_capacity(0, config), 1);
        let (positions, bits, bytes) = assignments(3, config);
        assert_eq!(&bytes[..2], &[Scalar::from(68u64), Scalar::from(4u64)]);
        for variant in 0..7 {
            let mut positions = positions.clone();
            let mut bits = bits.clone();
            let mut bytes = bytes.clone();
            let item = if variant == 1 { 4 } else { 3 };
            match variant {
                2 => positions[0] += Scalar::one(),
                3 => {
                    bits[2] = Scalar::zero();
                    bits[0] = Scalar::one();
                }
                4 => {
                    bits[2] = Scalar::zero();
                    bits[6] = Scalar::zero();
                    bits[0] = Scalar::from(2u64);
                }
                5 => *bytes.last_mut().unwrap() = Scalar::from(128u64),
                6 => bits[0] = Scalar::one(),
                _ => (),
            }
            if [3, 4, 6].contains(&variant) {
                // Keep the byte commitments consistent with the forged bits.
                // Otherwise a broken item/bit-vector relation could be masked
                // by a failure of the independent byte-equality constraints.
                bytes = bits
                    .chunks(8)
                    .map(|chunk| {
                        chunk
                            .iter()
                            .enumerate()
                            .fold(Scalar::zero(), |sum, (i, &bit)| {
                                sum + Scalar::from(1u64 << i) * bit
                            })
                    })
                    .collect();
            }
            let (proof, commitments) = prove(&pc, &bp, config, item, &positions, &bits, &bytes);
            assert_eq!(
                verify(&pc, &bp, config, 1, &proof, &commitments),
                variant == 0,
                "variant {variant}"
            );
            assert!(!verify(&pc, &bp, config, 2, &proof, &commitments));
            if variant == 0 {
                let mut changed = commitments.clone();
                changed.bytes[0] = (changed.bytes[0].decompress().unwrap()
                    + curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT)
                    .compress();
                assert!(!verify(&pc, &bp, config, 1, &proof, &changed));
            }
        }
    }

    #[test]
    fn last_bucket_and_byte_boundaries_are_constrained() {
        let pc = PedersenGens::default();
        for buckets in [1, 2, 8, 9, 32, 33] {
            let config = BloomFilterConfig {
                bloom_filter_size: buckets,
                hash_count: 1,
                target_marked_count: buckets / 2,
            };
            let bp = BulletproofGens::new(crate::bf::bp_capacity(0, config), 1);
            let (positions, bits, bytes) = assignments(buckets as u64, config);
            let (proof, commitments) =
                prove(&pc, &bp, config, buckets as u64, &positions, &bits, &bytes);
            assert!(
                verify(&pc, &bp, config, 1, &proof, &commitments),
                "bucket count {buckets}"
            );
        }
    }

    #[test]
    fn proves_100k_bucket_consistency_with_shared_item_and_bytes() {
        let config = BloomFilterConfig {
            bloom_filter_size: 100_000,
            hash_count: 20,
            target_marked_count: 50_000,
        };
        let pc = PedersenGens::default();
        let start = Instant::now();
        let bp = BulletproofGens::new(crate::bf::bp_capacity(0, config), 1);
        eprintln!(
            "100k consistency generator setup: {:?}; capacity {}",
            start.elapsed(),
            bp.gens_capacity
        );
        let (positions, bits, bytes) = assignments(4_999, config);
        let start = Instant::now();
        let (proof, commitments) = prove(&pc, &bp, config, 4_999, &positions, &bits, &bytes);
        eprintln!(
            "100k consistency proving: {:?}; R1CS proof {} bytes; byte commitments {}",
            start.elapsed(),
            proof.to_bytes().len(),
            commitments.bytes.len()
        );
        let start = Instant::now();
        assert!(verify(&pc, &bp, config, 1, &proof, &commitments));
        eprintln!("100k consistency verification: {:?}", start.elapsed());
    }
}
