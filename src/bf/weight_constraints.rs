//! Exact SHA-256 / rejection-sampling link from the proved monitor Bloom vector
//! to private plaintext-field weights. This component is not an RLWE proof.
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use curve25519_dalek_ng::scalar::Scalar;

use super::{
    bloom::{scalar_bloom_bits, scalar_positions_checked, scalar_to_usize, BloomFilterConfig},
    constraints::BloomVariables,
    field_constraints::{reduce_candidates, FieldVariable},
    rlwe::{BLOOM_PLAINTEXT_MODULUS, MAX_HASH_ATTEMPTS, PLAINTEXT_MODULUS, WEIGHT_DOMAIN},
    sha256_constraints::{ShaByte, ShaCircuit},
};

fn error(e: impl std::fmt::Display) -> R1CSError {
    R1CSError::GadgetError {
        description: e.to_string(),
    }
}

/// Produces canonical h_i variables from the *same* Bloom/position variables
/// constrained by constrain_bloom_consistency. All retries have a fixed public
/// shape. The caller must include config, modulus and repetition in its public
/// transcript and reuse these variables in its arithmetic/PKC bridge.
///
/// The prefix compression constraints are shared across positions and retries;
/// no digest or host-computed weight is trusted as a public assertion.
pub fn constrain_item_weights<CS: ConstraintSystem>(
    cs: &mut CS,
    bloom: &BloomVariables,
    config: BloomFilterConfig,
    modulus: u64,
    repetition: u64,
    item_assignment: Option<Scalar>,
) -> Result<Vec<FieldVariable>, R1CSError> {
    config.validate().map_err(error)?;
    if ![PLAINTEXT_MODULUS, BLOOM_PLAINTEXT_MODULUS].contains(&modulus)
        || config.bloom_filter_size >= modulus as usize
        || config.bloom_filter_size >= (1 << 20)
        || bloom.config.bloom_filter_size != config.bloom_filter_size
        || bloom.config.hash_count != config.hash_count
        || bloom.bits.len() != config.bloom_filter_size
        || bloom.position_bits.len() != config.hash_count
    {
        return Err(error("incompatible Bloom/hash statement"));
    }
    let assignments = item_assignment
        .map(|y| {
            Ok::<_, R1CSError>((
                scalar_bloom_bits(y, config).map_err(error)?,
                scalar_positions_checked(y, config)
                    .map_err(error)?
                    .into_iter()
                    .map(|p| (scalar_to_usize(p) as u64).to_le_bytes())
                    .collect::<Vec<_>>(),
            ))
        })
        .transpose()?;
    let mut circuit = ShaCircuit::new(item_assignment.is_some());
    let mut prefix = WEIGHT_DOMAIN
        .iter()
        .copied()
        .map(ShaByte::Constant)
        .collect::<Vec<_>>();
    for value in [
        modulus,
        repetition,
        config.bloom_filter_size as u64,
        config.hash_count as u64,
    ] {
        prefix.extend(value.to_le_bytes().into_iter().map(ShaByte::Constant));
    }
    prefix.extend(
        bloom
            .bytes()
            .into_iter()
            .enumerate()
            .map(|(i, expression)| ShaByte::Private {
                expression,
                assignment: assignments.as_ref().map(|a| a.0[i]),
            }),
    );
    let prefix = circuit.input(&prefix)?;
    let mut state = Sha256Gadget::default();
    state.update(&prefix).map_err(error)?;
    let mut digests = Vec::with_capacity(config.hash_count * MAX_HASH_ATTEMPTS);
    for (j, bytes) in bloom.position_bytes().into_iter().enumerate() {
        let bytes = bytes
            .into_iter()
            .enumerate()
            .map(|(i, expression)| ShaByte::Private {
                expression,
                assignment: assignments.as_ref().map(|a| a.1[j][i]),
            })
            .collect::<Vec<_>>();
        let bytes = circuit.input(&bytes)?;
        let mut position_state = state.clone();
        position_state.update(&bytes).map_err(error)?;
        for counter in 0..MAX_HASH_ATTEMPTS as u64 {
            let mut candidate_state = position_state.clone();
            let counter = circuit.input(
                &counter
                    .to_le_bytes()
                    .into_iter()
                    .map(ShaByte::Constant)
                    .collect::<Vec<_>>(),
            )?;
            candidate_state.update(&counter).map_err(error)?;
            digests.push(candidate_state.finalize().map_err(error)?.0);
        }
    }
    let digests = circuit.finish(cs, digests)?;
    digests
        .chunks(MAX_HASH_ATTEMPTS)
        .map(|attempts| {
            let bits = attempts
                .iter()
                .map(|d| d.bits[..8].iter().flatten().cloned().collect::<Vec<_>>())
                .collect::<Vec<_>>();
            let assignments = attempts
                .iter()
                .map(|d| {
                    d.assignment.as_ref().map(|a| {
                        u64::from_le_bytes(a[..8].try_into().expect("SHA-256 digest length"))
                    })
                })
                .collect::<Option<Vec<_>>>();
            if assignments
                .as_ref()
                .is_some_and(|a| a.iter().all(|&v| v >= u64::MAX - u64::MAX % modulus))
            {
                return Err(error(
                    "hash-to-field rejection limit exhausted; no biased fallback is allowed",
                ));
            }
            reduce_candidates(cs, &bits, assignments.as_deref(), modulus)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bf::{constraints::constrain_bloom_consistency, rlwe::item_weights_for_repetition};
    use bulletproofs::{
        r1cs::{LinearCombination as LC, Prover, Verifier},
        BulletproofGens, PedersenGens,
    };
    use merlin::Transcript;
    use rand::rngs::OsRng;

    fn transcript(config: BloomFilterConfig, modulus: u64, repetition: u64) -> Transcript {
        let mut t = Transcript::new(b"bf-bloom-to-sha-weight-proof-test-v1");
        t.append_u64(b"buckets", config.bloom_filter_size as u64);
        t.append_u64(b"hashes", config.hash_count as u64);
        t.append_u64(b"modulus", modulus);
        t.append_u64(b"repetition", repetition);
        t
    }

    #[test]
    fn full_bloom_sha_rejection_weight_proof_and_tampering() {
        let config = BloomFilterConfig {
            bloom_filter_size: 9,
            hash_count: 1,
            target_marked_count: 0,
        };
        let item = Scalar::from(8u64);
        let modulus = BLOOM_PLAINTEXT_MODULUS;
        let repetition = 2;
        let expected = item_weights_for_repetition(item, config, modulus, repetition).unwrap()[0].1;
        let packed = scalar_bloom_bits(item, config).unwrap();
        let bit_assignments = (0..config.bloom_filter_size)
            .map(|i| Scalar::from(((packed[i / 8] >> (i % 8)) & 1) as u64))
            .collect::<Vec<_>>();
        let pc = PedersenGens::default();
        let mut t = transcript(config, modulus, repetition);
        let mut p = Prover::new(&pc, &mut t);
        let (item_commitment, item_var) = p.commit(item, Scalar::random(&mut OsRng));
        let (pos_commitment, pos_var) = p.commit(item, Scalar::random(&mut OsRng));
        let bloom = constrain_bloom_consistency(
            &mut p,
            item_var,
            &[pos_var],
            config,
            Some(item),
            Some(&bit_assignments),
        )
        .unwrap();
        let weights =
            constrain_item_weights(&mut p, &bloom, config, modulus, repetition, Some(item))
                .unwrap();
        assert_eq!(weights[0].assignment(), Some(expected));
        p.constrain(LC::from(weights[0].variable()) - Scalar::from(expected));
        let gates = p.metrics().multipliers;
        eprintln!("linked Bloom/SHA/rejection proof: {gates} multipliers");
        let bp = BulletproofGens::new((gates + 32).next_power_of_two(), 1);
        let proof = p.prove(&bp).unwrap();
        for (claimed, rep, changed_item, valid) in [
            (expected, repetition, false, true),
            ((expected + 1) % modulus, repetition, false, false),
            (expected, repetition + 1, false, false),
            (expected, repetition, true, false),
        ] {
            let mut t = transcript(config, modulus, rep);
            let mut v = Verifier::new(&mut t);
            let item_var = v.commit(if changed_item {
                pc.commit(item + Scalar::one(), Scalar::zero()).compress()
            } else {
                item_commitment
            });
            let pos_var = v.commit(pos_commitment);
            let bloom =
                constrain_bloom_consistency(&mut v, item_var, &[pos_var], config, None, None)
                    .unwrap();
            let weights =
                constrain_item_weights(&mut v, &bloom, config, modulus, rep, None).unwrap();
            v.constrain(LC::from(weights[0].variable()) - Scalar::from(claimed));
            assert_eq!(v.verify(&proof, &pc, &bp).is_ok(), valid);
        }
    }
}
