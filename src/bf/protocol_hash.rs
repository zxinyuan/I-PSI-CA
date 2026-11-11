//! Versioned item/index HashToField and sparse Bloom-set field encoding.
//! Reuses Arkworks Poseidon and its standard constraints; Bulletproofs proves
//! the imported constraints over the identical Ristretto scalar field.
use super::{
    bloom::{scalar_positions_checked, scalar_to_usize, BloomFilterConfig},
    field_constraints::{reduce_candidates, FieldVariable},
    rlwe::PROTOCOL_PLAINTEXT_MODULUS,
    sha256_constraints::{ShaCircuit, F},
};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{
        constraints::PoseidonSpongeVar, traits::find_poseidon_ark_and_mds, PoseidonConfig,
        PoseidonSponge,
    },
    CryptographicSponge,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable};
use curve25519_dalek_ng::scalar::Scalar;
use sha2::{Digest, Sha512};
use std::sync::OnceLock;

pub(crate) const ATTEMPTS: usize = 6;
pub(crate) const REPETITIONS: usize = 3;
pub(crate) const MAX_BUCKETS: usize = 100_000;
pub(crate) const MAX_HASHES: usize = 64;

fn error(e: impl std::fmt::Display) -> R1CSError {
    R1CSError::GadgetError {
        description: e.to_string(),
    }
}

pub(crate) fn config() -> &'static PoseidonConfig<F> {
    static CONFIG: OnceLock<PoseidonConfig<F>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        // Width four, rate two, capacity two, x^5, 8 full/60 partial rounds.
        // Capacity is two field elements, exceeding 256 bits even in F_l.
        let (ark, mds) = find_poseidon_ark_and_mds::<F>(F::MODULUS_BIT_SIZE as u64, 3, 8, 60, 0);
        PoseidonConfig::new(8, 60, 5, mds, ark, 2, 2)
    })
}

fn domain() -> F {
    F::from_le_bytes_mod_order(&Sha512::digest(
        b"i-psi-ca/bf/poseidon-item-index-weight/v4",
    ))
}

pub(crate) fn validate(config: BloomFilterConfig) -> Result<(), String> {
    config.validate()?;
    if config.bloom_filter_size > MAX_BUCKETS || config.hash_count > MAX_HASHES {
        return Err("BF supports at most 100000 buckets and 64 hashes".into());
    }
    Ok(())
}

pub(crate) fn weights(
    item: Scalar,
    config: BloomFilterConfig,
) -> Result<Vec<Vec<(u64, u64)>>, String> {
    validate(config)?;
    let positions = scalar_positions_checked(item, config)?
        .into_iter()
        .map(|p| scalar_to_usize(p) as u64)
        .collect::<Vec<_>>();
    let mut prefix = PoseidonSponge::new(self::config());
    let values = vec![
        domain(),
        F::from(PROTOCOL_PLAINTEXT_MODULUS),
        F::from(config.bloom_filter_size as u64),
        F::from(config.hash_count as u64),
        F::from_le_bytes_mod_order(&item.to_bytes()),
    ];

    prefix.absorb(&values);
    let t = PROTOCOL_PLAINTEXT_MODULUS;
    let limit = u64::MAX - u64::MAX % t;
    (0..REPETITIONS)
        .map(|repetition| {
            positions
                .iter()
                .map(|&position| {
                    for counter in 0..ATTEMPTS {
                        let mut hash = prefix.clone();
                        hash.absorb(&vec![
                            F::from(repetition as u64),
                            F::from(position),
                            F::from(counter as u64),
                        ]);
                        let bytes = hash.squeeze_bytes(8);
                        let candidate = u64::from_le_bytes(bytes.try_into().unwrap());
                        if candidate < limit {
                            return Ok((position, candidate % t));
                        }
                    }
                    Err("HashToField rejection limit exhausted".into())
                })
                .collect()
        })
        .collect()
}

pub(crate) fn constrain<CS: ConstraintSystem>(
    cs: &mut CS,
    item: Variable,
    positions: &[Variable],
    config: BloomFilterConfig,
    item_assignment: Option<Scalar>,
) -> Result<Vec<Vec<FieldVariable>>, R1CSError> {
    validate(config).map_err(error)?;
    if positions.len() != config.hash_count {
        return Err(error("Bloom and hash statement differ"));
    }
    let assigned = item_assignment
        .map(|item| scalar_positions_checked(item, config))
        .transpose()
        .map_err(error)?;
    let mut circuit = ShaCircuit::new(item_assignment.is_some());
    let mut prefix = PoseidonSpongeVar::new(circuit.cs.clone(), self::config());
    let mut inputs = vec![
        FpVar::Constant(domain()),
        FpVar::Constant(F::from(PROTOCOL_PLAINTEXT_MODULUS)),
        FpVar::Constant(F::from(config.bloom_filter_size as u64)),
        FpVar::Constant(F::from(config.hash_count as u64)),
    ];
    let mut private = Vec::with_capacity(positions.len());
    for (i, &position) in positions.iter().enumerate() {
        private.push(circuit.field_input(position.into(), assigned.as_ref().map(|p| p[i]))?);
    }
    inputs.push(circuit.field_input(item.into(), item_assignment)?);
    prefix.absorb(&inputs).map_err(error)?;
    let mut digests = Vec::new();
    for repetition in 0..REPETITIONS {
        for position in &private {
            for counter in 0..ATTEMPTS {
                let mut hash = prefix.clone();
                hash.absorb(&vec![
                    FpVar::Constant(F::from(repetition as u64)),
                    position.clone(),
                    FpVar::Constant(F::from(counter as u64)),
                ])
                .map_err(error)?;
                digests.push(hash.squeeze_bytes(8).map_err(error)?);
            }
        }
    }
    let digests = circuit.finish(cs, digests)?;
    let mut values = Vec::new();
    for candidates in digests.chunks(ATTEMPTS) {
        let bits = candidates
            .iter()
            .map(|digest| digest.bits.iter().flatten().cloned().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let assignments = candidates
            .iter()
            .map(|digest| {
                digest
                    .assignment
                    .as_ref()
                    .map(|a| u64::from_le_bytes(a.as_slice().try_into().unwrap()))
            })
            .collect::<Option<Vec<_>>>();
        values.push(reduce_candidates(
            cs,
            &bits,
            assignments.as_deref(),
            PROTOCOL_PLAINTEXT_MODULUS,
        )?);
    }
    let mut iter = values.into_iter();
    Ok((0..REPETITIONS)
        .map(|_| iter.by_ref().take(config.hash_count).collect())
        .collect())
}

fn encoding_domain() -> F {
    F::from_le_bytes_mod_order(&Sha512::digest(b"i-psi-ca/bf/bloom-set-to-scalar/v1"))
}

pub(crate) fn encode_positions(item: Scalar, config: BloomFilterConfig) -> Result<Scalar, String> {
    validate(config)?;
    let positions = scalar_positions_checked(item, config)?;
    let mut values = vec![
        encoding_domain(),
        F::from(config.bloom_filter_size as u64),
        F::from(config.hash_count as u64),
    ];
    values.extend(
        positions
            .iter()
            .map(|p| F::from_le_bytes_mod_order(&p.to_bytes())),
    );
    let mut hash = PoseidonSponge::new(self::config());
    hash.absorb(&values);
    super::sha256_constraints::scalar(hash.squeeze_field_elements::<F>(1)[0])
        .map_err(|e| e.to_string())
}

/// The returned scalar is the SAME encoding used by root insertion and masked
/// accumulator evaluation. Hashing an unrelated host-side position list is not enough.
pub(crate) fn constrain_encoding<CS: ConstraintSystem>(
    cs: &mut CS,
    item: Variable,
    encoded: Variable,
    config: BloomFilterConfig,
    assignment: Option<Scalar>,
) -> Result<(), R1CSError> {
    let assigned = assignment
        .map(|v| scalar_positions_checked(v, config))
        .transpose()
        .map_err(error)?;
    let positions = (0..config.hash_count)
        .map(|j| cs.allocate(assigned.as_ref().map(|p| p[j])))
        .collect::<Result<Vec<_>, _>>()?;
    super::constraints::constrain_positions(cs, item, &positions, config, assignment)?;
    let mut circuit = ShaCircuit::new(assignment.is_some());
    let mut values = vec![
        FpVar::Constant(encoding_domain()),
        FpVar::Constant(F::from(config.bloom_filter_size as u64)),
        FpVar::Constant(F::from(config.hash_count as u64)),
    ];
    for (j, &p) in positions.iter().enumerate() {
        values.push(circuit.field_input(p.into(), assigned.as_ref().map(|p| p[j]))?);
    }
    let mut hash = PoseidonSpongeVar::new(circuit.cs.clone(), self::config());
    hash.absorb(&values).map_err(error)?;
    let value = hash.squeeze_field_elements(1).map_err(error)?.remove(0);
    circuit.bind_field(&value, encoded.into())?;
    circuit.finish(cs, Vec::new())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_domain_separation_and_sparse_bloom_are_canonical() {
        let config = BloomFilterConfig {
            bloom_filter_size: 100_000,
            hash_count: 20,
            target_marked_count: 50_000,
        };
        let weights = weights(Scalar::from(4123u64), config).unwrap();
        assert_eq!(weights.len(), 3);
        assert_eq!(weights[0].len(), 20);
        assert_ne!(weights[0], weights[1]);
        assert!(weights
            .iter()
            .flatten()
            .all(|&(p, h)| p <= 100_000 && h < PROTOCOL_PLAINTEXT_MODULUS));
    }
}
