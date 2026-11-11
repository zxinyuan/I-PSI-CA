#[cfg(feature = "experimental-rlwe")]
mod accumulator;
pub mod bloom;
pub mod constraints;
#[cfg(feature = "experimental-rlwe")]
pub mod monitor;
#[cfg(feature = "experimental-rlwe")]
pub mod proof;
#[cfg(feature = "experimental-rlwe")]
pub mod target;

// Native encryption, circuit privacy and shared arithmetic proof components.
#[cfg(feature = "experimental-rlwe")]
pub(crate) mod accumulator_proof;
#[cfg(feature = "experimental-rlwe")]
pub mod circuit_privacy;
#[cfg(feature = "experimental-rlwe")]
pub mod coefficient_constraints;
#[cfg(feature = "experimental-rlwe")]
pub mod evaluation_proof;
#[cfg(feature = "experimental-rlwe")]
pub(crate) mod extension;
#[cfg(feature = "experimental-rlwe")]
pub mod field_constraints;
#[cfg(feature = "experimental-rlwe")]
pub mod floor_constraints;
#[cfg(feature = "experimental-rlwe")]
pub mod packing_plan;
#[cfg(feature = "experimental-rlwe")]
pub(crate) mod pkc_evaluation;
#[cfg(feature = "experimental-rlwe")]
pub mod pkc_link;
#[cfg(feature = "experimental-rlwe")]
pub(crate) mod proof_values;
#[cfg(feature = "experimental-rlwe")]
pub(crate) mod protocol_hash;
#[cfg(feature = "experimental-rlwe")]
pub(crate) mod protocol_math;
#[cfg(feature = "experimental-rlwe")]
pub mod rlwe;
#[cfg(feature = "experimental-rlwe")]
mod rlwe_polynomial;
#[cfg(feature = "experimental-rlwe")]
pub mod sha256_constraints;
#[cfg(feature = "experimental-rlwe")]
pub mod weight_constraints;

#[cfg(test)]
use crate::bf::bloom::BloomFilterConfig;

#[cfg(test)]
pub(crate) fn bp_capacity(max_degree: usize, bf_config: BloomFilterConfig) -> usize {
    let coeff_len = max_degree + 1;
    let k = bf_config.hash_count;
    let mul_gates = k
        .saturating_mul(coeff_len.saturating_add(1))
        .saturating_add(1)
        .saturating_add(
            2 * (usize::BITS
                - bloom::usable_input_span(bf_config)
                    .saturating_sub(1)
                    .leading_zeros()) as usize,
        )
        .saturating_add(constraints::bloom_multipliers(bf_config));
    mul_gates.max(64).next_power_of_two()
}
