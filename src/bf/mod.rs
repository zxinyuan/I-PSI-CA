pub mod bloom;
pub mod monitor;
pub mod proof;
pub mod target;

use crate::bf::bloom::BloomFilterConfig;

pub(crate) fn bp_capacity(max_degree: usize, bf_config: BloomFilterConfig) -> usize {
    let coeff_len = max_degree + 1;
    let k = bf_config.hash_count;
    // L9's BF circuit has one `r·μ_j` multiplication and `coeff_len - 1`
    // exponent multiplications for every hash-derived mask μ_j, plus one
    // non-zero gate per μ_j and one for the outer mask r.
    let mul_gates = k
        .saturating_mul(coeff_len.saturating_add(1))
        .saturating_add(1);
    mul_gates.max(64).next_power_of_two()
}
