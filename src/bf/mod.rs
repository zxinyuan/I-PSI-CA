pub mod bloom;
pub mod monitor;
pub mod proof;
pub mod target;

use crate::bf::bloom::BloomFilterConfig;

pub(crate) fn bp_capacity(max_degree: usize, bf_config: BloomFilterConfig) -> usize {
    let coeff_len = max_degree + 1;
    let k = bf_config.hash_count;
    let mul_gates = k
        .saturating_mul(coeff_len.saturating_add(1))
        .saturating_add(1);
    mul_gates.max(64).next_power_of_two()
}
