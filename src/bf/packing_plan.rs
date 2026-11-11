//! Ciphertext packing subject to the current modulus-size/security policy.
//! A Bloom polynomial needs m+1 coefficients, including its leading coefficient.
use super::rlwe::{PROTOCOL_MODULI, PROTOCOL_PLAINTEXT_MODULUS};
use num_bigint::BigUint;

/// Current transport permits <4 MiB per ciphertext and public adjoints support
/// rings through 32768. Larger dimensions need separate resource validation.
pub const MAX_PROTOCOL_RING_DIMENSION: usize = 32768;
pub const PROTOCOL_RING_DIMENSIONS: [usize; 2] = [16384, 32768];

/// Classical 128-bit coefficient-modulus limits used by SEAL's HE-standard
/// policy (Gaussian/ternary reference tables). This is a parameter policy,
/// not a security certificate for this research implementation.
/// https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/hestdparms.h
pub fn modulus_bit_limit(dimension: usize) -> Option<usize> {
    match dimension {
        1024 => Some(27),
        2048 => Some(54),
        4096 => Some(109),
        8192 => Some(218),
        16384 => Some(438),
        32768 => Some(881),
        _ => None,
    }
}

pub(crate) fn validate_modulus_size(dimension: usize, bits: usize) -> Result<(), String> {
    let limit = modulus_bit_limit(dimension).ok_or("unsupported protocol ring dimension")?;
    if bits > limit {
        return Err(format!(
            "{bits}-bit ciphertext modulus exceeds the {limit}-bit policy limit for N={dimension}"
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackingPlan {
    pub coefficient_count: usize,
    pub ring_dimension: usize,
    pub ciphertext_count: usize,
    pub padded_coefficients: usize,
}
impl PackingPlan {
    pub fn for_buckets(buckets: usize) -> Result<Self, String> {
        if !(1..=100_000).contains(&buckets) {
            return Err("BF packing supports 1 through 100000 buckets".into());
        }
        let modulus: BigUint = PROTOCOL_MODULI.iter().map(|&q| BigUint::from(q)).product();
        let bits = modulus.bits() as usize;
        let count = buckets + 1;
        let candidates = PROTOCOL_RING_DIMENSIONS
            .into_iter()
            .filter_map(|n| {
                if validate_modulus_size(n, bits).is_err() {
                    return None;
                }
                Some(Self {
                    coefficient_count: count,
                    ring_dimension: n,
                    ciphertext_count: count.div_ceil(n),
                    padded_coefficients: count.div_ceil(n) * n,
                })
            })
            .collect::<Vec<_>>();
        // Prefer one ciphertext if an admissible implementation profile fits.
        if let Some(plan) = candidates
            .iter()
            .filter(|p| p.ciphertext_count == 1)
            .min_by_key(|p| p.ring_dimension)
        {
            return Ok(*plan);
        }
        // Splitting: minimize total coefficient slots first. For equal padding,
        // use the smaller ring, since coins/residual proof work scales with N.
        candidates
            .into_iter()
            .min_by_key(|p| (p.padded_coefficients, p.ring_dimension, p.ciphertext_count))
            .ok_or_else(|| "no secure supported packing profile".into())
    }

    pub fn plaintext_modulus(&self) -> u64 {
        PROTOCOL_PLAINTEXT_MODULUS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_one_ciphertext_or_minimum_padding_and_proof_dimension() {
        for (buckets, n, blocks) in [
            (1000, 16384, 1),
            (16383, 16384, 1),
            (16384, 32768, 1),
            (20000, 32768, 1),
            (32767, 32768, 1),
            (32768, 16384, 3),
            (50000, 16384, 4),
            (100000, 16384, 7),
        ] {
            let plan = PackingPlan::for_buckets(buckets).unwrap();
            assert_eq!((plan.ring_dimension, plan.ciphertext_count), (n, blocks));
            assert_eq!(plan.coefficient_count, buckets + 1);
            assert_eq!(plan.padded_coefficients, blocks * n);
        }
        assert!(PackingPlan::for_buckets(0).is_err());
        assert!(PackingPlan::for_buckets(100001).is_err());
    }
    #[test]
    fn every_supported_bucket_count_obeys_the_packing_objective() {
        for buckets in 1..=100000 {
            let plan = PackingPlan::for_buckets(buckets).unwrap();
            for n in PROTOCOL_RING_DIMENSIONS {
                let blocks = (buckets + 1).div_ceil(n);
                if blocks == 1 {
                    assert_eq!(plan.ciphertext_count, 1);
                }
                if plan.ciphertext_count > 1 {
                    assert!((plan.padded_coefficients, plan.ring_dimension) <= (blocks * n, n));
                }
            }
        }
    }
    #[test]
    fn capacity_does_not_override_the_modulus_size_policy() {
        assert!(1001 <= 1024);
        for n in [1024, 2048, 4096, 8192] {
            assert!(validate_modulus_size(n, 372).is_err());
        }
        for n in PROTOCOL_RING_DIMENSIONS {
            validate_modulus_size(n, 372).unwrap();
        }
        assert!(validate_modulus_size(32768, 882).is_err());
    }
}
