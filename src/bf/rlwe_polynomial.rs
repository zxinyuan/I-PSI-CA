//! Product-tree orchestration over fhe-math's existing exact NTT arithmetic.
use std::collections::BTreeMap;

use fhe_math::{ntt::NttOperator, zq::Modulus};
use zeroize::Zeroizing;

pub(super) fn from_roots(roots: &[u64], plaintext_modulus: u64) -> Result<Vec<u64>, String> {
    if roots.iter().any(|&r| r >= plaintext_modulus) {
        return Err("noncanonical polynomial root".into());
    }
    if roots.is_empty() {
        return Ok(vec![1]);
    }
    let modulus = Modulus::new(plaintext_modulus).map_err(|e| e.to_string())?;
    let mut operators = BTreeMap::new();
    let mut level: Vec<_> = roots
        .iter()
        .map(|&r| Zeroizing::new(vec![modulus.neg(r), 1]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut polynomials = level.into_iter();
        while let Some(left) = polynomials.next() {
            let Some(right) = polynomials.next() else {
                next.push(left);
                break;
            };
            let length = left.len() + right.len() - 1;
            let dimension = length.next_power_of_two().max(8);
            if let std::collections::btree_map::Entry::Vacant(entry) = operators.entry(dimension) {
                entry.insert(
                    NttOperator::new(&modulus, dimension)
                        .ok_or("plaintext field does not support the required polynomial size")?,
                );
            }
            let transform = &operators[&dimension];
            // Reserve full transform buffers before writing secret coefficients.
            let mut a = Zeroizing::new(vec![0; dimension]);
            let mut b = Zeroizing::new(vec![0; dimension]);
            a[..left.len()].copy_from_slice(&left);
            b[..right.len()].copy_from_slice(&right);
            transform.forward(&mut a);
            transform.forward(&mut b);
            modulus.mul_vec(&mut a, &b);
            transform.backward(&mut a);
            a.truncate(length);
            next.push(a);
        }
        level = next;
    }
    Ok(level.pop().unwrap().to_vec())
}
