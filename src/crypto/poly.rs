//! Plaintext polynomials over the scalar field, with coefficients in ascending order.
use curve25519_dalek_ng::scalar::Scalar;
use zeroize::Zeroizing;

/// Below this size, quadratic expansion is faster than recursion.
const LEAF: usize = 32;

/// Monic polynomial with the given roots (with multiplicity).
///
/// Uses a product tree with Karatsuba multiplication: O(n^1.59) field
/// multiplications instead of the O(n^2) of expanding one root at a time.
/// Intermediate products are zeroized, since roots may be private set elements.
pub fn poly_from_roots(roots: &[Scalar]) -> Vec<Scalar> {
    if roots.len() <= LEAF {
        return expand(roots);
    }
    let (low, high) = roots.split_at(roots.len() / 2);
    let low = Zeroizing::new(poly_from_roots(low));
    let high = Zeroizing::new(poly_from_roots(high));
    mul(&low, &high)
}

fn expand(roots: &[Scalar]) -> Vec<Scalar> {
    let mut coeffs = Vec::with_capacity(roots.len() + 1);
    coeffs.push(Scalar::one());
    for root in roots {
        let n = coeffs.len();
        let leading = *coeffs.last().unwrap();
        coeffs.push(leading);
        for d in (1..n).rev() {
            coeffs[d] = coeffs[d - 1] - root * coeffs[d];
        }
        coeffs[0] *= -root;
    }
    coeffs
}

/// Product of two nonempty polynomials.
fn mul(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    let len = a.len() + b.len() - 1;
    let n = a.len().max(b.len());
    // Allocate at full size: resizing a copy would free an unwiped buffer.
    let pad = |p: &[Scalar]| {
        let mut v = Zeroizing::new(Vec::with_capacity(n));
        v.extend_from_slice(p);
        v.resize(n, Scalar::zero());
        v
    };
    let mut out = karatsuba(&pad(a), &pad(b));
    out.truncate(len);
    out
}

/// Product of two polynomials of equal length n, as 2n - 1 coefficients.
fn karatsuba(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    let n = a.len();
    if n <= LEAF {
        let mut out = vec![Scalar::zero(); 2 * n - 1];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                out[i + j] += x * y;
            }
        }
        return out;
    }
    // a = a0 + X^h a1 with len(a0) = h <= len(a1) = n - h, and likewise for b.
    let h = n / 2;
    let (a0, a1) = a.split_at(h);
    let (b0, b1) = b.split_at(h);
    let sum = |lo: &[Scalar], hi: &[Scalar]| {
        Zeroizing::new(
            hi.iter()
                .enumerate()
                .map(|(i, x)| lo.get(i).map_or(*x, |y| x + y))
                .collect::<Vec<_>>(),
        )
    };
    let z0 = Zeroizing::new(karatsuba(a0, b0));
    let z2 = Zeroizing::new(karatsuba(a1, b1));
    let z1 = Zeroizing::new(karatsuba(&sum(a0, a1), &sum(b0, b1)));
    // a*b = z0 + X^h (z1 - z0 - z2) + X^(2h) z2.
    let mut out = vec![Scalar::zero(); 2 * n - 1];
    for (i, x) in z0.iter().enumerate() {
        out[i] += x;
        out[i + h] -= x;
    }
    for (i, x) in z2.iter().enumerate() {
        out[i + 2 * h] += x;
        out[i + h] -= x;
    }
    for (i, x) in z1.iter().enumerate() {
        out[i + h] += x;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn product_tree_matches_root_by_root_expansion() {
        let mut rng = StdRng::seed_from_u64(31);
        for n in [0, 1, 2, 31, 32, 33, 64, 65, 100, 257] {
            let mut roots: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            if n > 2 {
                roots[1] = roots[0];
            }
            assert_eq!(poly_from_roots(&roots), expand(&roots), "n={n}");
        }
    }
    #[test]
    fn unequal_products_match_schoolbook() {
        let mut rng = StdRng::seed_from_u64(32);
        for (la, lb) in [(1, 1), (1, 40), (33, 34), (70, 3), (128, 129)] {
            let a: Vec<_> = (0..la).map(|_| Scalar::random(&mut rng)).collect();
            let b: Vec<_> = (0..lb).map(|_| Scalar::random(&mut rng)).collect();
            let mut expected = vec![Scalar::zero(); la + lb - 1];
            for (i, x) in a.iter().enumerate() {
                for (j, y) in b.iter().enumerate() {
                    expected[i + j] += x * y;
                }
            }
            assert_eq!(mul(&a, &b), expected, "{la}x{lb}");
        }
    }
}
