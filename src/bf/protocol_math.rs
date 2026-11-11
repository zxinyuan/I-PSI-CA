//! Exact integer lifts and public adjoints using fhe-math's native NTT/CRT.
use curve25519_dalek_ng::scalar::Scalar;
use fhe::bfv::BfvParametersBuilder;
use fhe_math::rq::{traits::TryConvertFrom, Context, Poly, Representation};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::ToPrimitive;
#[cfg(test)]
use num_traits::Zero;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

#[cfg(test)]
pub(crate) fn scalar(value: &BigInt) -> Result<Scalar, String> {
    let (sign, encoded) = value.to_bytes_le();
    if encoded.len() > 64 {
        return Err("integer lift exceeds supported width".into());
    }
    let mut bytes = [0u8; 64];
    bytes[..encoded.len()].copy_from_slice(&encoded);
    let value = Scalar::from_bytes_mod_order_wide(&bytes);
    Ok(if sign == Sign::Minus { -value } else { value })
}

pub(crate) fn signed(value: i64) -> Scalar {
    if value < 0 {
        -Scalar::from(value.unsigned_abs())
    } else {
        Scalar::from(value as u64)
    }
}

pub(crate) fn split(value: &BigInt) -> Result<(i64, i32), String> {
    let base = BigInt::from(1u8) << 64usize;
    let mut low = value % &base;
    if low.sign() == Sign::Minus {
        low += &base;
    }
    if low >= (BigInt::from(1u8) << 63usize) {
        low -= &base;
    }
    let high = (value - &low) / base;
    Ok((
        low.to_i64().ok_or("low quotient limb overflow")?,
        high.to_i32().ok_or("high quotient limb overflow")?,
    ))
}

fn context(n: usize, limbs: usize) -> Result<Arc<Context>, String> {
    type Cache = BTreeMap<(usize, usize), Arc<Context>>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| "NTT context cache poisoned")?;
    if let Some(c) = cache.get(&(n, limbs)) {
        return Ok(c.clone());
    }
    let parameters = BfvParametersBuilder::new()
        .set_degree(n)
        .set_plaintext_modulus(17)
        .set_moduli_sizes(&vec![62; limbs])
        .build_arc()
        .map_err(|e| e.to_string())?;
    let context = parameters
        .context_at_level(0)
        .map_err(|e| e.to_string())?
        .clone();
    cache.insert((n, limbs), context.clone());
    Ok(context)
}

/// Exact signed negacyclic convolution. CRT modulus is checked against a
/// conservative integer bound before lifting; there is no silent wraparound.
pub(crate) fn convolution(a: &[BigInt], b: &[BigInt]) -> Result<Vec<BigInt>, String> {
    if a.len() != b.len() || !a.len().is_power_of_two() || a.len() < 8 || a.len() > 32768 {
        return Err("invalid integer-convolution dimensions".into());
    }
    let max_a = a
        .iter()
        .map(|x| x.magnitude())
        .max()
        .cloned()
        .unwrap_or_default();
    let max_b = b
        .iter()
        .map(|x| x.magnitude())
        .max()
        .cloned()
        .unwrap_or_default();
    let bound = BigUint::from(2 * a.len()) * max_a * max_b;
    let limbs = if bound.bits() < 180 { 3 } else { 6 };
    let ctx = context(a.len(), limbs)?;
    if ctx.modulus() <= &bound {
        return Err("insufficient auxiliary CRT modulus for exact convolution".into());
    }
    let encode = |values: &[BigInt]| -> Result<Poly, String> {
        let q = BigInt::from(ctx.modulus().clone());
        let values = values
            .iter()
            .map(|v| {
                let mut v = v % &q;
                if v.sign() == Sign::Minus {
                    v += &q;
                }
                v.to_biguint().unwrap()
            })
            .collect::<Vec<_>>();
        let mut polynomial =
            Poly::try_convert_from(values.as_slice(), &ctx, false, Representation::PowerBasis)
                .map_err(|e| e.to_string())?;
        polynomial.change_representation(Representation::Ntt);
        Ok(polynomial)
    };
    let mut product = &encode(a)? * &encode(b)?;
    product.change_representation(Representation::PowerBasis);
    let half = ctx.modulus() >> 1usize;
    Ok(Vec::<BigUint>::from(&product)
        .into_iter()
        .map(|v| {
            if v > half {
                BigInt::from(v) - BigInt::from(ctx.modulus().clone())
            } else {
                BigInt::from(v)
            }
        })
        .collect())
}

/// Public adjoint: <challenge,A*W mod(X^N+1)> = <adjoint,W> in F_l.
#[cfg(test)]
pub(crate) fn adjoint(a: &[u64], challenge: &[Scalar]) -> Result<Vec<Scalar>, String> {
    let n = a.len();
    if n != challenge.len() {
        return Err("adjoint dimensions differ".into());
    }
    let mut reversed = vec![BigInt::zero(); n];
    reversed[0] = BigInt::from(BigUint::from_bytes_le(&challenge[0].to_bytes()));
    for i in 1..n {
        reversed[n - i] = BigInt::from(BigUint::from_bytes_le(&(-challenge[i]).to_bytes()));
    }
    let a = a.iter().map(|&v| BigInt::from(v)).collect::<Vec<_>>();
    let convolution = convolution(&a, &reversed)?;
    let mut result = Vec::with_capacity(n);
    result.push(scalar(&convolution[0])?);
    for i in 1..n {
        result.push(-scalar(&convolution[n - i])?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_lifts_and_public_adjoint_match_independent_arithmetic() {
        let n = 16;
        let a = (0..n)
            .map(|i| BigInt::from(i as i64 * 19 - 80))
            .collect::<Vec<_>>();
        let b = (0..n)
            .map(|i| BigInt::from(i as i64 * 71 - 500))
            .collect::<Vec<_>>();
        let mut expected = vec![BigInt::zero(); n];
        for i in 0..n {
            for j in 0..n {
                let product = &a[i] * &b[j];
                if i + j < n {
                    expected[i + j] += product;
                } else {
                    expected[i + j - n] -= product;
                }
            }
        }
        assert_eq!(convolution(&a, &b).unwrap(), expected);
        let public = (0..n)
            .map(|i| (1u64 << 61) + i as u64 * 11)
            .collect::<Vec<_>>();
        let gamma = (0..n)
            .map(|_| Scalar::random(&mut rand::rngs::OsRng))
            .collect::<Vec<_>>();
        let adjoint = adjoint(&public, &gamma).unwrap();
        let mut lhs = Scalar::zero();
        for i in 0..n {
            for j in 0..n {
                let p = Scalar::from(public[i]) * signed(j as i64 - 5);
                if i + j < n {
                    lhs += gamma[i + j] * p;
                } else {
                    lhs -= gamma[i + j - n] * p;
                }
            }
        }
        let rhs = adjoint
            .iter()
            .enumerate()
            .fold(Scalar::zero(), |sum, (j, a)| sum + a * signed(j as i64 - 5));
        assert_eq!(lhs, rhs);
        for value in [
            BigInt::from(-1),
            BigInt::from(1u8) << 81usize,
            -(BigInt::from(1u8) << 80usize),
        ] {
            let (lo, hi) = split(&value).unwrap();
            assert_eq!(BigInt::from(lo) + (BigInt::from(hi) << 64usize), value);
        }
    }
}
