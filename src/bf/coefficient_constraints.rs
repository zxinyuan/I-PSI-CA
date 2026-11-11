//! Generic Bulletproof constraints for the power-basis coefficient weights.
//! A randomized integer polynomial identity avoids k modular products for every
//! coefficient. This does not prove any RLWE ciphertext or key-switch relation.
use super::field_constraints::FieldVariable;
use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination as LC, R1CSError, RandomizableConstraintSystem,
    RandomizedConstraintSystem,
};
use curve25519_dalek_ng::scalar::Scalar;
use fhe_math::zq::Modulus;
use num_bigint::BigUint;

fn error(e: impl std::fmt::Display) -> R1CSError {
    R1CSError::GadgetError {
        description: e.to_string(),
    }
}

fn constant<CS: ConstraintSystem>(
    cs: &mut CS,
    modulus: u64,
    value: u64,
    proving: bool,
) -> Result<FieldVariable, R1CSError> {
    let variable = FieldVariable::allocate(cs, modulus, proving.then_some(value))?;
    cs.constrain(LC::from(variable.variable()) - Scalar::from(value));
    Ok(variable)
}

fn scalar(value: &BigUint) -> Result<Scalar, R1CSError> {
    let encoded = value.to_bytes_le();
    if encoded.len() > 32 {
        return Err(error("integer witness exceeds proof field"));
    }
    let mut bytes = [0u8; 32];
    bytes[..encoded.len()].copy_from_slice(&encoded);
    Scalar::from_canonical_bytes(bytes).ok_or_else(|| error("noncanonical integer witness"))
}

fn range_wide<CS: ConstraintSystem>(
    cs: &mut CS,
    assignment: Option<&BigUint>,
    width: usize,
) -> Result<LC, R1CSError> {
    if width > 128 {
        return Err(error(
            "coefficient quotient bound exceeds implementation limit",
        ));
    }
    let encoded = assignment.map(BigUint::to_bytes_le);
    let mut value = LC::default();
    let mut power = Scalar::one();
    for i in 0..width {
        let bit = encoded
            .as_ref()
            .map(|b| Scalar::from(((b.get(i / 8).copied().unwrap_or(0) >> (i % 8)) & 1) as u64));
        let (a, b, c) = cs.allocate_multiplier(bit.map(|bit| (bit, Scalar::one() - bit)))?;
        cs.constrain(c.into());
        cs.constrain(LC::from(a) + b - Scalar::one());
        value = value + power * LC::from(a);
        power += power;
    }
    // Explicit equality also rejects assignments whose high bits were truncated.
    let full = cs.allocate(assignment.map(scalar).transpose()?)?;
    cs.constrain(value.clone() - full);
    Ok(value)
}

fn polynomial_eval(coefficients: &[LC], alpha: Scalar) -> LC {
    coefficients
        .iter()
        .rev()
        .fold(LC::default(), |sum, c| alpha * sum + c.clone())
}

/// Constrains E_j = r * sum_i h_i*x_i^j modulo t, for all j in 0..count.
/// Position and hash variables must be the caller's already-linked variables.
/// The mask is canonically bounded and constrained nonzero here. No value is
/// publicly revealed by this gadget. Public statement binding is the caller's
/// responsibility, as for the other component gadgets.
///
/// For C(X)=product_i(1-x_i X) in F_t[X], E is a recurrence sequence. Its first
/// k terms are computed directly; the remaining terms satisfy C*E=0 modulo t.
/// We prove an integer lift of that recurrence with bounded quotients, using a
/// challenge sampled AFTER all coefficients and quotients have been committed.
/// The extra identity-test error is at most (count+k)/|F_Ristretto|.
pub fn constrain_coefficient_weights<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    positions: &[FieldVariable],
    hashes: &[FieldVariable],
    mask: &FieldVariable,
    count: usize,
) -> Result<Vec<FieldVariable>, R1CSError> {
    let k = positions.len();
    let t = mask.modulus();
    if k == 0
        || k != hashes.len()
        || k > (1 << 20)
        || count == 0
        || count > (1 << 20)
        || positions.iter().chain(hashes).any(|v| v.modulus() != t)
    {
        return Err(error("invalid coefficient-weight dimensions or fields"));
    }
    mask.constrain_nonzero(cs)?;
    let proving = mask.assignment().is_some();
    let modulus = Modulus::new(t).map_err(error)?;
    // Characteristic polynomial, constrained with canonical modular arithmetic.
    let one = constant(cs, t, 1, proving)?;
    let zero = constant(cs, t, 0, proving)?;
    let mut characteristic = vec![one.clone()];
    for position in positions {
        let mut next = vec![one.clone()];
        for j in 1..=characteristic.len() {
            let product = position.multiply(cs, &characteristic[j - 1])?;
            next.push(
                characteristic
                    .get(j)
                    .unwrap_or(&zero)
                    .subtract(cs, &product)?,
            );
        }
        characteristic = next;
    }
    let assignments = positions
        .iter()
        .map(FieldVariable::assignment)
        .collect::<Option<Vec<_>>>()
        .zip(
            hashes
                .iter()
                .map(FieldVariable::assignment)
                .collect::<Option<Vec<_>>>(),
        )
        .zip(mask.assignment())
        .map(|((positions, hashes), r)| {
            let mut powers = vec![1; k];
            (0..count)
                .map(|_| {
                    let mut value = 0;
                    for ((power, &position), &h) in powers.iter_mut().zip(&positions).zip(&hashes) {
                        value = modulus.add(value, modulus.mul(h, *power));
                        *power = modulus.mul(*power, position);
                    }
                    modulus.mul(value, r)
                })
                .collect::<Vec<_>>()
        });
    let values = (0..count)
        .map(|j| FieldVariable::allocate(cs, t, assignments.as_ref().map(|a| a[j])))
        .collect::<Result<Vec<_>, _>>()?;
    // Direct initial conditions rule out a different sequence with the same C.
    let initial_count = k.min(count);
    let mut powers = vec![one; k];
    for expected in values.iter().take(initial_count) {
        let mut sum = zero.clone();
        for i in 0..k {
            let term = hashes[i].multiply(cs, &powers[i])?;
            sum = sum.add(cs, &term)?;
            powers[i] = powers[i].multiply(cs, &positions[i])?;
        }
        let expected_sum = mask.multiply(cs, &sum)?;
        cs.constrain(LC::from(expected.variable()) - expected_sum.variable());
    }
    // Boundary coefficients are computed directly as integer products, rather
    // than accepting an unconstrained low/high residual polynomial.
    let coefficient = |cs: &mut CS, j: usize| -> LC {
        let mut sum = LC::default();
        for (i, c) in characteristic.iter().enumerate() {
            if let Some(e) = j.checked_sub(i).and_then(|index| values.get(index)) {
                sum = sum + cs.multiply(c.variable().into(), e.variable().into()).2;
            }
        }
        sum
    };
    let low = (0..initial_count)
        .map(|j| coefficient(cs, j))
        .collect::<Vec<_>>();
    let high = (count..count + k)
        .map(|j| coefficient(cs, j))
        .collect::<Vec<_>>();
    let characteristic_assignments = characteristic
        .iter()
        .map(FieldVariable::assignment)
        .collect::<Option<Vec<_>>>();
    let quotient_bound = BigUint::from(k + 1) * BigUint::from(t);
    let quotient_width = quotient_bound.bits() as usize;
    let mut quotients = vec![LC::default(); initial_count];
    for j in initial_count..count {
        let assignment = assignments
            .as_ref()
            .zip(characteristic_assignments.as_ref())
            .map(|(e, c)| {
                c.iter()
                    .enumerate()
                    .filter_map(|(i, &c)| {
                        j.checked_sub(i)
                            .map(|index| BigUint::from(c) * BigUint::from(e[index]))
                    })
                    .sum::<BigUint>()
                    / BigUint::from(t)
            });
        quotients.push(range_wide(cs, assignment.as_ref(), quotient_width)?);
    }
    let characteristic = characteristic
        .iter()
        .map(|v| LC::from(v.variable()))
        .collect::<Vec<_>>();
    let sequence = values
        .iter()
        .map(|v| LC::from(v.variable()))
        .collect::<Vec<_>>();
    cs.specify_randomized_constraints(move |cs| {
        let alpha = cs.challenge_scalar(b"bf-coefficient-weight-recurrence-v1");
        let product = cs
            .multiply(
                polynomial_eval(&characteristic, alpha),
                polynomial_eval(&sequence, alpha),
            )
            .2;
        let mut shift = Scalar::one();
        for _ in 0..count {
            shift *= alpha;
        }
        cs.constrain(
            LC::from(product)
                - polynomial_eval(&low, alpha)
                - shift * polynomial_eval(&high, alpha)
                - Scalar::from(t) * polynomial_eval(&quotients, alpha),
        );
        Ok(())
    })?;
    Ok(values)
}

/// Reuses the global coefficient sequence, divides each weight by N in F_t,
/// and reverses/negates nonconstant terms for the negacyclic dot product. All
/// unused entries in the final block are the same constrained-zero variable.
pub fn constrain_packed_weight_blocks<CS: ConstraintSystem>(
    cs: &mut CS,
    weights: &[FieldVariable],
    dimension: usize,
) -> Result<Vec<Vec<FieldVariable>>, R1CSError> {
    let first = weights
        .first()
        .ok_or_else(|| error("empty coefficient sequence"))?;
    let t = first.modulus();
    if !dimension.is_power_of_two()
        || dimension < 2
        || dimension > (1 << 20)
        || weights.iter().any(|v| v.modulus() != t)
    {
        return Err(error("invalid packed weight layout"));
    }
    let inverse = Modulus::new(t)
        .map_err(error)?
        .inv(dimension as u64)
        .ok_or_else(|| error("ring dimension is not invertible in plaintext field"))?;
    let proving = first.assignment().is_some();
    let normalizer = constant(cs, t, inverse, proving)?;
    let zero = constant(cs, t, 0, proving)?;
    weights
        .chunks(dimension)
        .map(|chunk| {
            let mut block = vec![zero.clone(); dimension];
            for (j, weight) in chunk.iter().enumerate() {
                let normalized = weight.multiply(cs, &normalizer)?;
                if j == 0 {
                    block[0] = normalized;
                } else {
                    block[dimension - j] = zero.subtract(cs, &normalized)?;
                }
            }
            Ok(block)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bf::rlwe::BLOOM_PLAINTEXT_MODULUS as T;
    use bulletproofs::{
        r1cs::{Prover, Verifier},
        BulletproofGens, PedersenGens,
    };
    use merlin::Transcript;

    #[test]
    fn recurrence_integer_lifts_initial_conditions_and_tampering() {
        let pc = PedersenGens::default();
        for (positions, hashes, r, count) in [
            (vec![2, 5], vec![13, 29], 31, 64),
            (vec![T - 1, 7], vec![T - 1, T - 2], T - 1, 32),
            (vec![2, 5, 9], vec![0, 11, 0], 13, 2),
            (vec![2], vec![0], 1, 4),
            (vec![2], vec![9], 0, 4),
        ] {
            let mut transcript = Transcript::new(b"coefficient-recurrence-test");
            let mut p = Prover::new(&pc, &mut transcript);
            let positions_vars = positions
                .iter()
                .map(|&v| FieldVariable::allocate(&mut p, T, Some(v)).unwrap())
                .collect::<Vec<_>>();
            let hashes_vars = hashes
                .iter()
                .map(|&v| FieldVariable::allocate(&mut p, T, Some(v)).unwrap())
                .collect::<Vec<_>>();
            let mask = FieldVariable::allocate(&mut p, T, Some(r)).unwrap();
            let values =
                constrain_coefficient_weights(&mut p, &positions_vars, &hashes_vars, &mask, count)
                    .unwrap();
            let mut powers = vec![1u64; positions.len()];
            let expected = (0..count)
                .map(|_| {
                    let mut value = 0u128;
                    for ((power, &position), &hash) in
                        powers.iter_mut().zip(&positions).zip(&hashes)
                    {
                        value = (value + hash as u128 * *power as u128) % T as u128;
                        *power = (*power as u128 * position as u128 % T as u128) as u64;
                    }
                    (value * r as u128 % T as u128) as u64
                })
                .collect::<Vec<_>>();
            for (value, &expected) in values.iter().zip(&expected) {
                assert_eq!(value.assignment(), Some(expected));
                p.constrain(LC::from(value.variable()) - Scalar::from(expected));
            }
            let bp = BulletproofGens::new((p.metrics().multipliers + 8).next_power_of_two(), 1);
            let proof = p.prove(&bp).unwrap();
            for tamper in [false, true] {
                let mut transcript = Transcript::new(b"coefficient-recurrence-test");
                let mut v = Verifier::new(&mut transcript);
                let positions_vars = positions
                    .iter()
                    .map(|_| FieldVariable::allocate(&mut v, T, None).unwrap())
                    .collect::<Vec<_>>();
                let hashes_vars = hashes
                    .iter()
                    .map(|_| FieldVariable::allocate(&mut v, T, None).unwrap())
                    .collect::<Vec<_>>();
                let mask = FieldVariable::allocate(&mut v, T, None).unwrap();
                let values = constrain_coefficient_weights(
                    &mut v,
                    &positions_vars,
                    &hashes_vars,
                    &mask,
                    count,
                )
                .unwrap();
                for (j, (value, &expected)) in values.iter().zip(&expected).enumerate() {
                    let expected = if tamper && j == count - 1 {
                        (expected + 1) % T
                    } else {
                        expected
                    };
                    v.constrain(LC::from(value.variable()) - Scalar::from(expected));
                }
                assert_eq!(v.verify(&proof, &pc, &bp).is_ok(), !tamper && r != 0);
            }
        }
    }

    #[test]
    fn packed_layout_proves_normalization_reversal_and_final_padding() {
        let pc = PedersenGens::default();
        let expected = (1..=17).map(|x| x * 101).collect::<Vec<u64>>();
        let mut t = Transcript::new(b"packed-weight-layout-test");
        let mut p = Prover::new(&pc, &mut t);
        let values = expected
            .iter()
            .map(|&x| FieldVariable::allocate(&mut p, T, Some(x)).unwrap())
            .collect::<Vec<_>>();
        let blocks = constrain_packed_weight_blocks(&mut p, &values, 8).unwrap();
        let inv = Modulus::new(T).unwrap().inv(8).unwrap();
        let mut expected_blocks = vec![vec![0u64; 8]; 3];
        for (global, &value) in expected.iter().enumerate() {
            let normalized = (value as u128 * inv as u128 % T as u128) as u64;
            let j = global % 8;
            expected_blocks[global / 8][if j == 0 { 0 } else { 8 - j }] =
                if j == 0 || normalized == 0 {
                    normalized
                } else {
                    T - normalized
                };
        }
        for (block, expected) in blocks.iter().zip(&expected_blocks) {
            for (variable, &expected) in block.iter().zip(expected) {
                assert_eq!(variable.assignment(), Some(expected));
                p.constrain(LC::from(variable.variable()) - Scalar::from(expected));
            }
        }
        let bp = BulletproofGens::new((p.metrics().multipliers + 8).next_power_of_two(), 1);
        let proof = p.prove(&bp).unwrap();
        for tamper in [false, true] {
            let mut t = Transcript::new(b"packed-weight-layout-test");
            let mut v = Verifier::new(&mut t);
            let values = expected
                .iter()
                .map(|_| FieldVariable::allocate(&mut v, T, None).unwrap())
                .collect::<Vec<_>>();
            let blocks = constrain_packed_weight_blocks(&mut v, &values, 8).unwrap();
            for (i, (block, expected)) in blocks.iter().zip(&expected_blocks).enumerate() {
                for (j, (variable, &expected)) in block.iter().zip(expected).enumerate() {
                    let expected = if tamper && i == 2 && j == 1 {
                        1
                    } else {
                        expected
                    };
                    v.constrain(LC::from(variable.variable()) - Scalar::from(expected));
                }
            }
            assert_eq!(v.verify(&proof, &pc, &bp).is_ok(), !tamper);
        }
    }
}
