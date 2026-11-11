//! Integer-lift constraints for the BFV plaintext field inside Ristretto R1CS.
//! Every product is below 2^124, far below the Ristretto scalar modulus.
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination as LC, R1CSError, Variable};
use curve25519_dalek_ng::scalar::Scalar;

fn error(message: &str) -> R1CSError {
    R1CSError::GadgetError {
        description: message.into(),
    }
}

pub(crate) fn range<CS: ConstraintSystem>(
    cs: &mut CS,
    value: LC,
    assignment: Option<u64>,
    width: usize,
) -> Result<Vec<LC>, R1CSError> {
    if width > 64 {
        return Err(error("integer range exceeds 64 bits"));
    }
    let mut sum = LC::default();
    let mut bits = Vec::with_capacity(width);
    for i in 0..width {
        let (bit, complement, product) = cs.allocate_multiplier(assignment.map(|x| {
            let bit = Scalar::from((x >> i) & 1);
            (bit, Scalar::one() - bit)
        }))?;
        cs.constrain(product.into());
        cs.constrain(LC::from(bit) + complement - Scalar::one());
        sum = sum + Scalar::from(1u64 << i) * LC::from(bit);
        bits.push(bit.into());
    }
    cs.constrain(sum - value);
    Ok(bits)
}

/// Returns a Boolean expression for x < bound. Input bits must be Boolean and
/// in little-endian order; callers obtain them from range() or SHA constraints.
pub(crate) fn less_than<CS: ConstraintSystem>(cs: &mut CS, bits: &[LC], bound: u64) -> LC {
    let mut equal = LC::from(Scalar::one());
    let mut less = LC::default();
    for i in (0..bits.len()).rev() {
        if (bound >> i) & 1 == 1 {
            let lower = cs
                .multiply(equal.clone(), LC::from(Scalar::one()) - bits[i].clone())
                .2;
            less = less + lower;
            equal = cs.multiply(equal, bits[i].clone()).2.into();
        } else {
            equal = cs
                .multiply(equal, LC::from(Scalar::one()) - bits[i].clone())
                .2
                .into();
        }
    }
    less
}

/// A canonically bounded integer in the stated plaintext field. Private fields
/// prevent constructing this type from an unconstrained Ristretto scalar.
#[derive(Clone)]
pub struct FieldVariable {
    variable: Variable,
    modulus: u64,
    assignment: Option<u64>,
}

impl FieldVariable {
    pub fn variable(&self) -> Variable {
        self.variable
    }
    pub fn assignment(&self) -> Option<u64> {
        self.assignment
    }
    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    pub fn allocate<CS: ConstraintSystem>(
        cs: &mut CS,
        modulus: u64,
        assignment: Option<u64>,
    ) -> Result<Self, R1CSError> {
        let variable = cs.allocate(assignment.map(Scalar::from))?;
        Self::constrain(cs, variable, modulus, assignment)
    }

    /// Constrain the caller's existing variable, including shared commitments.
    pub fn constrain<CS: ConstraintSystem>(
        cs: &mut CS,
        variable: Variable,
        modulus: u64,
        assignment: Option<u64>,
    ) -> Result<Self, R1CSError> {
        if !(2..(1u64 << 62)).contains(&modulus) {
            return Err(error("plaintext modulus must be between 2 and 2^62"));
        }
        let width = (64 - modulus.leading_zeros()) as usize;
        let bits = range(cs, variable.into(), assignment, width)?;
        let valid = less_than(cs, &bits, modulus);
        cs.constrain(valid - Scalar::one());
        Ok(Self {
            variable,
            modulus,
            assignment,
        })
    }

    pub fn add<CS: ConstraintSystem>(&self, cs: &mut CS, rhs: &Self) -> Result<Self, R1CSError> {
        if self.modulus != rhs.modulus {
            return Err(error("plaintext fields differ"));
        }
        let sum = self.assignment.zip(rhs.assignment).map(|(a, b)| a + b);
        let result = Self::allocate(cs, self.modulus, sum.map(|v| v % self.modulus))?;
        let quotient = cs.allocate(sum.map(|v| Scalar::from(v / self.modulus)))?;
        range(cs, quotient.into(), sum.map(|v| v / self.modulus), 1)?;
        cs.constrain(
            LC::from(self.variable) + rhs.variable
                - result.variable
                - Scalar::from(self.modulus) * LC::from(quotient),
        );
        Ok(result)
    }

    pub fn subtract<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        rhs: &Self,
    ) -> Result<Self, R1CSError> {
        if self.modulus != rhs.modulus {
            return Err(error("plaintext fields differ"));
        }
        let difference = self
            .assignment
            .zip(rhs.assignment)
            .map(|(a, b)| (a + self.modulus - b, (a < b) as u64));
        let result = Self::allocate(cs, self.modulus, difference.map(|(v, _)| v % self.modulus))?;
        let quotient = cs.allocate(difference.map(|(_, q)| Scalar::from(q)))?;
        range(cs, quotient.into(), difference.map(|(_, q)| q), 1)?;
        cs.constrain(
            LC::from(self.variable) - rhs.variable - result.variable
                + Scalar::from(self.modulus) * LC::from(quotient),
        );
        Ok(result)
    }

    /// Ranges make this an integer equality, not merely equality modulo l.
    pub fn multiply<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
        rhs: &Self,
    ) -> Result<Self, R1CSError> {
        if self.modulus != rhs.modulus {
            return Err(error("plaintext fields differ"));
        }
        let value = self
            .assignment
            .zip(rhs.assignment)
            .map(|(a, b)| a as u128 * b as u128);
        let result = Self::allocate(
            cs,
            self.modulus,
            value.map(|v| (v % self.modulus as u128) as u64),
        )?;
        // Canonical inputs and result already imply q < modulus. A bit bound
        // prevents scalar-field wrap; a second comparison with modulus adds no
        // soundness and used to duplicate most of the reduction work.
        let quotient_assignment = value.map(|v| (v / self.modulus as u128) as u64);
        let quotient = cs.allocate(quotient_assignment.map(Scalar::from))?;
        range(
            cs,
            quotient.into(),
            quotient_assignment,
            (64 - self.modulus.leading_zeros()) as usize,
        )?;
        let product = cs.multiply(self.variable.into(), rhs.variable.into()).2;
        cs.constrain(
            LC::from(product) - result.variable - Scalar::from(self.modulus) * LC::from(quotient),
        );
        Ok(result)
    }

    /// Reduce an entire integer dot product once. Its integer bound is checked
    /// structurally on both prover and verifier, so no term can wrap F_l.
    pub fn sum_products<CS: ConstraintSystem>(
        cs: &mut CS,
        left: &[Self],
        right: &[Self],
    ) -> Result<Self, R1CSError> {
        if left.is_empty() || left.len() != right.len() {
            return Err(error("invalid field dot product"));
        }
        let modulus = left[0].modulus;
        if left.iter().chain(right).any(|v| v.modulus != modulus) {
            return Err(error("plaintext fields differ"));
        }
        let bound = (modulus as u128 - 1)
            .checked_mul(modulus as u128 - 1)
            .and_then(|v| v.checked_mul(left.len() as u128))
            .ok_or_else(|| error("field dot product exceeds integer budget"))?;
        let max_q = u64::try_from(bound / modulus as u128)
            .map_err(|_| error("field dot product quotient exceeds 64 bits"))?;
        let assignment = left.iter().zip(right).try_fold(0u128, |sum, (a, b)| {
            Some(sum + a.assignment? as u128 * b.assignment? as u128)
        });
        let result = Self::allocate(
            cs,
            modulus,
            assignment.map(|v| (v % modulus as u128) as u64),
        )?;
        let q_assignment = assignment.map(|v| (v / modulus as u128) as u64);
        let q = cs.allocate(q_assignment.map(Scalar::from))?;
        range(
            cs,
            q.into(),
            q_assignment,
            (64 - max_q.leading_zeros()) as usize,
        )?;
        let mut sum = LC::default();
        for (a, b) in left.iter().zip(right) {
            sum = sum + cs.multiply(a.variable.into(), b.variable.into()).2;
        }
        cs.constrain(sum - result.variable - Scalar::from(modulus) * LC::from(q));
        Ok(result)
    }

    pub fn constrain_nonzero<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<(), R1CSError> {
        let inverse = cs.allocate(self.assignment.map(|v| Scalar::from(v).invert()))?;
        let product = cs.multiply(self.variable.into(), inverse.into()).2;
        cs.constrain(LC::from(product) - Scalar::one());
        Ok(())
    }
}

/// Select the first accepted SHA candidate, with the native rejection threshold,
/// and constrain its canonical residue. All candidates are constrained SHA bits.
pub(crate) fn reduce_candidates<CS: ConstraintSystem>(
    cs: &mut CS,
    candidates: &[Vec<LC>],
    assignments: Option<&[u64]>,
    modulus: u64,
) -> Result<FieldVariable, R1CSError> {
    if !(2..(1u64 << 62)).contains(&modulus)
        || candidates.is_empty()
        || candidates.iter().any(|b| b.len() != 64)
        || assignments.is_some_and(|a| a.len() != candidates.len())
    {
        return Err(error("invalid rejection-sampling dimensions"));
    }
    let limit = u64::MAX - u64::MAX % modulus;
    let selected_assignment = assignments.and_then(|a| a.iter().copied().find(|&x| x < limit));
    let mut unselected = LC::from(Scalar::one());
    let mut selected = LC::default();
    for bits in candidates {
        let accept = less_than(cs, bits, limit);
        let select = cs.multiply(unselected.clone(), accept).2;
        unselected = unselected - select;
        let value = bits.iter().enumerate().fold(LC::default(), |sum, (i, b)| {
            sum + Scalar::from(1u64 << i) * b.clone()
        });
        selected = selected + cs.multiply(select.into(), value).2;
    }
    // Fixed shape conceals the retry index. Exhaustion rejects; it never changes
    // the mapping to a biased residue or accepts a later-than-first candidate.
    cs.constrain(unselected);
    let result = FieldVariable::allocate(cs, modulus, selected_assignment.map(|v| v % modulus))?;
    let quotient = cs.allocate(selected_assignment.map(|v| Scalar::from(v / modulus)))?;
    let max_quotient = limit / modulus - 1;
    let width = (64 - max_quotient.leading_zeros()) as usize;
    range(
        cs,
        quotient.into(),
        selected_assignment.map(|v| v / modulus),
        width,
    )?;
    cs.constrain(selected - result.variable - Scalar::from(modulus) * LC::from(quotient));
    Ok(result)
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
    fn integer_products_ranges_and_nonzero_masks() {
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(2048, 1);
        for (a, b, expected, nonzero, valid) in [
            (T - 1, T - 1, 1, true, true),
            (T - 1, T - 2, 2, true, true),
            (0, 7, 0, false, true),
            (0, 7, 0, true, false),
            (T, 1, 0, false, false),
            (T - 1, T - 1, 2, false, false),
            (u64::MAX, 1, u64::MAX % T, false, false),
        ] {
            let mut t = Transcript::new(b"integer-products-test");
            let mut p = Prover::new(&pc, &mut t);
            let x = FieldVariable::allocate(&mut p, T, Some(a)).unwrap();
            let y = FieldVariable::allocate(&mut p, T, Some(b)).unwrap();
            if nonzero {
                x.constrain_nonzero(&mut p).unwrap();
            }
            let z = x.multiply(&mut p, &y).unwrap();
            p.constrain(LC::from(z.variable()) - Scalar::from(expected));
            let proof = p.prove(&bp).unwrap();
            let mut t = Transcript::new(b"integer-products-test");
            let mut v = Verifier::new(&mut t);
            let x = FieldVariable::allocate(&mut v, T, None).unwrap();
            let y = FieldVariable::allocate(&mut v, T, None).unwrap();
            if nonzero {
                x.constrain_nonzero(&mut v).unwrap();
            }
            let z = x.multiply(&mut v, &y).unwrap();
            v.constrain(LC::from(z.variable()) - Scalar::from(expected));
            assert_eq!(v.verify(&proof, &pc, &bp).is_ok(), valid, "a={a}, b={b}");
        }
    }

    #[test]
    fn dot_product_reduces_once_and_rejects_false_results() {
        let t = crate::bf::rlwe::PROTOCOL_PLAINTEXT_MODULUS;
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(16384, 1);
        for forged in [false, true] {
            let mut transcript = Transcript::new(b"batched-field-dot");
            let mut p = Prover::new(&pc, &mut transcript);
            let a = (0..20)
                .map(|_| FieldVariable::allocate(&mut p, t, Some(t - 1)).unwrap())
                .collect::<Vec<_>>();
            let b = (0..20)
                .map(|_| FieldVariable::allocate(&mut p, t, Some(t - 2)).unwrap())
                .collect::<Vec<_>>();
            for input in &a {
                p.constrain(LC::from(input.variable()) - Scalar::from(t - 1));
            }
            for input in &b {
                p.constrain(LC::from(input.variable()) - Scalar::from(t - 2));
            }
            let before = p.metrics().multipliers;
            let result = FieldVariable::sum_products(&mut p, &a, &b).unwrap();
            assert!(
                p.metrics().multipliers - before < 500,
                "dot products must not reduce every term separately"
            );
            let expected = 40 + u64::from(forged);
            p.constrain(LC::from(result.variable()) - Scalar::from(expected));
            let proof = p.prove(&bp).unwrap();
            let mut transcript = Transcript::new(b"batched-field-dot");
            let mut v = Verifier::new(&mut transcript);
            let a = (0..20)
                .map(|_| FieldVariable::allocate(&mut v, t, None).unwrap())
                .collect::<Vec<_>>();
            let b = (0..20)
                .map(|_| FieldVariable::allocate(&mut v, t, None).unwrap())
                .collect::<Vec<_>>();
            // Bind the private test inputs, so another dot product cannot satisfy
            // the forged public result.
            for input in &a {
                v.constrain(LC::from(input.variable()) - Scalar::from(t - 1));
            }
            for input in &b {
                v.constrain(LC::from(input.variable()) - Scalar::from(t - 2));
            }
            let result = FieldVariable::sum_products(&mut v, &a, &b).unwrap();
            v.constrain(LC::from(result.variable()) - Scalar::from(expected));
            assert_eq!(v.verify(&proof, &pc, &bp).is_ok(), !forged);
        }
    }

    #[test]
    fn rejection_threshold_first_candidate_and_exhaustion() {
        let limit = u64::MAX - u64::MAX % T;
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(2048, 1);
        for (candidates, expected, valid) in [
            ([limit, 17, 29, 41], 17, true),
            ([limit, 17, 29, 41], 29, false),
            ([limit - 1, 17, 29, 41], T - 1, true),
            ([limit, u64::MAX, 29, 41], 29, true),
            ([limit, u64::MAX, 29, 41], 41, false),
            ([limit, limit, limit, 41], 41, true),
            ([0, 17, 29, 41], 0, true),
            ([limit, limit, limit, limit], 0, false),
        ] {
            let mut t = Transcript::new(b"first-valid-candidate-test");
            let mut p = Prover::new(&pc, &mut t);
            let bits = candidates
                .iter()
                .map(|&x| range(&mut p, Scalar::from(x).into(), Some(x), 64).unwrap())
                .collect::<Vec<_>>();
            // Assign zero in the exhausted case to produce an unsatisfied proof
            // rather than missing-witness failure, and test the actual verifier.
            let assignment = if valid || candidates.iter().any(|&x| x < limit) {
                candidates
            } else {
                [0, 0, 0, 0]
            };
            let h = reduce_candidates(&mut p, &bits, Some(&assignment), T).unwrap();
            p.constrain(LC::from(h.variable()) - Scalar::from(expected));
            let proof = p.prove(&bp).unwrap();
            let mut t = Transcript::new(b"first-valid-candidate-test");
            let mut v = Verifier::new(&mut t);
            let bits = candidates
                .iter()
                .map(|&x| range(&mut v, Scalar::from(x).into(), None, 64).unwrap())
                .collect::<Vec<_>>();
            let h = reduce_candidates(&mut v, &bits, None, T).unwrap();
            v.constrain(LC::from(h.variable()) - Scalar::from(expected));
            assert_eq!(
                v.verify(&proof, &pc, &bp).is_ok(),
                valid,
                "candidates={candidates:?}"
            );
        }
    }
}
