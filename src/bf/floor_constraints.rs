//! Exact terminal floor constraints across RNS limbs. Wide remainders are
//! constrained as bits/64-bit limbs, never reduced into one Ristretto scalar.
use super::field_constraints::{range, FieldVariable};
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination as LC, R1CSError};
use curve25519_dalek_ng::scalar::Scalar;
use fhe_math::{rns::RnsContext, zq::Modulus};
use num_bigint::BigUint;

fn error(e: impl std::fmt::Display) -> R1CSError {
    R1CSError::GadgetError {
        description: e.to_string(),
    }
}

fn less_than_big<CS: ConstraintSystem>(cs: &mut CS, bits: &[LC], bound: &BigUint) -> LC {
    let mut equal = LC::from(Scalar::one());
    let mut less = LC::default();
    for i in (0..bits.len()).rev() {
        if bound.bit(i as u64) {
            less = less
                + cs.multiply(equal.clone(), LC::from(Scalar::one()) - bits[i].clone())
                    .2;
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

fn public<CS: ConstraintSystem>(
    cs: &mut CS,
    q: u64,
    value: u64,
    proving: bool,
) -> Result<FieldVariable, R1CSError> {
    let variable = FieldVariable::allocate(cs, q, proving.then_some(value))?;
    cs.constrain(LC::from(variable.variable()) - Scalar::from(value));
    Ok(variable)
}

fn chunk_residue<CS: ConstraintSystem>(
    cs: &mut CS,
    bits: &[LC],
    assignment: Option<u64>,
    q: u64,
) -> Result<FieldVariable, R1CSError> {
    let integer = bits
        .iter()
        .enumerate()
        .fold(LC::default(), |sum, (i, bit)| {
            sum + Scalar::from(1u64 << i) * bit.clone()
        });
    let residue = FieldVariable::allocate(cs, q, assignment.map(|a| a % q))?;
    let quotient = cs.allocate(assignment.map(|a| Scalar::from(a / q)))?;
    let max = if bits.len() == 64 {
        u64::MAX
    } else {
        (1u64 << bits.len()) - 1
    };
    let max_quotient = max / q;
    let width = (64 - max_quotient.leading_zeros()) as usize;
    range(cs, quotient.into(), assignment.map(|a| a / q), width)?;
    cs.constrain(integer - residue.variable() - Scalar::from(q) * LC::from(quotient));
    Ok(residue)
}

/// For ONE ciphertext-component coefficient, prove
/// output = floor(C / D), D=product(discarded primes), where C is represented
/// by the caller's canonical private source RNS variables. The output is public
/// in the retained RNS basis. Every source variable must be linked to the
/// actual BFV evaluation/rerandomization proof by the caller.
///
/// R<D and the canonical retained output imply 0<=D*output+R<Q. Equal residues
/// in every coprime input limb therefore prove an integer equality by CRT.
pub fn constrain_terminal_floor<CS: ConstraintSystem>(
    cs: &mut CS,
    source: &[FieldVariable],
    moduli: &[u64],
    output: &[u64],
) -> Result<(), R1CSError> {
    if source.len() != moduli.len()
        || output.is_empty()
        || output.len() >= moduli.len()
        || moduli.len() > 16
        || moduli.iter().any(|&q| !(2..(1u64 << 62)).contains(&q))
        || source.iter().zip(moduli).any(|(v, &q)| v.modulus() != q)
        || output.iter().zip(moduli).any(|(&value, &q)| value >= q)
    {
        return Err(error("invalid terminal-floor RNS statement"));
    }
    let context = RnsContext::new(moduli).map_err(error)?;
    let divisor: BigUint = moduli[output.len()..]
        .iter()
        .map(|&q| BigUint::from(q))
        .product();
    let assignment = source
        .iter()
        .map(FieldVariable::assignment)
        .collect::<Option<Vec<_>>>()
        .map(|values| context.lift(values.as_slice().into()) % &divisor);
    let digits = assignment.as_ref().map(BigUint::to_u64_digits);
    let width = divisor.bits() as usize;
    let mut bits = Vec::with_capacity(width);
    for offset in (0..width).step_by(64) {
        let count = (width - offset).min(64);
        let value = digits
            .as_ref()
            .map(|digits| digits.get(offset / 64).copied().unwrap_or(0));
        let variable = cs.allocate(value.map(Scalar::from))?;
        bits.extend(range(cs, variable.into(), value, count)?);
    }
    let valid = less_than_big(cs, &bits, &divisor);
    cs.constrain(valid - Scalar::one());
    for (i, (&q, source)) in moduli.iter().zip(source).enumerate() {
        let arithmetic = Modulus::new(q).map_err(error)?;
        // 2^64 is wider than a u64; reduce it in the library without truncation.
        let base = arithmetic.mul(arithmetic.reduce(1u64 << 32), arithmetic.reduce(1u64 << 32));
        let base = public(cs, q, base, assignment.is_some())?;
        let mut residue = public(cs, q, 0, assignment.is_some())?;
        for (index, chunk) in bits.chunks(64).enumerate().rev() {
            residue = residue.multiply(cs, &base)?;
            let chunk = chunk_residue(
                cs,
                chunk,
                digits.as_ref().map(|d| d.get(index).copied().unwrap_or(0)),
                q,
            )?;
            residue = residue.add(cs, &chunk)?;
        }
        let divisor_residue = (&divisor % BigUint::from(q))
            .to_u64_digits()
            .first()
            .copied()
            .unwrap_or(0);
        let output_residue = output.get(i).copied().unwrap_or(0);
        // D is divisible by each discarded prime, so its contribution is zero
        // there; only the retained output residues need to be supplied.
        let constant = public(
            cs,
            q,
            arithmetic.mul(divisor_residue, output_residue),
            assignment.is_some(),
        )?;
        let reconstructed = residue.add(cs, &constant)?;
        cs.constrain(LC::from(source.variable()) - reconstructed.variable());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::{
        r1cs::{Prover, Verifier},
        BulletproofGens, PedersenGens,
    };
    use merlin::Transcript;
    use rand::rngs::OsRng;

    #[test]
    fn seven_limb_floor_integer_binding_and_output_tampering() {
        let moduli = [
            4611686018427322369,
            4611686018427289601,
            4611686018425815041,
            4611686018424733697,
            4611686018423881729,
            4611686018423390209,
            4611686018423062529,
        ];
        let divisor: BigUint = moduli[2..].iter().map(|&q| BigUint::from(q)).product();
        assert!(divisor.bits() > 252);
        let retained: BigUint = moduli[..2].iter().map(|&q| BigUint::from(q)).product();
        let residues = |value: &BigUint| {
            moduli
                .iter()
                .map(|&q| {
                    (value % BigUint::from(q))
                        .to_u64_digits()
                        .first()
                        .copied()
                        .unwrap_or(0)
                })
                .collect::<Vec<_>>()
        };
        let pc = PedersenGens::default();
        for (quotient, remainder) in [
            (BigUint::from(0u8), BigUint::from(0u8)),
            (BigUint::from(19u8), &divisor - BigUint::from(1u8)),
            (&retained - BigUint::from(1u8), BigUint::from(1u8)),
        ] {
            let source = residues(&(&quotient * &divisor + &remainder));
            let output = residues(&quotient)[..2].to_vec();
            let mut t = Transcript::new(b"bf-terminal-floor-proof-test-v1");
            let mut p = Prover::new(&pc, &mut t);
            let mut commitments = Vec::new();
            let mut variables = Vec::new();
            for (&q, &value) in moduli.iter().zip(&source) {
                let (c, v) = p.commit(Scalar::from(value), Scalar::random(&mut OsRng));
                commitments.push(c);
                variables.push(FieldVariable::constrain(&mut p, v, q, Some(value)).unwrap());
            }
            constrain_terminal_floor(&mut p, &variables, &moduli, &output).unwrap();
            let bp = BulletproofGens::new(p.metrics().multipliers.next_power_of_two(), 1);
            let proof = p.prove(&bp).unwrap();
            for tamper in [false, true] {
                let mut t = Transcript::new(b"bf-terminal-floor-proof-test-v1");
                let mut v = Verifier::new(&mut t);
                let mut variables = Vec::new();
                for (&q, &commitment) in moduli.iter().zip(&commitments) {
                    let variable = v.commit(commitment);
                    variables.push(FieldVariable::constrain(&mut v, variable, q, None).unwrap());
                }
                let mut output = output.clone();
                if tamper {
                    output[0] = (output[0] + 1) % moduli[0];
                }
                constrain_terminal_floor(&mut v, &variables, &moduli, &output).unwrap();
                assert_eq!(v.verify(&proof, &pc, &bp).is_ok(), !tamper);
            }
        }
    }
}
