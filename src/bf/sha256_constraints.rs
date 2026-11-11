//! Existing Arkworks SHA-256 constraints translated into the Bulletproof R1CS.
//! Arkworks is a constraint frontend here, not a separate proof backend.
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    bits::{uint8::UInt8, ToBitsGadget},
    R1CSVar,
};
use ark_relations::r1cs::{
    ConstraintSystem as ArkCS, ConstraintSystemRef, LinearCombination as ArkLC, SynthesisError,
    SynthesisMode, Variable as ArkVariable,
};
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError, Variable};
use curve25519_dalek_ng::scalar::Scalar;

// ark-ff 0.4's derive emits these two legacy lints; arithmetic stays entirely
// in the library, over exactly the existing Ristretto scalar modulus.
#[allow(unexpected_cfgs, non_local_definitions)]
mod field {
    use ark_ff::{Fp256, MontBackend, MontConfig};
    #[derive(MontConfig)]
    #[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
    #[generator = "2"]
    pub struct Config;
    pub type Fr = Fp256<MontBackend<Config, 4>>;
}
pub(crate) type F = field::Fr;

fn error(e: impl std::fmt::Display) -> R1CSError {
    R1CSError::GadgetError {
        description: e.to_string(),
    }
}

pub(crate) fn scalar(value: F) -> Result<Scalar, R1CSError> {
    let encoded = value.into_bigint().to_bytes_le();
    let mut bytes = [0u8; 32];
    bytes[..encoded.len()].copy_from_slice(&encoded);
    Scalar::from_canonical_bytes(bytes).ok_or_else(|| error("incompatible constraint fields"))
}

pub enum ShaByte {
    Constant(u8),
    /// The assignment is only for proving; equality to expression is constrained.
    Private {
        expression: LinearCombination,
        assignment: Option<u8>,
    },
}

pub struct ShaDigest {
    pub bytes: Vec<LinearCombination>,
    /// Little-endian bit order inside each byte, with SHA's standard byte order.
    pub bits: Vec<Vec<LinearCombination>>,
    pub assignment: Option<Vec<u8>>,
}

pub(crate) struct ShaCircuit {
    pub(crate) cs: ConstraintSystemRef<F>,
    bindings: Vec<(ArkLC<F>, LinearCombination)>,
}

impl ShaCircuit {
    pub(crate) fn bind_field(
        &mut self,
        value: &ark_r1cs_std::fields::fp::FpVar<F>,
        external: LinearCombination,
    ) -> Result<(), R1CSError> {
        use ark_r1cs_std::eq::EqGadget;
        use ark_r1cs_std::fields::fp::FpVar;
        // Sponge outputs can be symbolic linear combinations. Materialize an
        // equality-constrained witness before finalize() inlines those LCs.
        let witness = FpVar::new_witness(self.cs.clone(), || value.value()).map_err(error)?;
        witness.enforce_equal(value).map_err(error)?;
        if let FpVar::Var(v) = witness {
            self.bindings.push((ArkLC::from(v.variable), external));
        }
        Ok(())
    }
    pub(crate) fn field_input(
        &mut self,
        expression: LinearCombination,
        assignment: Option<Scalar>,
    ) -> Result<ark_r1cs_std::fields::fp::FpVar<F>, R1CSError> {
        use ark_r1cs_std::fields::fp::FpVar;
        let variable = FpVar::new_witness(self.cs.clone(), || {
            assignment
                .map(|a| F::from_le_bytes_mod_order(&a.to_bytes()))
                .ok_or(SynthesisError::AssignmentMissing)
        })
        .map_err(error)?;
        if let FpVar::Var(value) = &variable {
            self.bindings
                .push((ArkLC::from(value.variable), expression));
        }
        Ok(variable)
    }
    pub(crate) fn new(proving: bool) -> Self {
        let cs = ArkCS::<F>::new_ref();
        if !proving {
            cs.set_mode(SynthesisMode::Setup);
        }
        Self {
            cs,
            bindings: Vec::new(),
        }
    }

    pub(crate) fn input(&mut self, bytes: &[ShaByte]) -> Result<Vec<UInt8<F>>, R1CSError> {
        bytes
            .iter()
            .map(|byte| match byte {
                ShaByte::Constant(value) => Ok(UInt8::constant(*value)),
                ShaByte::Private {
                    expression,
                    assignment,
                } => {
                    let byte = UInt8::new_witness(self.cs.clone(), || {
                        assignment.ok_or(SynthesisError::AssignmentMissing)
                    })
                    .map_err(error)?;
                    let encoded = byte
                        .to_bits_le()
                        .map_err(error)?
                        .iter()
                        .enumerate()
                        .fold(ArkLC::zero(), |sum, (i, bit)| {
                            sum + (F::from(1u64 << i), &bit.lc())
                        });
                    self.bindings.push((encoded, expression.clone()));
                    Ok(byte)
                }
            })
            .collect()
    }

    /// Import every generated constraint and witness without changing fields.
    /// External inputs are linked by equality constraints, including on verifier.
    pub(crate) fn finish<CS: ConstraintSystem>(
        self,
        cs: &mut CS,
        digests: Vec<Vec<UInt8<F>>>,
    ) -> Result<Vec<ShaDigest>, R1CSError> {
        self.cs.finalize();
        let matrices = self
            .cs
            .to_matrices()
            .ok_or_else(|| error("missing SHA constraint matrices"))?;
        if matrices.num_instance_variables != 1 {
            return Err(error("unexpected SHA public variables"));
        }
        let assignments = self
            .cs
            .borrow()
            .ok_or_else(|| error("missing SHA constraint system"))?
            .witness_assignment
            .clone();
        // Resolve source wires on demand. When an Ark multiplication creates a
        // new output witness, reuse the Bulletproof output wire instead of
        // allocating a duplicate witness and proving their equality afterward.
        let mut imported = vec![None; matrices.num_witness_variables];
        for ((a, b), c) in matrices.a.iter().zip(&matrices.b).zip(&matrices.c) {
            let left = import_row(cs, a, &mut imported, &assignments)?;
            let right = import_row(cs, b, &mut imported, &assignments)?;
            let constant = |row: &[(F, usize)]| -> Result<Option<Scalar>, R1CSError> {
                if row.iter().any(|(_, i)| *i != 0) {
                    return Ok(None);
                }
                Ok(Some(
                    row.iter().try_fold(Scalar::zero(), |sum, (v, _)| {
                        Ok::<_, R1CSError>(sum + scalar(*v)?)
                    })?,
                ))
            };
            if let Some(value) = constant(a)? {
                let output = import_row(cs, c, &mut imported, &assignments)?;
                cs.constrain(value * right - output);
            } else if let Some(value) = constant(b)? {
                let output = import_row(cs, c, &mut imported, &assignments)?;
                cs.constrain(value * left - output);
            } else {
                let product = cs.multiply(left, right).2;
                if c.len() == 1
                    && c[0].0 == F::from(1u64)
                    && c[0].1 > 0
                    && imported[c[0].1 - 1].is_none()
                {
                    imported[c[0].1 - 1] = Some(product);
                } else {
                    let output = import_row(cs, c, &mut imported, &assignments)?;
                    cs.constrain(LinearCombination::from(product) - output);
                }
            }
        }
        let variables = imported
            .into_iter()
            .enumerate()
            .map(|(i, v)| match v {
                Some(v) => Ok(v),
                None => cs.allocate(assignments.get(i).copied().map(scalar).transpose()?),
            })
            .collect::<Result<Vec<_>, R1CSError>>()?;
        for (encoded, external) in self.bindings {
            cs.constrain(convert_lc(&encoded, &variables)? - external);
        }
        digests
            .into_iter()
            .map(|digest| {
                let assignment = digest
                    .iter()
                    .map(|b| b.value().ok())
                    .collect::<Option<Vec<_>>>();
                let bits = digest
                    .iter()
                    .map(|byte| {
                        byte.to_bits_le()
                            .map_err(error)?
                            .iter()
                            .map(|bit| convert_lc(&bit.lc(), &variables))
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let bytes = bits
                    .iter()
                    .map(|bits| {
                        bits.iter()
                            .enumerate()
                            .fold(LinearCombination::default(), |sum, (i, bit)| {
                                sum + Scalar::from(1u64 << i) * bit.clone()
                            })
                    })
                    .collect();
                Ok(ShaDigest {
                    bytes,
                    bits,
                    assignment,
                })
            })
            .collect()
    }
}

fn import_row<CS: ConstraintSystem>(
    cs: &mut CS,
    row: &[(F, usize)],
    variables: &mut [Option<Variable>],
    assignments: &[F],
) -> Result<LinearCombination, R1CSError> {
    row.iter()
        .try_fold(LinearCombination::default(), |sum, (coefficient, index)| {
            let term = if *index == 0 {
                LinearCombination::from(Scalar::one())
            } else {
                let slot = variables
                    .get_mut(index - 1)
                    .ok_or_else(|| error("invalid imported witness index"))?;
                let variable = if let Some(v) = *slot {
                    v
                } else {
                    let v = cs.allocate(
                        assignments
                            .get(index - 1)
                            .copied()
                            .map(scalar)
                            .transpose()?,
                    )?;
                    *slot = Some(v);
                    v
                };
                variable.into()
            };
            Ok(sum + scalar(*coefficient)? * term)
        })
}

fn convert_lc(lc: &ArkLC<F>, variables: &[Variable]) -> Result<LinearCombination, R1CSError> {
    lc.0.iter().try_fold(
        LinearCombination::default(),
        |sum, &(coefficient, variable)| {
            let term = match variable {
                ArkVariable::Zero => LinearCombination::default(),
                ArkVariable::One => LinearCombination::from(Scalar::one()),
                ArkVariable::Witness(index) => LinearCombination::from(
                    *variables
                        .get(index)
                        .ok_or_else(|| error("invalid SHA witness variable"))?,
                ),
                _ => return Err(error("unexpected SHA symbolic/public variable")),
            };
            Ok(sum + scalar(coefficient)? * term)
        },
    )
}

/// SHA-256 over constants and private byte expressions in the caller's R1CS.
/// The caller must bind its public statement to its Merlin transcript.
pub fn constrain_sha256<CS: ConstraintSystem>(
    cs: &mut CS,
    input: &[ShaByte],
    proving: bool,
) -> Result<ShaDigest, R1CSError> {
    if input.len() > (1 << 20) {
        return Err(error("SHA input exceeds implementation limit"));
    }
    let mut circuit = ShaCircuit::new(proving);
    let bytes = circuit.input(input)?;
    let digest = Sha256Gadget::digest(&bytes).map_err(error)?;
    circuit
        .finish(cs, vec![digest.0])?
        .pop()
        .ok_or_else(|| error("missing SHA digest"))
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
    use sha2::{Digest, Sha256};

    #[test]
    fn field_translation_preserves_ristretto_arithmetic() {
        let mut rng = OsRng;
        for _ in 0..32 {
            let a = Scalar::random(&mut rng);
            let b = Scalar::random(&mut rng);
            let x = F::from_le_bytes_mod_order(&a.to_bytes());
            let y = F::from_le_bytes_mod_order(&b.to_bytes());
            assert_eq!(scalar(x).unwrap(), a);
            assert_eq!(scalar(x + y).unwrap(), a + b);
            assert_eq!(scalar(x * y).unwrap(), a * b);
            assert_eq!(scalar(x - y).unwrap(), a - b);
        }
    }

    fn transcript(length: usize) -> Transcript {
        let mut t = Transcript::new(b"bf-sha256-bulletproof-arithmetic-test-v1");
        t.append_u64(b"length", length as u64);
        t
    }

    #[test]
    fn private_sha_vectors_wrong_digest_and_input_commitment_rejection() {
        let pc = PedersenGens::default();
        let mut rng = OsRng;
        for input in [b"abc".to_vec(), vec![42u8; 64]] {
            let expected: [u8; 32] = Sha256::digest(&input).into();
            let mut t = transcript(input.len());
            let mut p = Prover::new(&pc, &mut t);
            let mut commitments = Vec::new();
            let mut bytes = Vec::new();
            for &byte in &input {
                let (c, v) = p.commit(Scalar::from(byte as u64), Scalar::random(&mut rng));
                commitments.push(c);
                bytes.push(ShaByte::Private {
                    expression: v.into(),
                    assignment: Some(byte),
                });
            }
            let output = constrain_sha256(&mut p, &bytes, true).unwrap();
            assert_eq!(output.assignment.unwrap(), expected);
            for (byte, expected) in output.bytes.into_iter().zip(expected) {
                p.constrain(byte - Scalar::from(expected as u64));
            }
            let capacity = p.metrics().multipliers.max(64).next_power_of_two();
            eprintln!(
                "SHA-256 {} private bytes: {} multipliers",
                input.len(),
                p.metrics().multipliers
            );
            let bp = BulletproofGens::new(capacity, 1);
            let proof = p.prove(&bp).unwrap();
            for variant in 0..3 {
                let mut t = transcript(input.len());
                let mut v = Verifier::new(&mut t);
                let mut bytes = Vec::new();
                for (i, &c) in commitments.iter().enumerate() {
                    let c = if variant == 2 && i == 0 {
                        (c.decompress().unwrap()
                            + curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT)
                            .compress()
                    } else {
                        c
                    };
                    let byte = v.commit(c);
                    bytes.push(ShaByte::Private {
                        expression: byte.into(),
                        assignment: None,
                    });
                }
                let output = constrain_sha256(&mut v, &bytes, false).unwrap();
                assert!(output.assignment.is_none());
                let mut digest = expected;
                if variant == 1 {
                    digest[0] ^= 1;
                }
                for (byte, expected) in output.bytes.into_iter().zip(digest) {
                    v.constrain(byte - Scalar::from(expected as u64));
                }
                assert_eq!(v.verify(&proof, &pc, &bp).is_ok(), variant == 0);
            }
        }
    }
}
