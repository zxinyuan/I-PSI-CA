//! One logical F_(t^3) result in three native RLWE plaintext coordinates.
//! A uniform nonzero extension-field mask hides every nonzero result, including
//! which coordinates of the unmasked vector were zero. Arithmetic reuses Ark FF.
use super::{field_constraints::FieldVariable, rlwe::PROTOCOL_PLAINTEXT_MODULUS as T};
use ark_ff::PrimeField;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination as LC, R1CSError};

pub(crate) const NONRESIDUE: u64 = 5;
#[allow(unexpected_cfgs, non_local_definitions)]
mod arithmetic {
    use ark_ff::{Fp3, Fp3Config, Fp64, MontBackend, MontConfig, MontFp};
    #[derive(MontConfig)]
    #[modulus = "36028796991700993"]
    #[generator = "5"]
    pub struct BaseConfig;
    pub type Base = Fp64<MontBackend<BaseConfig, 1>>;
    pub struct CubicConfig;
    impl Fp3Config for CubicConfig {
        type Fp = Base;
        const NONRESIDUE: Base = MontFp!("5");
        const FROBENIUS_COEFF_FP3_C1: &'static [Base] = &[
            MontFp!("1"),
            MontFp!("16569271990397580"),
            MontFp!("19459525001303412"),
        ];
        const FROBENIUS_COEFF_FP3_C2: &'static [Base] = &[
            MontFp!("1"),
            MontFp!("19459525001303412"),
            MontFp!("16569271990397580"),
        ];
        const TWO_ADICITY: u32 = 21;
        const TRACE_MINUS_ONE_DIV_TWO: &'static [u64] =
            &[17036789762178940908, 18445371883249457151, 32767];
        const QUADRATIC_NONRESIDUE_TO_T: Fp3<Self> =
            Fp3::new(MontFp!("31489810568081836"), MontFp!("0"), MontFp!("0"));
    }
    pub type Element = Fp3<CubicConfig>;
}
use arithmetic::{Base, Element};
fn element(c: [u64; 3]) -> Element {
    Element::new(Base::from(c[0]), Base::from(c[1]), Base::from(c[2]))
}
fn coordinates(e: Element) -> [u64; 3] {
    [
        e.c0.into_bigint().0[0],
        e.c1.into_bigint().0[0],
        e.c2.into_bigint().0[0],
    ]
}

pub(crate) fn mask_hashes(
    hashes: &[Vec<(u64, u64)>],
    mask: [u64; 3],
) -> Result<Vec<Vec<(u64, u64)>>, String> {
    if hashes.len() != 3
        || hashes[0].is_empty()
        || mask == [0; 3]
        || mask.iter().any(|&r| r >= T)
        || hashes.iter().any(|v| v.len() != hashes[0].len())
    {
        return Err("invalid extension-field mask or hash shape".into());
    }
    let mut output = vec![Vec::new(); 3];
    let mask = element(mask);
    for i in 0..hashes[0].len() {
        let position = hashes[0][i].0;
        if hashes
            .iter()
            .any(|row| row[i].0 != position || row[i].1 >= T)
        {
            return Err("inconsistent extension-field hash coordinates".into());
        }
        let h = element([hashes[0][i].1, hashes[1][i].1, hashes[2][i].1]);
        for (row, value) in output.iter_mut().zip(coordinates(mask * h)) {
            row.push((position, value));
        }
    }
    Ok(output)
}

/// The same standard cubic-extension product, enforced with bounded base-field
/// gadgets in the existing Bulletproof R1CS. Karatsuba uses six base products.
pub(crate) fn constrain_product<CS: ConstraintSystem>(
    cs: &mut CS,
    a: &[FieldVariable],
    b: &[FieldVariable],
) -> Result<Vec<FieldVariable>, R1CSError> {
    let error = || R1CSError::GadgetError {
        description: "extension field requires three matching base-field coordinates".into(),
    };
    if a.len() != 3 || b.len() != 3 || a.iter().chain(b).any(|v| v.modulus() != T) {
        return Err(error());
    }
    let beta = FieldVariable::allocate(cs, T, a[0].assignment().map(|_| NONRESIDUE))?;
    cs.constrain(LC::from(beta.variable()) - curve25519_dalek_ng::scalar::Scalar::from(NONRESIDUE));
    let v0 = a[0].multiply(cs, &b[0])?;
    let v1 = a[1].multiply(cs, &b[1])?;
    let v2 = a[2].multiply(cs, &b[2])?;
    let mut cross = |i: usize, j: usize, x: &FieldVariable, y: &FieldVariable| {
        let left = a[i].add(cs, &a[j])?;
        let right = b[i].add(cs, &b[j])?;
        let value = left
            .multiply(cs, &right)?
            .subtract(cs, x)?
            .subtract(cs, y)?;
        Ok::<_, R1CSError>(value)
    };
    let t0 = cross(1, 2, &v1, &v2)?;
    let t1 = cross(0, 1, &v0, &v1)?;
    let t2 = cross(0, 2, &v0, &v2)?;
    let reduced0 = t0.multiply(cs, &beta)?;
    let reduced1 = v2.multiply(cs, &beta)?;
    let c0 = v0.add(cs, &reduced0)?;
    let c1 = t1.add(cs, &reduced1)?;
    let c2 = t2.add(cs, &v1)?;
    Ok(vec![c0, c1, c2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use bulletproofs::{
        r1cs::{Prover, R1CSProof, Verifier},
        BulletproofGens, PedersenGens,
    };
    use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};
    use merlin::Transcript;
    #[test]
    fn logical_extension_evaluation_matches_plaintext_at_100k_buckets() {
        use super::super::{
            bloom::BloomFilterConfig,
            protocol_hash,
            rlwe::{generate_keys_with_profile, RlweProfile, RlwePublicContext},
        };
        let mut rng = rand09::rng();
        let (public, secret) =
            generate_keys_with_profile(&mut rng, RlweProfile::Protocol100k).unwrap();
        let config = BloomFilterConfig {
            bloom_filter_size: 100_000,
            hash_count: 2,
            target_marked_count: 2,
        };
        let source = public
            .encrypt_bloom_positions(config, &[2, 5], &mut rng)
            .unwrap();
        let monitor = RlwePublicContext::from_bytes(&public.to_bytes().unwrap()).unwrap();
        let source = monitor.from_wire(&source.to_wire()).unwrap();
        let f = fhe_math::zq::Modulus::new(T).unwrap();
        for item in [2u64, 3] {
            let h = protocol_hash::weights(Scalar::from(item), config).unwrap();
            let mut sum = element([0; 3]);
            for i in 0..config.hash_count {
                let p = h[0][i].0;
                let value = f.mul(f.sub(p, 2), f.sub(p, 5));
                sum += element([h[0][i].1, h[1][i].1, h[2][i].1]) * element([value, 0, 0]);
            }
            for mask in [[17, 18, 19], [0, 1, 0]] {
                let mixed = mask_hashes(&h, mask).unwrap();
                let mut decoded = Vec::new();
                for row in &mixed {
                    let (output, _) = monitor.evaluate_sample(&source, row, 1, &mut rng).unwrap();
                    decoded.push(secret.decrypt_sample(&public, &output).unwrap());
                }
                assert_eq!(decoded, coordinates(element(mask) * sum));
                assert_eq!(decoded == [0; 3], item == 2);
            }
        }
    }
    #[test]
    fn constrained_extension_product_matches_ark_ff_and_rejects_wrong_coordinates() {
        let mut rng = rand::rngs::OsRng;
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(16384, 1);
        for (a, b) in [
            ([0, 1, 0], [1, 1, 1]),
            ([T - 1, T - 2, T - 3], [0, 1, 0]),
            ([2, 3, 4], [5, 7, 11]),
        ] {
            let expected = coordinates(element(a) * element(b));
            for forged in [false, true] {
                let mut values = a.into_iter().chain(b).chain(expected).collect::<Vec<_>>();
                if forged {
                    values[6] = (values[6] + 1) % T;
                }
                let mut transcript = Transcript::new(b"bf-extension-product-test");
                let mut prover = Prover::new(&pc, &mut transcript);
                let mut commits = Vec::new();
                let mut variables = Vec::new();
                for &value in &values {
                    let (c, v) = prover.commit(Scalar::from(value), Scalar::random(&mut rng));
                    commits.push(c);
                    variables.push(v);
                }
                let input = (0..6)
                    .map(|i| {
                        FieldVariable::constrain(&mut prover, variables[i], T, Some(values[i]))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                let output = constrain_product(&mut prover, &input[..3], &input[3..]).unwrap();
                for i in 0..3 {
                    prover.constrain(LC::from(output[i].variable()) - variables[6 + i]);
                }
                let proof = prover.prove(&bp).unwrap();
                let mut transcript = Transcript::new(b"bf-extension-product-test");
                let mut verifier = Verifier::new(&mut transcript);
                let variables = commits
                    .iter()
                    .map(|c| verifier.commit(CompressedRistretto(c.to_bytes())))
                    .collect::<Vec<_>>();
                let input = (0..6)
                    .map(|i| FieldVariable::constrain(&mut verifier, variables[i], T, None))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                let output = constrain_product(&mut verifier, &input[..3], &input[3..]).unwrap();
                for i in 0..3 {
                    verifier.constrain(LC::from(output[i].variable()) - variables[6 + i]);
                }
                assert_eq!(
                    verifier
                        .verify(&R1CSProof::from_bytes(&proof.to_bytes()).unwrap(), &pc, &bp)
                        .is_ok(),
                    !forged
                );
            }
        }
    }
    #[test]
    fn irreducible_extension_masks_zero_patterns_and_every_nonzero_value() {
        assert_eq!(Base::MODULUS.0[0], T);
        assert_eq!(T % 3, 1);
        assert_ne!(Base::from(NONRESIDUE).pow([(T - 1) / 3]), Base::from(1u64));
        let u = element([0, 1, 0]);
        assert_eq!(u.pow([3]), element([NONRESIDUE, 0, 0]));
        for mask in [
            [1, 0, 0],
            [0, 1, 0],
            [0, 0, 1],
            [2, 3, 4],
            [T - 1, T - 2, T - 3],
        ] {
            let m = element(mask);
            let inv = m.inverse().unwrap();
            for value in [[0, 1, 0], [1, 0, 0], [0, 0, 1], [5, 7, 11]] {
                assert_eq!((m * element(value)) * inv, element(value));
                assert_ne!(coordinates(m * element(value)), [0; 3]);
            }
        }
        let h = vec![vec![(1, 0)], vec![(1, 1)], vec![(1, 0)]];
        let out = mask_hashes(&h, [1, 1, 1]).unwrap();
        assert_eq!(out, vec![vec![(1, 5)], vec![(1, 1)], vec![(1, 1)]]);
        assert!(mask_hashes(&h, [0; 3]).is_err());
    }
}
