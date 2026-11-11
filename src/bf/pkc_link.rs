//! Commitment composition for the reused PKC 2019 and Bulletproof arguments.
//! Links the COMPLETE proof-checked commitments. Merely comparing auxiliary
//! partial commitment fields is not a proof that their witnesses agree.
use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination as LC, R1CSError, R1CSProof, Variable},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::{Identity, MultiscalarMul},
};
use logproof::{
    InnerProductProof, InnerProductProverKnowledge, InnerProductVerifierKnowledge, LogProof,
    LogProofGenerators,
};
use merlin::Transcript;
use sha2::{Digest, Sha512};

fn error(message: impl Into<String>) -> R1CSError {
    R1CSError::GadgetError {
        description: message.into(),
    }
}

/// Allocate every bit of the complete PKC opening before any arithmetic gates.
/// The bits include the integer-lift factors, not only the selected S entries.
/// The first bits can then be decoded with signed_coefficients() and linked to
/// the caller's exact item/hash/weight variables by equality constraints.
pub fn allocate_ring_bits<CS: ConstraintSystem>(
    cs: &mut CS,
    length: usize,
    assignment: Option<&[bool]>,
) -> Result<Vec<Variable>, R1CSError> {
    if length == 0
        || length > (1 << 26)
        || cs.metrics().multipliers != 0
        || assignment.is_some_and(|a| a.len() != length)
    {
        return Err(error("PKC bit inputs must be a bounded first-phase prefix"));
    }
    let bits = (0..length)
        .map(|i| cs.allocate(assignment.map(|a| Scalar::from(a[i] as u64))))
        .collect::<Result<Vec<_>, _>>()?;
    for &bit in &bits {
        let product = cs.multiply(bit.into(), Scalar::one() - bit).2;
        cs.constrain(product.into());
    }
    Ok(bits)
}

/// Decode the PKC two's-complement S prefix, in row-major coefficient order.
/// Widths must be the public statement's bumped bounds (vk.b()). Zero-width
/// coefficients are constant zero. The remaining factor bits stay constrained
/// and included in the full commitment link.
pub fn signed_coefficients(bits: &[Variable], widths: &[u32]) -> Result<Vec<LC>, R1CSError> {
    let mut offset = 0usize;
    let mut coefficients = Vec::with_capacity(widths.len());
    for &width in widths {
        if width > 128
            || offset
                .checked_add(width as usize)
                .is_none_or(|end| end > bits.len())
        {
            return Err(error("invalid signed PKC coefficient width"));
        }
        let mut value = LC::default();
        let mut power = Scalar::one();
        for j in 0..width as usize {
            let sign = if j + 1 == width as usize {
                -power
            } else {
                power
            };
            value = value + sign * LC::from(bits[offset + j]);
            power += power;
        }
        coefficients.push(value);
        offset += width as usize;
    }
    Ok(coefficients)
}

struct Material {
    transcript: Transcript,
    g: Vec<RistrettoPoint>,
    h: Vec<RistrettoPoint>,
    commitment: RistrettoPoint,
    beta: Scalar,
}

fn material(
    context: &[u8],
    pkc: &LogProof,
    pkc_gens: &LogProofGenerators,
    arithmetic: &R1CSProof,
    bp_gens: &BulletproofGens,
    pc: &PedersenGens,
    wire_pairs: usize,
) -> Result<Material, R1CSError> {
    let length = pkc_gens.g.len();
    if length == 0
        || length != pkc_gens.h.len()
        || wire_pairs == 0
        || wire_pairs > bp_gens.gens_capacity
        || length > wire_pairs.saturating_mul(2)
    {
        return Err(error("incompatible complete-commitment dimensions"));
    }
    let input = arithmetic
        .input_commitment()
        .decompress()
        .ok_or_else(|| error("invalid arithmetic input commitment"))?;
    let mut transcript = Transcript::new(b"bf-pkc-r1cs-full-commitment-link-v1");
    transcript.append_message(b"context", context);
    transcript.append_message(
        b"pkc-proof",
        &bincode::serialize(pkc).map_err(|e| error(e.to_string()))?,
    );
    transcript.append_message(b"arithmetic-proof", &arithmetic.to_bytes());
    transcript.append_u64(b"wire-pairs", wire_pairs as u64);
    transcript.append_u64(b"pkc-bits", length as u64);
    let share = bp_gens.share(0);
    let arithmetic_gens = share
        .G(wire_pairs)
        .zip(share.H(wire_pairs))
        .flat_map(|(g, h)| [*g, *h])
        .collect::<Vec<_>>();
    let mut hash = Sha512::new();
    hash.update(b"bf-pkc-r1cs-link-generator-context-v1");
    for point in pkc_gens
        .g
        .iter()
        .chain(&pkc_gens.h)
        .chain(&arithmetic_gens)
        .chain([&pc.B_blinding])
    {
        hash.update(point.compress().as_bytes());
    }
    transcript.append_message(b"generators", &hash.finalize());
    let mut wide = [0u8; 64];
    transcript.challenge_bytes(b"combine", &mut wide);
    let beta = Scalar::from_bytes_mod_order_wide(&wide);
    if beta == Scalar::zero() {
        return Err(error("zero commitment-combination challenge"));
    }
    // PKC w = sum(g_i) + sum((h_i-g_i)*bit_i) + u*rho.
    // BP A_I1 = sum(P_i*wire_i) + u*gamma, with the PKC bits as
    // the fixed prefix of its interleaved left/right input wires.
    let constant = pkc_gens.g.iter().copied().sum::<RistrettoPoint>();
    let commitment = pkc.w - constant + beta * input;
    let g = arithmetic_gens
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            beta * p
                + if i < length {
                    pkc_gens.h[i] - pkc_gens.g[i]
                } else {
                    RistrettoPoint::identity()
                }
        })
        .collect::<Vec<_>>();
    let h = (0..g.len())
        .map(|i| {
            let mut hash = Sha512::new();
            hash.update(b"bf-pkc-r1cs-link-independent-ipa-h-v1");
            hash.update((i as u64).to_le_bytes());
            RistrettoPoint::from_uniform_bytes(&hash.finalize().into())
        })
        .collect();
    Ok(Material {
        transcript,
        g,
        h,
        commitment,
        beta,
    })
}

/// Reuses the existing PKC zero-knowledge inner-product argument to prove a
/// common opening of the full ring and arithmetic commitments. Its right vector
/// is zero, so the public inner product is zero. Independent generator families
/// and the transcript-derived combination challenge bind the common prefix.
pub fn prove_commitment_link(
    context: &[u8],
    pkc: &LogProof,
    pkc_gens: &LogProofGenerators,
    arithmetic: &R1CSProof,
    bp_gens: &BulletproofGens,
    pc: &PedersenGens,
    left: &[Scalar],
    right: &[Scalar],
    pkc_blinding: Scalar,
    arithmetic_blinding: Scalar,
) -> Result<InnerProductProof, R1CSError> {
    if left.len() != right.len() {
        return Err(error("arithmetic opening dimensions differ"));
    }
    let mut m = material(context, pkc, pkc_gens, arithmetic, bp_gens, pc, left.len())?;
    let values = zeroize::Zeroizing::new(
        left.iter()
            .zip(right)
            .flat_map(|(a, b)| [*a, *b])
            .collect::<Vec<_>>(),
    );
    let zeros = vec![Scalar::zero(); values.len()];
    let blinding = pkc_blinding + m.beta * arithmetic_blinding;
    let commitment = RistrettoPoint::multiscalar_mul(
        values.iter().chain([&blinding]),
        m.g.iter().chain([&pc.B_blinding]),
    );
    if commitment != m.commitment {
        return Err(error(
            "ring and arithmetic witnesses do not have a common opening",
        ));
    }
    let knowledge = InnerProductProverKnowledge::new(&values, &zeros, &blinding, &m.commitment);
    Ok(InnerProductProof::create(
        &mut m.transcript,
        &knowledge,
        &m.g,
        &m.h,
        &pc.B_blinding,
    ))
}

/// The caller must also verify BOTH constituent proofs against their complete
/// public statements; this proof only enforces their witness equality.
pub fn verify_commitment_link(
    context: &[u8],
    pkc: &LogProof,
    pkc_gens: &LogProofGenerators,
    arithmetic: &R1CSProof,
    bp_gens: &BulletproofGens,
    pc: &PedersenGens,
    wire_pairs: usize,
    link: &InnerProductProof,
) -> Result<(), R1CSError> {
    let mut m = material(context, pkc, pkc_gens, arithmetic, bp_gens, pc, wire_pairs)?;
    let knowledge = InnerProductVerifierKnowledge {
        t: m.commitment,
        x: Scalar::zero(),
    };
    link.verify(&mut m.transcript, &knowledge, &m.g, &m.h, &pc.B_blinding)
        .map_err(|e| error(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, Verifier};
    use logproof::{
        linear_algebra::Matrix, math::make_poly, rings::ZqSeal128_2048 as Q, Bounds,
        LogProofProverKnowledge,
    };
    use rand::rngs::OsRng;

    fn problem(first: i64) -> LogProofProverKnowledge<Q> {
        let a = Matrix::from([[make_poly::<Q>(&[2, 3, 1])]]);
        let s = Matrix::from([[make_poly::<Q>(&[first, 5, -2, 1, 0, 0, 0, 0])]]);
        let f = make_poly::<Q>(&[1, 0, 0, 0, 0, 0, 0, 0, 1]);
        let t = (&a * &s).map(|p| p.vartime_div_rem_restricted_rhs(&f).1);
        let bounds = Matrix::from([[Bounds(vec![4; 8])]]);
        LogProofProverKnowledge::new(&a, &s, &t, &bounds, &f)
    }

    #[test]
    fn bounded_ring_relation_and_full_arithmetic_commitment_link() {
        let knowledge = problem(3);
        let gens = LogProofGenerators::new(knowledge.vk.l() as usize);
        let pc = PedersenGens::default();
        let mut rng = OsRng;
        let half_rho = Scalar::random(&mut rng);
        let mut t = Transcript::new(b"bf-bounded-ring-proof-test");
        let ring = LogProof::create_with_shared(
            &mut t,
            &knowledge,
            &gens.g,
            &gens.h,
            &pc.B_blinding,
            &half_rho,
            &[],
        );
        ring.verify(
            &mut Transcript::new(b"bf-bounded-ring-proof-test"),
            &knowledge.vk,
            &gens.g,
            &gens.h,
            &pc.B_blinding,
        )
        .unwrap();
        let bit_assignment = LogProof::binary_witness(&knowledge)
            .iter()
            .map(|b| *b)
            .collect::<Vec<_>>();
        assert_eq!(bit_assignment.len(), knowledge.vk.l() as usize);
        let widths = LogProof::serialize_bounds(&knowledge.vk.b());
        let mut t = Transcript::new(b"bf-linked-arithmetic-test");
        let mut p = Prover::new(&pc, &mut t);
        let bits = allocate_ring_bits(&mut p, bit_assignment.len(), Some(&bit_assignment)).unwrap();
        let coefficients = signed_coefficients(&bits, &widths).unwrap();
        let (commitment, item) = p.commit(Scalar::from(3u64), Scalar::random(&mut rng));
        p.constrain(coefficients[0].clone() - item);
        let product = p
            .multiply(coefficients[0].clone(), coefficients[1].clone())
            .2;
        p.constrain(LC::from(product) - Scalar::from(15u64));
        p.constrain(coefficients[2].clone() + Scalar::from(2u64));
        let (left, right) = p.input_wire_witness();
        let bp = BulletproofGens::new(p.metrics().multipliers.next_power_of_two(), 1);
        let blind = Scalar::random(&mut rng);
        let arithmetic = p.prove_with_input_blinding(&bp, Some(blind)).unwrap().0;
        let mut t = Transcript::new(b"bf-linked-arithmetic-test");
        let mut v = Verifier::new(&mut t);
        let bits = allocate_ring_bits(&mut v, bit_assignment.len(), None).unwrap();
        let coefficients = signed_coefficients(&bits, &widths).unwrap();
        let item = v.commit(commitment);
        v.constrain(coefficients[0].clone() - item);
        let product = v
            .multiply(coefficients[0].clone(), coefficients[1].clone())
            .2;
        v.constrain(LC::from(product) - Scalar::from(15u64));
        v.constrain(coefficients[2].clone() + Scalar::from(2u64));
        let wire_pairs = v.metrics().multipliers;
        v.verify(&arithmetic, &pc, &bp).unwrap();
        let context = b"round/context/1";
        let link = prove_commitment_link(
            context,
            &ring,
            &gens,
            &arithmetic,
            &bp,
            &pc,
            &left,
            &right,
            Scalar::from(2u64) * half_rho,
            blind,
        )
        .unwrap();
        verify_commitment_link(
            context,
            &ring,
            &gens,
            &arithmetic,
            &bp,
            &pc,
            wire_pairs,
            &link,
        )
        .unwrap();
        assert!(verify_commitment_link(
            b"round/context/2",
            &ring,
            &gens,
            &arithmetic,
            &bp,
            &pc,
            wire_pairs,
            &link
        )
        .is_err());

        // Both independent proofs can be valid about different inputs. They
        // must still be rejected as a combined proof, even if an unchecked
        // auxiliary partial commitment happens to look right.
        let different = problem(4);
        let different_half = Scalar::random(&mut rng);
        let different_ring = LogProof::create_with_shared(
            &mut Transcript::new(b"bf-bounded-ring-proof-test"),
            &different,
            &gens.g,
            &gens.h,
            &pc.B_blinding,
            &different_half,
            &[],
        );
        different_ring
            .verify(
                &mut Transcript::new(b"bf-bounded-ring-proof-test"),
                &different.vk,
                &gens.g,
                &gens.h,
                &pc.B_blinding,
            )
            .unwrap();
        assert!(verify_commitment_link(
            context,
            &different_ring,
            &gens,
            &arithmetic,
            &bp,
            &pc,
            wire_pairs,
            &link
        )
        .is_err());
        assert!(prove_commitment_link(
            context,
            &different_ring,
            &gens,
            &arithmetic,
            &bp,
            &pc,
            &left,
            &right,
            Scalar::from(2u64) * different_half,
            blind
        )
        .is_err());
        // Bypass the honest-prover check deliberately: test the actual link
        // verifier against a forged common-opening argument.
        // Upstream debug assertions deliberately prevent constructing this
        // invalid argument; release tests exercise its real verification path.
        #[cfg(not(debug_assertions))]
        {
            let mut m = material(
                context,
                &different_ring,
                &gens,
                &arithmetic,
                &bp,
                &pc,
                wire_pairs,
            )
            .unwrap();
            let values = left
                .iter()
                .zip(&right)
                .flat_map(|(a, b)| [*a, *b])
                .collect::<Vec<_>>();
            let zeros = vec![Scalar::zero(); values.len()];
            let wrong = InnerProductProverKnowledge::new(
                &values,
                &zeros,
                &(Scalar::from(2u64) * different_half + m.beta * blind),
                &m.commitment,
            );
            let forged =
                InnerProductProof::create(&mut m.transcript, &wrong, &m.g, &m.h, &pc.B_blinding);
            assert!(verify_commitment_link(
                context,
                &different_ring,
                &gens,
                &arithmetic,
                &bp,
                &pc,
                wire_pairs,
                &forged
            )
            .is_err());
        }
        let wrong_output = problem(4).vk;
        assert!(ring
            .verify(
                &mut Transcript::new(b"bf-bounded-ring-proof-test"),
                &wrong_output,
                &gens.g,
                &gens.h,
                &pc.B_blinding
            )
            .is_err());
    }
}
