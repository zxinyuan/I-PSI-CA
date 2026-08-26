use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;

pub fn eval_chain_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    e: Vec<LinearCombination>,
    y: LinearCombination,
    inv_en: Variable,
) -> Result<(), R1CSError> {
    assert!(!e.is_empty(), "e must contain at least one element");
    let n = e.len() - 1;

    for d in 0..n {
        let (_, _, out) = cs.multiply(e[d + 1].clone(), y.clone());
        cs.constrain(LinearCombination::from(out) - e[d].clone());
    }

    let (_, _, prod) = cs.multiply(e[n].clone(), inv_en.into());
    cs.constrain(LinearCombination::from(prod) - Scalar::one());

    Ok(())
}

pub struct EvalChainProof {
    pub proof: R1CSProof,
    pub e_comms: Vec<CompressedRistretto>,
    pub y_comm: CompressedRistretto,
    pub inv_en_comm: CompressedRistretto,
}

pub fn prove(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    e_scalars: &[Scalar],
    y_scalar: Scalar,
) -> Result<EvalChainProof, R1CSError> {
    assert!(
        !e_scalars.is_empty(),
        "e_scalars must contain at least one element"
    );
    let n = e_scalars.len() - 1;

    for d in 0..n {
        debug_assert_eq!(
            e_scalars[d],
            e_scalars[d + 1] * y_scalar,
            "witness violates chain constraint at d = {d}"
        );
    }
    debug_assert_ne!(e_scalars[n], Scalar::zero(), "e_n must be non-zero");

    let mut rng = thread_rng();
    let mut transcript = Transcript::new(b"I-PSI-CA::eval_chain");
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let mut e_comms = Vec::with_capacity(e_scalars.len());
    let mut e_vars: Vec<Variable> = Vec::with_capacity(e_scalars.len());
    for &ei in e_scalars {
        let (comm, var) = prover.commit(ei, Scalar::random(&mut rng));
        e_comms.push(comm);
        e_vars.push(var);
    }

    let (y_comm, y_var) = prover.commit(y_scalar, Scalar::random(&mut rng));

    let inv_en = e_scalars[n].invert();
    let (inv_en_comm, inv_en_var) = prover.commit(inv_en, Scalar::random(&mut rng));

    let e_lcs: Vec<LinearCombination> = e_vars.into_iter().map(Into::into).collect();
    let y_lc: LinearCombination = y_var.into();

    eval_chain_gadget(&mut prover, e_lcs, y_lc, inv_en_var)?;

    let proof = prover.prove(bp_gens)?;

    Ok(EvalChainProof {
        proof,
        e_comms,
        y_comm,
        inv_en_comm,
    })
}

pub fn verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proof: &EvalChainProof,
) -> Result<(), R1CSError> {
    assert!(
        !proof.e_comms.is_empty(),
        "e_comms must contain at least one commitment"
    );

    let mut transcript = Transcript::new(b"I-PSI-CA::eval_chain");
    let mut verifier = Verifier::new(&mut transcript);

    let e_vars: Vec<Variable> = proof.e_comms.iter().map(|&c| verifier.commit(c)).collect();
    let y_var: Variable = verifier.commit(proof.y_comm);
    let inv_en_var: Variable = verifier.commit(proof.inv_en_comm);

    let e_lcs: Vec<LinearCombination> = e_vars.into_iter().map(Into::into).collect();
    let y_lc: LinearCombination = y_var.into();

    eval_chain_gadget(&mut verifier, e_lcs, y_lc, inv_en_var)?;

    verifier
        .verify(&proof.proof, pc_gens, bp_gens)
        .map_err(|e| R1CSError::GadgetError {
            description: format!("R1CS verification failed: {e:?}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gens(n: usize) -> (PedersenGens, BulletproofGens) {
        let pc_gens = PedersenGens::default();
        let capacity = ((2 * (n + 1)) as f64).log2().ceil();
        let capacity = 1usize << (capacity as usize).max(1);
        let bp_gens = BulletproofGens::new(capacity, 1);
        (pc_gens, bp_gens)
    }

    fn build_witness(n: usize, y: Scalar, e_n: Scalar) -> Vec<Scalar> {
        let mut e = vec![Scalar::zero(); n + 1];
        e[n] = e_n;
        for d in (0..n).rev() {
            e[d] = e[d + 1] * y;
        }
        e
    }

    #[test]
    fn test_valid_chain_n4() {
        let n = 4;
        let (pc_gens, bp_gens) = make_gens(n);
        let mut rng = thread_rng();

        let y = Scalar::random(&mut rng);
        let e_n = Scalar::random(&mut rng);
        let e = build_witness(n, y, e_n);

        let proof = prove(&pc_gens, &bp_gens, &e, y).expect("prove failed");
        verify(&pc_gens, &bp_gens, &proof).expect("verify failed");
    }

    #[test]
    fn test_valid_chain_n1() {
        let n = 1;
        let (pc_gens, bp_gens) = make_gens(n);
        let mut rng = thread_rng();

        let y = Scalar::random(&mut rng);
        let e_n = Scalar::random(&mut rng);
        let e = build_witness(n, y, e_n);

        let proof = prove(&pc_gens, &bp_gens, &e, y).expect("prove failed");
        verify(&pc_gens, &bp_gens, &proof).expect("verify failed");
    }

    #[test]
    fn test_valid_chain_n0() {
        let n = 0;
        let (pc_gens, bp_gens) = make_gens(n);
        let mut rng = thread_rng();

        let y = Scalar::random(&mut rng);
        let e = vec![Scalar::random(&mut rng)];

        let proof = prove(&pc_gens, &bp_gens, &e, y).expect("prove failed");
        verify(&pc_gens, &bp_gens, &proof).expect("verify failed");
    }
}
