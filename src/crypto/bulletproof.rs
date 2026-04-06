//! Bulletproof R1CS gadget for the eval-chain constraint:
//!
//!   (1)  e_d = e_{d+1} · y    for all d ∈ {0, 1, …, n−1}
//!   (2)  e_n ≠ 0
//!
//! Constraint (1) captures a Horner-form polynomial evaluation chain:
//! given e_n and a point y, each step multiplies the running value by y,
//! so e_0 = e_n · y^n at the end of the chain.
//!
//! Constraint (2) proves that the "seed" e_n is non-zero; in the protocol
//! this rules out a degenerate evaluation (e.g. the polynomial vanishes
//! at the queried point, which would be a false positive).
//!
//! # Non-interactive setting
//!
//! This module is non-interactive: both prover and verifier instantiate the
//! same Merlin transcript (`I-PSI-CA::eval_chain`) and rely on Bulletproofs'
//! Fiat-Shamir transform internally.
//!
//! # Circuit cost
//!
//! n multiplication gates for constraint (1), plus 1 gate for constraint (2),
//! giving n+1 multiplication gates in total.

use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;

// ── Core gadget ──────────────────────────────────────────────────────────────

/// Adds R1CS constraints that enforce:
///
///   (1) e_d = e_{d+1} · y   for all d ∈ {0, …, n−1}
///   (2) e_n ≠ 0
///
/// # Arguments
///
/// * `cs`     – mutable reference to the constraint system (prover or verifier)
/// * `e`      – `n+1` linear combinations representing \[e_0, e_1, …, e_n\]
/// * `y`      – the multiplier scalar as a `LinearCombination`
/// * `inv_en` – a committed variable holding e_n⁻¹, the witness for (2)
pub fn eval_chain_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    e: Vec<LinearCombination>,
    y: LinearCombination,
    inv_en: Variable,
) -> Result<(), R1CSError> {
    assert!(!e.is_empty(), "e must contain at least one element");
    let n = e.len() - 1;

    // ── Constraint (1): e_d = e_{d+1} · y  for d in 0 .. n-1 ───────────────
    //
    // For each d we open a multiplication gate:
    //
    //   left  = e[d+1]
    //   right = y
    //   out   = left * right          (enforced by the R1CS)
    //
    // Then we add a linear constraint: out − e[d] = 0.
    for d in 0..n {
        let (_, _, out) = cs.multiply(e[d + 1].clone(), y.clone());
        cs.constrain(LinearCombination::from(out) - e[d].clone());
    }

    // ── Constraint (2): e_n ≠ 0  ⟺  ∃ inv_en : e_n · inv_en = 1 ───────────
    //
    // Introduce a multiplication gate:
    //
    //   left  = e[n]
    //   right = inv_en                (committed before calling this gadget)
    //   out   = left * right = 1
    //
    // Linear constraint: out − 1 = 0.
    let (_, _, prod) = cs.multiply(e[n].clone(), inv_en.into());
    cs.constrain(LinearCombination::from(prod) - Scalar::one());

    Ok(())
}

// ── Prover ────────────────────────────────────────────────────────────────────

/// Proof output: the R1CS proof together with all Pedersen commitments.
pub struct EvalChainProof {
    pub proof: R1CSProof,
    /// Commitments to \[e_0, …, e_n\] in order.
    pub e_comms: Vec<CompressedRistretto>,
    /// Commitment to y.
    pub y_comm: CompressedRistretto,
    /// Commitment to e_n⁻¹.
    pub inv_en_comm: CompressedRistretto,
}

/// Produce a Bulletproof R1CS proof that the supplied witnesses satisfy the
/// eval-chain constraints.
///
/// This is a non-interactive proof generation routine.
///
/// # Arguments
///
/// * `pc_gens`   – Pedersen commitment generators
/// * `bp_gens`   – Bulletproof generators (must have capacity ≥ next power-of-2
///                 above 2 · (n+1))
/// * `e_scalars` – plaintext witnesses \[e_0, e_1, …, e_n\]
/// * `y_scalar`  – plaintext multiplier y
///
/// The caller is responsible for ensuring the witnesses are consistent:
///   `e_scalars[d] == e_scalars[d+1] * y_scalar`  for every d, and
///   `e_scalars[n] != 0`.
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

    // ── Witness sanity checks ────────────────────────────────────────────────
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

    // ── Commit to each e_d ──────────────────────────────────────────────────
    let mut e_comms = Vec::with_capacity(e_scalars.len());
    let mut e_vars: Vec<Variable> = Vec::with_capacity(e_scalars.len());
    for &ei in e_scalars {
        let (comm, var) = prover.commit(ei, Scalar::random(&mut rng));
        e_comms.push(comm);
        e_vars.push(var);
    }

    // ── Commit to y ─────────────────────────────────────────────────────────
    let (y_comm, y_var) = prover.commit(y_scalar, Scalar::random(&mut rng));

    // ── Commit to e_n⁻¹ (the non-zero witness) ──────────────────────────────
    let inv_en = e_scalars[n].invert();
    let (inv_en_comm, inv_en_var) = prover.commit(inv_en, Scalar::random(&mut rng));

    // ── Build linear combinations and apply the gadget ───────────────────────
    let e_lcs: Vec<LinearCombination> = e_vars.into_iter().map(Into::into).collect();
    let y_lc: LinearCombination = y_var.into();

    eval_chain_gadget(&mut prover, e_lcs, y_lc, inv_en_var)?;

    // ── Generate proof ───────────────────────────────────────────────────────
    let proof = prover.prove(bp_gens)?;

    Ok(EvalChainProof {
        proof,
        e_comms,
        y_comm,
        inv_en_comm,
    })
}

// ── Verifier ──────────────────────────────────────────────────────────────────

/// Verify a Bulletproof R1CS proof for the eval-chain constraints.
///
/// Verification is non-interactive and recomputes challenges from the same
/// Merlin transcript domain as the prover.
///
/// # Arguments
///
/// * `pc_gens`     – same Pedersen generators as used during proving
/// * `bp_gens`     – same Bulletproof generators as used during proving
/// * `proof`       – the `EvalChainProof` to verify
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

    // ── Allocate variables from commitments (same order as prover) ───────────
    let e_vars: Vec<Variable> = proof.e_comms.iter().map(|&c| verifier.commit(c)).collect();
    let y_var: Variable = verifier.commit(proof.y_comm);
    let inv_en_var: Variable = verifier.commit(proof.inv_en_comm);

    // ── Rebuild linear combinations and apply the same gadget ────────────────
    let e_lcs: Vec<LinearCombination> = e_vars.into_iter().map(Into::into).collect();
    let y_lc: LinearCombination = y_var.into();

    eval_chain_gadget(&mut verifier, e_lcs, y_lc, inv_en_var)?;

    // ── Verify proof ─────────────────────────────────────────────────────────
    verifier
        .verify(&proof.proof, pc_gens, bp_gens)
        .map_err(|e| R1CSError::GadgetError {
            description: format!("R1CS verification failed: {e:?}"),
        })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gens(n: usize) -> (PedersenGens, BulletproofGens) {
        let pc_gens = PedersenGens::default();
        // We need capacity ≥ next power-of-2 above 2*(n+1) multiplication gates.
        let capacity = ((2 * (n + 1)) as f64).log2().ceil();
        let capacity = 1usize << (capacity as usize).max(1);
        let bp_gens = BulletproofGens::new(capacity, 1);
        (pc_gens, bp_gens)
    }

    /// Builds a valid witness: e[d] = e_n * y^{n-d} for d in [0,n].
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
        let e_n = Scalar::random(&mut rng); // non-zero with overwhelming probability
        let e = build_witness(n, y, e_n);

        let proof = prove(&pc_gens, &bp_gens, &e, y).expect("prove failed");
        verify(&pc_gens, &bp_gens, &proof).expect("verify failed");
    }

    #[test]
    fn test_valid_chain_n1() {
        // Edge case: n = 1, one chain constraint + one non-zero check.
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
        // Edge case: n = 0, only the non-zero check applies.
        let n = 0;
        let (pc_gens, bp_gens) = make_gens(n);
        let mut rng = thread_rng();

        let y = Scalar::random(&mut rng);
        let e = vec![Scalar::random(&mut rng)]; // e[0] ≠ 0 w.o.p.

        let proof = prove(&pc_gens, &bp_gens, &e, y).expect("prove failed");
        verify(&pc_gens, &bp_gens, &proof).expect("verify failed");
    }
}
