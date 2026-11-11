//! Shared-witness Sigma–Bulletproof for evaluation, masking, decryption, and division.
use super::{
    performance::{generators, mul_g},
    proofs::ProofContext,
    sigma::Base,
    target::{EncodedPoly, WireCiphertext, WireEncryptedPoly},
};
use crate::crypto::elgamal::{
    self, Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};
use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier},
    PedersenGens,
};
use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, MultiscalarMul},
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Every Sigma equation below uses the same challenge and responses. No batching of
/// independent group equations: every committed wire and ciphertext component is checked.
#[derive(Serialize, Deserialize)]
pub(crate) struct DivisionReply {
    pub next: WireEncryptedPoly,
    // Interaction start: target payload received, before decoding/proof verification.
    pub computation_started_unix_ns: u128,
    scaled: WireCiphertext,
    partial: WireCiphertext,
    // e[0..n], m, inverse_mask, each committed as value*G + blind*H.
    wires: Vec<[u8; 32]>,
    circuit: Vec<u8>,
    sigma: super::sigma::Proof,
}
fn decode(b: [u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| "invalid monitor proof point".into())
}
fn validate(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    n: usize,
    ctx: &ProofContext,
) -> Result<(), String> {
    if n == 0 || n > super::MAX_COEFFICIENTS || ctx.round == 0 {
        return Err("invalid monitor statement dimensions/round".into());
    }
    if pk.0 == RistrettoPoint::identity()
        || pk1.0 == RistrettoPoint::identity()
        || pk2.0 == RistrettoPoint::identity()
        || pk.0 != pk1.0 + pk2.0
    {
        return Err("invalid encryption key shares".into());
    }
    Ok(())
}
fn append_ct(t: &mut Transcript, label: &'static [u8], ct: &WireCiphertext) {
    t.append_message(label, &ct.c1);
    t.append_message(label, &ct.c2);
}
/// Binds canonical encodings, which each endpoint already holds as wire data.
#[allow(clippy::too_many_arguments)]
fn statement(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &WireEncryptedPoly,
    next: &WireEncryptedPoly,
    scaled: &WireCiphertext,
    partial: &WireCiphertext,
    ctx: &ProofContext,
) -> Transcript {
    let mut t = Transcript::new(b"exact::monitor-sigma-bullet-v2");
    t.append_message(b"version", b"exact-pok-v7");
    t.append_message(b"session", &ctx.session);
    t.append_u64(b"round", ctx.round);
    for p in [pk.0, pk1.0, pk2.0] {
        t.append_message(b"key", p.compress().as_bytes());
    }
    t.append_u64(b"coefficients", current.0.len() as u64);
    for ct in &current.0 {
        append_ct(&mut t, b"current", ct);
    }
    for ct in &next.0 {
        append_ct(&mut t, b"quotient", ct);
    }
    append_ct(&mut t, b"scaled", scaled);
    append_ct(&mut t, b"partial", partial);
    t
}
#[allow(clippy::too_many_arguments)]
fn sigma_statement(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    msg: &DivisionReply,
    encoded_next: &EncodedPoly,
    scaled: &Ciphertext,
    partial: &Ciphertext,
    base: &Transcript,
) -> Result<super::sigma::Statement, String> {
    let next = encoded_next.native();
    let n = current.0.len();
    let width = n + 2;
    let extra = 2 * width;
    let quotient = extra + 3;
    let mut t = base.clone();
    t.append_message(b"section", b"sigma-fun-shared-witness-v1");
    t.append_u64(b"wires", msg.wires.len() as u64);
    for c in &msg.wires {
        t.append_message(b"wire", c);
    }
    t.append_message(b"circuit", &msg.circuit);
    t.append_message(
        b"monitor-computation-start",
        &msg.computation_started_unix_ns.to_le_bytes(),
    );
    let mut relation = super::sigma::Statement::new(super::sigma::context(t));
    let pc = PedersenGens::default();
    let (g, h, blinding) = (
        relation.fixed(G),
        relation.fixed(pk.0),
        relation.fixed(pc.B_blinding),
    );
    for i in 0..width {
        relation.add_encoded(
            decode(msg.wires[i])?,
            msg.wires[i],
            [(i, g), (width + i, blinding)],
        );
    }
    relation.add(
        scaled.c1,
        (0..n)
            .map(|i| (i, Base::Point(current.0[i].c1)))
            .chain([(extra, g)]),
    );
    relation.add(
        scaled.c2,
        (0..n)
            .map(|i| (i, Base::Point(current.0[i].c2)))
            .chain([(extra, h)]),
    );
    relation.add(pk2.0, [(extra + 1, g)]);
    relation.add(partial.c1 - scaled.c1, [(extra + 2, g)]);
    relation.add(
        partial.c2 - scaled.c2,
        [
            (extra + 1, Base::Point(-scaled.c1)),
            (extra + 2, Base::Point(pk1.0)),
        ],
    );
    for i in 1..n {
        relation.add(
            next.0[i - 1].c1 - current.0[i].c1,
            [(n, Base::Point(next.0[i].c1)), (quotient + i - 1, g)],
        );
        relation.add(
            next.0[i - 1].c2 - current.0[i].c2,
            [(n, Base::Point(next.0[i].c2)), (quotient + i - 1, h)],
        );
    }
    relation.add_encoded(
        next.0[n - 1].c1,
        encoded_next.wire().0[n - 1].c1,
        [(quotient + n - 1, g)],
    );
    relation.add_encoded(
        next.0[n - 1].c2,
        encoded_next.wire().0[n - 1].c2,
        [(quotient + n - 1, h)],
    );
    Ok(relation)
}
fn evaluation_gadget<CS: ConstraintSystem>(cs: &mut CS, wires: &[Variable], n: usize) {
    // e_i = mask * m^i. Checking e_0 * inverse_mask = 1 excludes a zero mask.
    for i in 1..n {
        let (_, _, p) = cs.multiply(wires[i - 1].into(), wires[n].into());
        cs.constrain(LinearCombination::from(p) - wires[i]);
    }
    let (_, _, p) = cs.multiply(wires[0].into(), wires[n + 1].into());
    cs.constrain(LinearCombination::from(p) - Scalar::one());
}
// Witness-dependent scalars: always use constant-time MSM in the prover.
fn eval_linear(
    current: &EncryptedPoly,
    weights: &[Scalar],
    eta: Scalar,
    pk: &PublicKey,
) -> Ciphertext {
    use std::iter::once;
    Ciphertext {
        c1: RistrettoPoint::multiscalar_mul(
            weights.iter().chain(once(&eta)),
            current.0.iter().map(|ct| &ct.c1).chain(once(&G)),
        ),
        c2: RistrettoPoint::multiscalar_mul(
            weights.iter().chain(once(&eta)),
            current.0.iter().map(|ct| &ct.c2).chain(once(&pk.0)),
        ),
    }
}
// Reference used to check the library adapter in tests.
#[cfg(test)]
fn eval_linear_public(
    current: &EncryptedPoly,
    weights: &[Scalar],
    eta: Scalar,
    pk: &PublicKey,
) -> Ciphertext {
    use curve25519_dalek_ng::traits::VartimeMultiscalarMul;
    use std::iter::once;
    Ciphertext {
        c1: RistrettoPoint::vartime_multiscalar_mul(
            weights.iter().chain(once(&eta)),
            current.0.iter().map(|ct| &ct.c1).chain(once(&G)),
        ),
        c2: RistrettoPoint::vartime_multiscalar_mul(
            weights.iter().chain(once(&eta)),
            current.0.iter().map(|ct| &ct.c2).chain(once(&pk.0)),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    sk2: &SecretKeyShare,
    current: &EncryptedPoly,
    m: Scalar,
    ctx: &ProofContext,
) -> Result<DivisionReply, String> {
    let current = EncodedPoly::from_native(current.clone());
    prove_with_candidate(rng, pk, pk1, pk2, sk2, &current, m, ctx).map(|(reply, _)| reply)
}
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn prove_with_candidate<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    sk2: &SecretKeyShare,
    current: &EncodedPoly,
    m: Scalar,
    ctx: &ProofContext,
) -> Result<(DivisionReply, EncodedPoly), String> {
    let computation_started_unix_ns = super::measurements::unix_ns().map_err(|e| e.to_string())?;
    prove_with_candidate_started_at(
        rng, pk, pk1, pk2, sk2, current, m, ctx, computation_started_unix_ns,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_with_candidate_started_at<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    sk2: &SecretKeyShare,
    current: &EncodedPoly,
    m: Scalar,
    ctx: &ProofContext,
    computation_started_unix_ns: u128,
) -> Result<(DivisionReply, EncodedPoly), String> {
    let mut mask = Scalar::random(rng);
    while mask == Scalar::zero() {
        mask = Scalar::random(rng);
    }
    let eta = Scalar::random(rng);
    prove_inner(
        rng,
        pk,
        pk1,
        pk2,
        sk2,
        current,
        m,
        mask,
        eta,
        computation_started_unix_ns,
        ctx,
    )
}
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn prove_with_mask<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    sk2: &SecretKeyShare,
    current: &EncryptedPoly,
    m: Scalar,
    mask: Scalar,
    eta: Scalar,
    ctx: &ProofContext,
) -> Result<DivisionReply, String> {
    let computation_started_unix_ns = super::measurements::unix_ns().map_err(|e| e.to_string())?;
    prove_inner(
        rng,
        pk,
        pk1,
        pk2,
        sk2,
        &EncodedPoly::from_native(current.clone()),
        m,
        mask,
        eta,
        computation_started_unix_ns,
        ctx,
    )
    .map(|(reply, _)| reply)
}
#[allow(clippy::too_many_arguments)]
fn prove_inner<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    sk2: &SecretKeyShare,
    encoded: &EncodedPoly,
    m: Scalar,
    mask: Scalar,
    eta: Scalar,
    computation_started_unix_ns: u128,
    ctx: &ProofContext,
) -> Result<(DivisionReply, EncodedPoly), String> {
    let current = encoded.native();
    let n = current.0.len();
    validate(pk, pk1, pk2, n, ctx)?;
    if mask == Scalar::zero() || mul_g(sk2.as_scalar()) != pk2.0 {
        return Err("invalid monitor witness".into());
    }
    let mut next = if n > 1 {
        elgamal::div_poly_linear(current, &m)
    } else {
        EncryptedPoly(vec![])
    };
    next.0.push(Ciphertext {
        c1: RistrettoPoint::identity(),
        c2: RistrettoPoint::identity(),
    });
    // Sending the deterministic quotient leaks a query-testing handle to a target
    // that knows the coefficient encryption randomness. Hide it with fresh zeros.
    let (next, quotient_randomness) =
        super::encryption::rerandomize_poly_with_witness(rng, pk, &next);
    // These witnesses express Q'[i-1] - C[i] = m Q'[i] + Enc(0; lambda[i]).
    let mut quotient_witness = Vec::with_capacity(n);
    quotient_witness
        .extend((1..n).map(|i| quotient_randomness[i - 1] - m * quotient_randomness[i]));
    quotient_witness.push(quotient_randomness[n - 1]);
    let mut values = Vec::with_capacity(n + 2);
    values.push(mask);
    for i in 1..n {
        values.push(values[i - 1] * m);
    }
    let scaled = eval_linear(current, &values, eta, pk);
    values.extend([m, mask.invert()]);
    let (partial, r) = elgamal::partial_decrypt_with_witness(rng, sk2, pk1, &scaled);
    let pc = PedersenGens::default();
    // Compress the reply's points once, for both the transcript and the wire.
    let next = EncodedPoly::from_native(next);
    let scaled_wire = WireCiphertext::from_native(&scaled);
    let partial_wire = WireCiphertext::from_native(&partial);
    let base = statement(
        pk,
        pk1,
        pk2,
        encoded.wire(),
        next.wire(),
        &scaled_wire,
        &partial_wire,
        ctx,
    );
    let mut t = base.clone();
    let mut prover = Prover::new(&pc, &mut t);
    let blinds: Vec<_> = values.iter().map(|_| Scalar::random(rng)).collect();
    let mut wires = Vec::with_capacity(n + 2);
    let mut variables = Vec::with_capacity(n + 2);
    for (v, b) in values.iter().zip(&blinds) {
        let (c, x) = prover.commit(*v, *b);
        wires.push(c.to_bytes());
        variables.push(x);
    }
    evaluation_gadget(&mut prover, &variables, n);
    let circuit = prover
        .prove(&generators(n))
        .map_err(|e| format!("monitor circuit: {e}"))?
        .to_bytes();
    let mut msg = DivisionReply {
        next: next.wire().clone(),
        computation_started_unix_ns,
        scaled: scaled_wire,
        partial: partial_wire,
        wires,
        circuit,
        sigma: super::sigma::Proof {
            challenge: Default::default(),
            response: vec![],
        },
    };
    complete_sigma_native(
        rng,
        pk,
        pk1,
        pk2,
        current,
        &mut msg,
        &MonitorWitness {
            values,
            blinds,
            eta,
            sk2: *sk2.as_scalar(),
            r,
            quotient: quotient_witness,
        },
        &next,
        &scaled,
        &partial,
        &base,
    )?;
    Ok((msg, next))
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct MonitorWitness {
    values: Vec<Scalar>,
    blinds: Vec<Scalar>,
    eta: Scalar,
    sk2: Scalar,
    r: Scalar,
    quotient: Vec<Scalar>,
}
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn complete_sigma<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    msg: &mut DivisionReply,
    witness: &MonitorWitness,
    ctx: &ProofContext,
) -> Result<(), String> {
    let next = EncodedPoly::from_wire(msg.next.clone())?;
    let scaled = msg.scaled.to_native()?;
    let partial = msg.partial.to_native()?;
    let base = statement(
        pk,
        pk1,
        pk2,
        &WireEncryptedPoly::from_native(current),
        next.wire(),
        &msg.scaled,
        &msg.partial,
        ctx,
    );
    complete_sigma_native(
        rng, pk, pk1, pk2, current, msg, witness, &next, &scaled, &partial, &base,
    )
}
#[allow(clippy::too_many_arguments)]
fn complete_sigma_native<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    msg: &mut DivisionReply,
    witness: &MonitorWitness,
    next: &EncodedPoly,
    scaled: &Ciphertext,
    partial: &Ciphertext,
    base: &Transcript,
) -> Result<(), String> {
    let n = current.0.len();
    let witness = zeroize::Zeroizing::new(
        witness
            .values
            .iter()
            .chain(&witness.blinds)
            .copied()
            .chain([witness.eta, witness.sk2, witness.r])
            .chain(witness.quotient.iter().copied())
            .collect::<Vec<_>>(),
    );
    let relation = sigma_statement(pk, pk1, pk2, current, msg, next, scaled, partial, base)?;
    msg.sigma = super::sigma::prover(3 * n + 7).prove(&witness, &relation, Some(rng));
    Ok(())
}

#[cfg(test)]
pub(crate) fn verify(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    msg: &DivisionReply,
    ctx: &ProofContext,
) -> Result<(EncryptedPoly, Ciphertext), String> {
    let current = EncodedPoly::from_native(current.clone());
    verify_encoded(pk, pk1, pk2, &current, msg, ctx)
        .map(|(next, partial)| (next.into_native(), partial))
}
pub(crate) fn verify_encoded(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    encoded: &EncodedPoly,
    msg: &DivisionReply,
    ctx: &ProofContext,
) -> Result<(EncodedPoly, Ciphertext), String> {
    let current = encoded.native();
    let n = current.0.len();
    validate(pk, pk1, pk2, n, ctx)?;
    if msg.next.0.len() != n
        || msg.wires.len() != n + 2
        || msg.sigma.response.len() != 3 * n + 7
        || msg.circuit.len() > 65536
    {
        return Err("invalid monitor proof dimensions".into());
    }
    let next = EncodedPoly::from_wire(msg.next.clone())?;
    let scaled = msg.scaled.to_native()?;
    let partial = msg.partial.to_native()?;
    let pc = PedersenGens::default();
    let base = statement(
        pk,
        pk1,
        pk2,
        encoded.wire(),
        next.wire(),
        &msg.scaled,
        &msg.partial,
        ctx,
    );
    let relation = sigma_statement(pk, pk1, pk2, current, msg, &next, &scaled, &partial, &base)?;
    if !super::sigma::prover(3 * n + 7).verify(&relation, &msg.sigma) {
        return Err(
            "monitor Sigma witness mismatch or division query/evaluation/decryption invalid".into(),
        );
    }
    let mut t = base;
    let mut verifier = Verifier::new(&mut t);
    let vars: Vec<_> = msg
        .wires
        .iter()
        .map(|c| verifier.commit(CompressedRistretto(*c)))
        .collect();
    evaluation_gadget(&mut verifier, &vars, n);
    let circuit =
        R1CSProof::from_bytes(&msg.circuit).map_err(|e| format!("monitor circuit decode: {e}"))?;
    verifier
        .verify(&circuit, &pc, &generators(n))
        .map_err(|e| format!("monitor circuit invalid: {e}"))?;
    Ok((next, partial))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exact::target::poly_from_roots;
    use rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn optimized_msm_and_native_candidate_match_reference_equations() {
        let mut rng = StdRng::seed_from_u64(61);
        let (_, pk1) = elgamal::generate_key_share(&mut rng);
        let (sk2, pk2) = elgamal::generate_key_share(&mut rng);
        let pk = PublicKey(pk1.0 + pk2.0);
        let ctx = ProofContext {
            session: [4; 32],
            round: 2,
        };
        for n in [1, 3, 17] {
            let coeffs: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let ct = elgamal::encrypt_poly(&mut rng, &pk, &coeffs);
            let weights: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let eta = Scalar::random(&mut rng);
            let mut expected = Ciphertext {
                c1: eta * G,
                c2: eta * pk.0,
            };
            for (c, e) in ct.0.iter().zip(&weights) {
                expected.c1 += e * c.c1;
                expected.c2 += e * c.c2;
            }
            let private = eval_linear(&ct, &weights, eta, &pk);
            let public = eval_linear_public(&ct, &weights, eta, &pk);
            assert_eq!(private.c1, expected.c1);
            assert_eq!(private.c2, expected.c2);
            assert_eq!(public.c1, expected.c1);
            assert_eq!(public.c2, expected.c2);
            let encoded = EncodedPoly::from_native(ct.clone());
            let (reply, native) = prove_with_candidate(
                &mut rng,
                &pk,
                &pk1,
                &pk2,
                &sk2,
                &encoded,
                Scalar::from(7u64),
                &ctx,
            )
            .unwrap();
            assert_eq!(
                bincode::serialize(&reply.next).unwrap(),
                bincode::serialize(&WireEncryptedPoly::from_native(native.native())).unwrap()
            );
            verify(&pk, &pk1, &pk2, &ct, &reply, &ctx).unwrap();
        }
    }
    // Malicious prover: permit circuit assignments, Sigma assignments, and
    // quotient query to disagree. This exercises verifier soundness rather than
    // relying on the honest prover to refuse invalid inputs.
    #[allow(clippy::too_many_arguments)]
    fn crafted_reply(
        rng: &mut StdRng,
        pk: &PublicKey,
        pk1: &PublicKeyShare,
        pk2: &PublicKeyShare,
        sk2: &SecretKeyShare,
        current: &EncryptedPoly,
        circuit_values: Vec<Scalar>,
        sigma_values: Vec<Scalar>,
        division_m: Scalar,
        corruption: usize,
        ctx: &ProofContext,
    ) -> Result<DivisionReply, String> {
        let n = current.0.len();
        let mut q = elgamal::div_poly_linear(current, &division_m);
        q.0.push(Ciphertext {
            c1: RistrettoPoint::identity(),
            c2: RistrettoPoint::identity(),
        });
        let (mut next, rho) = elgamal::rerandomize_poly_with_witness(rng, pk, &q);
        if corruption == 3 {
            next.0[n - 1].c2 += G;
        }
        let mut quotient: Vec<_> = (1..n).map(|i| rho[i - 1] - division_m * rho[i]).collect();
        quotient.push(rho[n - 1]);
        let eta = Scalar::from(19u64);
        let mut scaled = eval_linear(current, &sigma_values[..n], eta, pk);
        if corruption == 1 {
            scaled.c2 += G;
        }
        let (mut partial, r) = elgamal::partial_decrypt_with_witness(rng, sk2, pk1, &scaled);
        if corruption == 2 {
            partial.c2 += G;
        }
        let pc = PedersenGens::default();
        let mut t = statement(
            pk,
            pk1,
            pk2,
            &WireEncryptedPoly::from_native(current),
            &WireEncryptedPoly::from_native(&next),
            &WireCiphertext::from_native(&scaled),
            &WireCiphertext::from_native(&partial),
            ctx,
        );
        let mut prover = Prover::new(&pc, &mut t);
        let blinds: Vec<_> = circuit_values.iter().map(|_| Scalar::random(rng)).collect();
        let mut wires = vec![];
        let mut vars = vec![];
        for (v, b) in circuit_values.iter().zip(&blinds) {
            let (c, x) = prover.commit(*v, *b);
            wires.push(c.to_bytes());
            vars.push(x);
        }
        evaluation_gadget(&mut prover, &vars, n);
        let circuit = prover
            .prove(&generators(n))
            .map_err(|e| e.to_string())?
            .to_bytes();
        let mut msg = DivisionReply {
            computation_started_unix_ns: crate::exact::measurements::unix_ns().unwrap(),
            next: WireEncryptedPoly::from_native(&next),
            scaled: WireCiphertext::from_native(&scaled),
            partial: WireCiphertext::from_native(&partial),
            wires,
            circuit,
            sigma: crate::exact::sigma::Proof {
                challenge: Default::default(),
                response: vec![],
            },
        };
        complete_sigma(
            rng,
            pk,
            pk1,
            pk2,
            current,
            &mut msg,
            &MonitorWitness {
                values: sigma_values,
                blinds,
                eta,
                sk2: *sk2.as_scalar(),
                r,
                quotient,
            },
            ctx,
        )?;
        Ok(msg)
    }
    #[test]
    fn malicious_monitor_cannot_separate_circuit_evaluation_decryption_and_division() {
        let mut rng = StdRng::seed_from_u64(613);
        let (_, pk1) = elgamal::generate_key_share(&mut rng);
        let (sk2, pk2) = elgamal::generate_key_share(&mut rng);
        let pk = elgamal::combine_public_keys(&pk1, &pk2);
        let ctx = ProofContext {
            session: [6; 32],
            round: 4,
        };
        let m = Scalar::from(7u64);
        let mask = Scalar::from(13u64);
        let current =
            elgamal::encrypt_poly(&mut rng, &pk, &poly_from_roots(&[m, Scalar::from(42u64)]));
        let honest = vec![mask, mask * m, mask * m * m, m, mask.invert()];
        let accepted = crafted_reply(
            &mut rng,
            &pk,
            &pk1,
            &pk2,
            &sk2,
            &current,
            honest.clone(),
            honest.clone(),
            m,
            0,
            &ctx,
        )
        .unwrap();
        verify(&pk, &pk1, &pk2, &current, &accepted, &ctx).unwrap();
        let mut unrelated = honest.clone();
        unrelated[1] += Scalar::one();
        let attack = crafted_reply(
            &mut rng,
            &pk,
            &pk1,
            &pk2,
            &sk2,
            &current,
            honest.clone(),
            unrelated,
            m,
            0,
            &ctx,
        )
        .unwrap();
        assert!(verify(&pk, &pk1, &pk2, &current, &attack, &ctx)
            .unwrap_err()
            .contains("witness mismatch"));
        let different_query = crafted_reply(
            &mut rng,
            &pk,
            &pk1,
            &pk2,
            &sk2,
            &current,
            honest.clone(),
            honest.clone(),
            m + Scalar::one(),
            0,
            &ctx,
        )
        .unwrap();
        assert!(verify(&pk, &pk1, &pk2, &current, &different_query, &ctx)
            .unwrap_err()
            .contains("division query"));
        for corruption in 1..=3 {
            let attack = crafted_reply(
                &mut rng,
                &pk,
                &pk1,
                &pk2,
                &sk2,
                &current,
                honest.clone(),
                honest.clone(),
                m,
                corruption,
                &ctx,
            )
            .unwrap();
            assert!(verify(&pk, &pk1, &pk2, &current, &attack, &ctx).is_err());
        }
        // All linear group equations can be satisfied with zero weights. Only
        // the linked R1CS inverse constraint rules out this attack.
        let zero = vec![
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
            m,
            Scalar::zero(),
        ];
        let attack = crafted_reply(
            &mut rng,
            &pk,
            &pk1,
            &pk2,
            &sk2,
            &current,
            zero.clone(),
            zero,
            m,
            0,
            &ctx,
        )
        .unwrap();
        assert!(verify(&pk, &pk1, &pk2, &current, &attack, &ctx)
            .unwrap_err()
            .contains("circuit invalid"));
    }
    #[test]
    fn independent_encryption_randomness_and_quotient_blinding_preserve_matches() {
        let mut rng = StdRng::seed_from_u64(76);
        let (sk1, pk1) = elgamal::generate_key_share(&mut rng);
        let (sk2, pk2) = elgamal::generate_key_share(&mut rng);
        let pk = elgamal::combine_public_keys(&pk1, &pk2);
        let ctx = ProofContext {
            session: [8; 32],
            round: 1,
        };
        let roots = [Scalar::from(7u64), Scalar::from(42u64)];
        let current = elgamal::encrypt_poly(&mut rng, &pk, &poly_from_roots(&roots));
        for m in [roots[0], Scalar::from(99u64)] {
            let mut previous = None;
            for eta in [Scalar::zero(), Scalar::from(17u64)] {
                let msg = prove_with_mask(
                    &mut rng,
                    &pk,
                    &pk1,
                    &pk2,
                    &sk2,
                    &current,
                    m,
                    Scalar::from(13u64),
                    eta,
                    &ctx,
                )
                .unwrap();
                let (q, partial) = verify(&pk, &pk1, &pk2, &current, &msg, &ctx).unwrap();
                assert_eq!(elgamal::test_zero(&sk1, &partial), m == roots[0]);
                assert_ne!(q.0.last().unwrap().c1, RistrettoPoint::identity());
                if let Some(prior) = previous {
                    assert_ne!(msg.next.0[0].c1, prior);
                }
                previous = Some(msg.next.0[0].c1);
                // Re-randomization of every quotient coefficient preserves its plaintext.
                let mut raw = elgamal::div_poly_linear(&current, &m);
                raw.0.push(Ciphertext {
                    c1: RistrettoPoint::identity(),
                    c2: RistrettoPoint::identity(),
                });
                for (a, b) in raw.0.iter().zip(&q.0) {
                    let delta = Ciphertext {
                        c1: b.c1 - a.c1,
                        c2: b.c2 - a.c2,
                    };
                    let half = elgamal::partial_decrypt(&mut rng, &sk2, &pk1, &delta);
                    assert!(elgamal::test_zero(&sk1, &half));
                }
            }
        }
        assert!(prove_with_mask(
            &mut rng,
            &pk,
            &pk1,
            &pk2,
            &sk2,
            &current,
            roots[0],
            Scalar::zero(),
            Scalar::one(),
            &ctx
        )
        .is_err());
    }
    #[test]
    fn quotient_relation_and_context_are_checked() {
        let mut rng = StdRng::seed_from_u64(17);
        let (_, pk1) = elgamal::generate_key_share(&mut rng);
        let (sk2, pk2) = elgamal::generate_key_share(&mut rng);
        let pk = elgamal::combine_public_keys(&pk1, &pk2);
        let ctx = ProofContext {
            session: [3; 32],
            round: 1,
        };
        for roots in [
            vec![],
            vec![Scalar::from(7u64)],
            vec![Scalar::from(7u64), Scalar::from(42u64)],
        ] {
            for m in [Scalar::from(7u64), Scalar::from(99u64)] {
                let current = elgamal::encrypt_poly(&mut rng, &pk, &poly_from_roots(&roots));
                let msg = prove(&mut rng, &pk, &pk1, &pk2, &sk2, &current, m, &ctx).unwrap();
                let (next, _) = verify(&pk, &pk1, &pk2, &current, &msg, &ctx).unwrap();
                assert_eq!(next.0.len(), current.0.len());
                let bytes = bincode::serialize(&msg).unwrap();
                assert!(bincode::deserialize::<DivisionReply>(&bytes[..bytes.len() - 1]).is_err());
                let mut wrong_time: DivisionReply = bincode::deserialize(&bytes).unwrap();
                wrong_time.computation_started_unix_ns += 1;
                assert!(verify(&pk, &pk1, &pk2, &current, &wrong_time, &ctx).is_err());
                let mut wrong_ctx = ctx.clone();
                wrong_ctx.round += 1;
                assert!(verify(&pk, &pk1, &pk2, &current, &msg, &wrong_ctx).is_err());
                wrong_ctx = ctx.clone();
                wrong_ctx.session[0] ^= 1;
                assert!(verify(&pk, &pk1, &pk2, &current, &msg, &wrong_ctx).is_err());
                let mut wrong: DivisionReply = bincode::deserialize(&bytes).unwrap();
                wrong.next.0[0].c1 = (next.0[0].c1 + G).compress().to_bytes();
                assert!(verify(&pk, &pk1, &pk2, &current, &wrong, &ctx).is_err());
                let mut wrong: DivisionReply = bincode::deserialize(&bytes).unwrap();
                wrong.partial.c2 = (msg.partial.to_native().unwrap().c2 + G)
                    .compress()
                    .to_bytes();
                assert!(verify(&pk, &pk1, &pk2, &current, &wrong, &ctx).is_err());
                let mut wrong: DivisionReply = bincode::deserialize(&bytes).unwrap();
                wrong.sigma.response[2 * (current.0.len() + 2)] += Scalar::one();
                assert!(verify(&pk, &pk1, &pk2, &current, &wrong, &ctx).is_err());
            }
        }
    }
}
