//! Shared-witness Sigma–Bulletproof for evaluation, masking, decryption, and division.
use super::{
    performance::{generators, mul_g},
    proofs::ProofContext,
    target::{WireCiphertext, WireEncryptedPoly},
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
    traits::{Identity, MultiscalarMul, VartimeMultiscalarMul},
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Every Sigma equation below uses the same challenge and responses. No batching of
/// independent group equations: every committed wire and ciphertext component is checked.
#[derive(Serialize, Deserialize)]
pub(crate) struct DivisionReply {
    pub next: WireEncryptedPoly,
    scaled: WireCiphertext,
    partial: WireCiphertext,
    // e[0..n], m, inverse_mask, each committed as value*G + blind*H.
    wires: Vec<[u8; 32]>,
    circuit: Vec<u8>,
    opening_commitments: Vec<[u8; 32]>,
    evaluation_commitments: [[u8; 32]; 2],
    division_commitments: Vec<[[u8; 32]; 2]>,
    quotient_zero_commitments: [[u8; 32]; 2],
    quotient_responses: Vec<[u8; 32]>,
    partial_commitments: [[u8; 32]; 3],
    wire_responses: Vec<[[u8; 32]; 2]>,
    // Independent encryption rerandomization, decryption share, decryption rerandomization.
    extra_responses: [[u8; 32]; 3],
}
fn decode(b: [u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| "invalid monitor proof point".into())
}
fn scalar(b: [u8; 32]) -> Result<Scalar, String> {
    Scalar::from_canonical_bytes(b).ok_or_else(|| "noncanonical monitor proof scalar".into())
}
fn validate(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    n: usize,
    ctx: &ProofContext,
) -> Result<(), String> {
    if n == 0 || n > 4096 || ctx.round == 0 {
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
fn append_ct(t: &mut Transcript, label: &'static [u8], ct: &Ciphertext) {
    t.append_message(label, ct.c1.compress().as_bytes());
    t.append_message(label, ct.c2.compress().as_bytes());
}
#[allow(clippy::too_many_arguments)]
fn statement(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    next: &EncryptedPoly,
    scaled: &Ciphertext,
    partial: &Ciphertext,
    ctx: &ProofContext,
) -> Transcript {
    let mut t = Transcript::new(b"exact::monitor-sigma-bullet-v2");
    t.append_message(b"version", b"exact-pok-v4");
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
fn challenge(t: &mut Transcript, msg: &DivisionReply) -> Result<Scalar, String> {
    t.append_message(b"section", b"shared-witness-sigma");
    // Explicit lengths and canonical fixed-width encodings, including the R1CS proof.
    t.append_u64(b"wires", msg.wires.len() as u64);
    for c in &msg.wires {
        t.append_message(b"wire", c);
    }
    t.append_message(b"circuit", &msg.circuit);
    for c in &msg.opening_commitments {
        t.append_message(b"opening-A", c);
    }
    for c in &msg.evaluation_commitments {
        t.append_message(b"evaluation-A", c);
    }
    for pair in &msg.division_commitments {
        for c in pair {
            t.append_message(b"division-A", c);
        }
    }
    for c in &msg.quotient_zero_commitments {
        t.append_message(b"quotient-zero-A", c);
    }
    for c in &msg.partial_commitments {
        t.append_message(b"partial-A", c);
    }
    let mut bytes = [0; 64];
    t.challenge_bytes(b"challenge", &mut bytes);
    Ok(Scalar::from_bytes_mod_order_wide(&bytes))
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
// This is restricted to verifier responses, all of which are public.
fn eval_linear_public(
    current: &EncryptedPoly,
    weights: &[Scalar],
    eta: Scalar,
    pk: &PublicKey,
) -> Ciphertext {
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
    prove_with_candidate(rng, pk, pk1, pk2, sk2, current, m, ctx).map(|(reply, _)| reply)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_with_candidate<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    sk2: &SecretKeyShare,
    current: &EncryptedPoly,
    m: Scalar,
    ctx: &ProofContext,
) -> Result<(DivisionReply, EncryptedPoly), String> {
    let mut mask = Scalar::random(rng);
    while mask == Scalar::zero() {
        mask = Scalar::random(rng);
    }
    let eta = Scalar::random(rng);
    prove_inner(rng, pk, pk1, pk2, sk2, current, m, mask, eta, ctx)
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
    prove_inner(rng, pk, pk1, pk2, sk2, current, m, mask, eta, ctx).map(|(reply, _)| reply)
}
#[allow(clippy::too_many_arguments)]
fn prove_inner<R: RngCore + CryptoRng>(
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
) -> Result<(DivisionReply, EncryptedPoly), String> {
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
    let (next, quotient_randomness) = elgamal::rerandomize_poly_with_witness(rng, pk, &next);
    // These witnesses express Q'[i-1] - C[i] = m Q'[i] + Enc(0; lambda[i]).
    let mut quotient_witness: Vec<_> = (1..n)
        .map(|i| quotient_randomness[i - 1] - m * quotient_randomness[i])
        .collect();
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
    let base = statement(pk, pk1, pk2, current, &next, &scaled, &partial, ctx);
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
        next: WireEncryptedPoly::from_native(&next),
        scaled: WireCiphertext::from_native(&scaled),
        partial: WireCiphertext::from_native(&partial),
        wires,
        circuit,
        opening_commitments: vec![],
        evaluation_commitments: [[0; 32]; 2],
        division_commitments: vec![],
        quotient_zero_commitments: [[0; 32]; 2],
        quotient_responses: vec![],
        partial_commitments: [[0; 32]; 3],
        wire_responses: vec![],
        extra_responses: [[0; 32]; 3],
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
    let next = msg.next.to_native()?;
    let scaled = msg.scaled.to_native()?;
    let partial = msg.partial.to_native()?;
    let base = statement(pk, pk1, pk2, current, &next, &scaled, &partial, ctx);
    complete_sigma_native(
        rng, pk, pk1, pk2, current, msg, witness, &next, &scaled, &partial, &base,
    )
}
#[allow(clippy::too_many_arguments)]
fn complete_sigma_native<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    _pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    msg: &mut DivisionReply,
    witness: &MonitorWitness,
    next: &EncryptedPoly,
    scaled: &Ciphertext,
    _partial: &Ciphertext,
    base: &Transcript,
) -> Result<(), String> {
    let n = current.0.len();
    let MonitorWitness {
        values,
        blinds,
        eta,
        sk2,
        r,
        quotient: quotient_witness,
    } = witness;
    let pc = PedersenGens::default();
    let quotient_nonces: Vec<_> = (0..n).map(|_| Scalar::random(rng)).collect();
    let kv: Vec<_> = values.iter().map(|_| Scalar::random(rng)).collect();
    let kb: Vec<_> = values.iter().map(|_| Scalar::random(rng)).collect();
    let extras = [*eta, *sk2, *r];
    let k = [
        Scalar::random(rng),
        Scalar::random(rng),
        Scalar::random(rng),
    ];
    let opening_commitments = kv
        .iter()
        .zip(&kb)
        .map(|(v, b)| {
            RistrettoPoint::multiscalar_mul([*v, *b], [G, pc.B_blinding])
                .compress()
                .to_bytes()
        })
        .collect();
    let a = eval_linear(current, &kv[..n], k[0], pk);
    let evaluation_commitments = [a.c1.compress().to_bytes(), a.c2.compress().to_bytes()];
    let division_commitments = next
        .0
        .iter()
        .skip(1)
        .enumerate()
        .map(|(j, ct)| {
            [
                RistrettoPoint::multiscalar_mul([kv[n], quotient_nonces[j]], [ct.c1, G])
                    .compress()
                    .to_bytes(),
                RistrettoPoint::multiscalar_mul([kv[n], quotient_nonces[j]], [ct.c2, pk.0])
                    .compress()
                    .to_bytes(),
            ]
        })
        .collect();
    let quotient_zero_commitments = [
        mul_g(&quotient_nonces[n - 1]).compress().to_bytes(),
        (quotient_nonces[n - 1] * pk.0).compress().to_bytes(),
    ];
    let partial_commitments = [
        mul_g(&k[1]).compress().to_bytes(),
        mul_g(&k[2]).compress().to_bytes(),
        RistrettoPoint::multiscalar_mul([-k[1], k[2]], [scaled.c1, pk1.0])
            .compress()
            .to_bytes(),
    ];

    msg.opening_commitments = opening_commitments;
    msg.evaluation_commitments = evaluation_commitments;
    msg.division_commitments = division_commitments;
    msg.quotient_zero_commitments = quotient_zero_commitments;
    msg.partial_commitments = partial_commitments;
    let e = challenge(&mut base.clone(), msg)?;
    msg.wire_responses = (0..values.len())
        .map(|i| {
            [
                (kv[i] + e * values[i]).to_bytes(),
                (kb[i] + e * blinds[i]).to_bytes(),
            ]
        })
        .collect();
    msg.quotient_responses = (0..n)
        .map(|i| (quotient_nonces[i] + e * quotient_witness[i]).to_bytes())
        .collect();
    msg.extra_responses = std::array::from_fn(|i| (k[i] + e * extras[i]).to_bytes());
    Ok(())
}

pub(crate) fn verify(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    msg: &DivisionReply,
    ctx: &ProofContext,
) -> Result<(EncryptedPoly, Ciphertext), String> {
    let n = current.0.len();
    validate(pk, pk1, pk2, n, ctx)?;
    if msg.next.0.len() != n
        || msg.wires.len() != n + 2
        || msg.wire_responses.len() != n + 2
        || msg.opening_commitments.len() != n + 2
        || msg.division_commitments.len() != n - 1
        || msg.quotient_responses.len() != n
        || msg.circuit.len() > 65536
    {
        return Err("invalid monitor proof dimensions".into());
    }
    let next = msg.next.to_native()?;
    let scaled = msg.scaled.to_native()?;
    let partial = msg.partial.to_native()?;
    let pc = PedersenGens::default();
    let base = statement(pk, pk1, pk2, current, &next, &scaled, &partial, ctx);
    let e = challenge(&mut base.clone(), msg)?;
    let mut z = Vec::with_capacity(n + 2);
    for i in 0..n + 2 {
        let v = scalar(msg.wire_responses[i][0])?;
        let b = scalar(msg.wire_responses[i][1])?;
        if RistrettoPoint::vartime_multiscalar_mul(
            [v, b, -e, -Scalar::one()],
            [
                G,
                pc.B_blinding,
                decode(msg.wires[i])?,
                decode(msg.opening_commitments[i])?,
            ],
        ) != RistrettoPoint::identity()
        {
            return Err("monitor circuit/Sigma witness mismatch".into());
        }
        z.push(v);
    }
    let [zeta, zsk, zr] = msg.extra_responses.map(scalar);
    let (zeta, zsk, zr) = (zeta?, zsk?, zr?);
    let eval = eval_linear_public(current, &z[..n], zeta, pk);
    if eval.c1 != decode(msg.evaluation_commitments[0])? + e * scaled.c1
        || eval.c2 != decode(msg.evaluation_commitments[1])? + e * scaled.c2
    {
        return Err("incorrect masked/rerandomized evaluation".into());
    }
    if zsk * G != decode(msg.partial_commitments[0])? + e * pk2.0
        || zr * G != decode(msg.partial_commitments[1])? + e * (partial.c1 - scaled.c1)
        || -zsk * scaled.c1 + zr * pk1.0
            != decode(msg.partial_commitments[2])? + e * (partial.c2 - scaled.c2)
    {
        return Err("incorrect rerandomized partial decryption".into());
    }
    let ztop = scalar(msg.quotient_responses[n - 1])?;
    if ztop * G != decode(msg.quotient_zero_commitments[0])? + e * next.0[n - 1].c1
        || ztop * pk.0 != decode(msg.quotient_zero_commitments[1])? + e * next.0[n - 1].c2
    {
        return Err("quotient leading coefficient is not an encryption of zero".into());
    }
    for i in 1..n {
        let a = msg.division_commitments[i - 1];
        let zlambda = scalar(msg.quotient_responses[i - 1])?;
        if RistrettoPoint::vartime_multiscalar_mul(
            [z[n], zlambda, -e, -Scalar::one()],
            [
                next.0[i].c1,
                G,
                next.0[i - 1].c1 - current.0[i].c1,
                decode(a[0])?,
            ],
        ) != RistrettoPoint::identity()
            || RistrettoPoint::vartime_multiscalar_mul(
                [z[n], zlambda, -e, -Scalar::one()],
                [
                    next.0[i].c2,
                    pk.0,
                    next.0[i - 1].c2 - current.0[i].c2,
                    decode(a[1])?,
                ],
            ) != RistrettoPoint::identity()
        {
            return Err("division query mismatch or incorrect quotient".into());
        }
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
            let (reply, native) = prove_with_candidate(
                &mut rng,
                &pk,
                &pk1,
                &pk2,
                &sk2,
                &ct,
                Scalar::from(7u64),
                &ctx,
            )
            .unwrap();
            assert_eq!(
                bincode::serialize(&reply.next).unwrap(),
                bincode::serialize(&WireEncryptedPoly::from_native(&native)).unwrap()
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
        let mut t = statement(pk, pk1, pk2, current, &next, &scaled, &partial, ctx);
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
            next: WireEncryptedPoly::from_native(&next),
            scaled: WireCiphertext::from_native(&scaled),
            partial: WireCiphertext::from_native(&partial),
            wires,
            circuit,
            opening_commitments: vec![],
            evaluation_commitments: [[0; 32]; 2],
            division_commitments: vec![],
            quotient_zero_commitments: [[0; 32]; 2],
            quotient_responses: vec![],
            partial_commitments: [[0; 32]; 3],
            wire_responses: vec![],
            extra_responses: [[0; 32]; 3],
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
                wrong.extra_responses[0] = [255; 32];
                assert!(verify(&pk, &pk1, &pk2, &current, &wrong, &ctx).is_err());
            }
        }
    }
}
