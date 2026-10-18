//! Optional proofs for exact polynomial ciphertexts. Context is supplied locally by both peers.
use super::{
    performance::{generators, mul_g},
    target::poly_from_roots,
};
use crate::crypto::elgamal::{EncryptedPoly, PublicKey};
use bulletproofs::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof,
        RandomizableConstraintSystem, RandomizedConstraintSystem, Verifier,
    },
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

type Error = String;
const MAX_COEFFICIENTS: usize = 4096;

#[derive(Clone, Debug)]
pub struct ProofContext {
    pub session: [u8; 32],
    pub round: u64,
}

fn point(bytes: [u8; 32]) -> Result<RistrettoPoint, Error> {
    CompressedRistretto(bytes)
        .decompress()
        .ok_or_else(|| "invalid proof point".into())
}
fn scalar(bytes: [u8; 32]) -> Result<Scalar, Error> {
    Scalar::from_canonical_bytes(bytes).ok_or_else(|| "noncanonical proof scalar".into())
}
fn challenge(t: &mut Transcript) -> Scalar {
    let mut bytes = [0; 64];
    t.challenge_bytes(b"challenge", &mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}
fn append_poly(t: &mut Transcript, p: &EncryptedPoly) {
    t.append_u64(b"length", p.0.len() as u64);
    for c in &p.0 {
        t.append_message(b"U", c.c1.compress().as_bytes());
        t.append_message(b"V", c.c2.compress().as_bytes());
    }
}
fn transcript(domain: &'static [u8], pk: &PublicKey, ctx: &ProofContext) -> Transcript {
    let mut t = Transcript::new(domain);
    t.append_message(b"version", b"exact-pok-v4");
    t.append_message(b"session", &ctx.session);
    t.append_u64(b"round", ctx.round);
    t.append_message(b"pk", pk.0.compress().as_bytes());
    t
}
fn validate_key(pk: &PublicKey) -> Result<(), Error> {
    if pk.0 == RistrettoPoint::identity() {
        return Err("identity encryption key".into());
    }
    Ok(())
}
fn dimensions(polys: &[&EncryptedPoly]) -> Result<usize, Error> {
    let n = polys[0].0.len();
    if n == 0 || n > MAX_COEFFICIENTS || polys.iter().any(|p| p.0.len() != n) {
        return Err("invalid polynomial dimensions".into());
    }
    Ok(n)
}

/// Two complete vector Chaum–Pedersen transcripts, with a single challenge per branch.
/// The serialized representation contains no real-branch selector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrRerandProof {
    challenges: [[u8; 32]; 2],
    responses: [Vec<[u8; 32]>; 2],
}
fn or_transcript(
    pk: &PublicKey,
    old: &EncryptedPoly,
    next: &EncryptedPoly,
    new: &EncryptedPoly,
    ctx: &ProofContext,
    a: &[Vec<[[u8; 32]; 2]>; 2],
) -> Transcript {
    let mut t = transcript(b"exact::cds94-rerandomization-v2", pk, ctx);
    for p in [old, next, new] {
        append_poly(&mut t, p);
    }
    for branch in a {
        for pair in branch {
            for p in pair {
                t.append_message(b"commitment", p);
            }
        }
    }
    t
}
#[allow(clippy::too_many_arguments)]
pub fn prove_rerandomization_or<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    old: &EncryptedPoly,
    next: &EncryptedPoly,
    new: &EncryptedPoly,
    real_branch: usize,
    witness: &[Scalar],
    ctx: &ProofContext,
) -> Result<OrRerandProof, Error> {
    validate_key(pk)?;
    let n = dimensions(&[old, next, new])?;
    if ctx.round < 2 || real_branch > 1 || witness.len() != n {
        return Err("invalid OR witness/context".into());
    }
    let candidates = [old, next];
    let fake = 1 - real_branch;
    let mut e = [Scalar::zero(); 2];
    e[fake] = Scalar::random(rng);
    let mut z = [vec![Scalar::zero(); n], vec![Scalar::zero(); n]];
    let mut a = [Vec::with_capacity(n), Vec::with_capacity(n)];
    let nonces: Vec<_> = (0..n).map(|_| Scalar::random(rng)).collect();
    for b in 0..2 {
        for (i, nonce) in nonces.iter().enumerate() {
            let du = new.0[i].c1 - candidates[b].0[i].c1;
            let dv = new.0[i].c2 - candidates[b].0[i].c2;
            let (u, v) = if b == real_branch {
                if du != mul_g(&witness[i]) || dv != witness[i] * pk.0 {
                    return Err("invalid rerandomization witness".into());
                }
                (mul_g(nonce), nonce * pk.0)
            } else {
                z[b][i] = Scalar::random(rng);
                (
                    RistrettoPoint::multiscalar_mul([z[b][i], -e[b]], [G, du]),
                    RistrettoPoint::multiscalar_mul([z[b][i], -e[b]], [pk.0, dv]),
                )
            };
            a[b].push([u.compress().to_bytes(), v.compress().to_bytes()]);
        }
    }
    e[real_branch] = challenge(&mut or_transcript(pk, old, next, new, ctx, &a)) - e[fake];
    for i in 0..n {
        z[real_branch][i] = nonces[i] + e[real_branch] * witness[i];
    }
    Ok(OrRerandProof {
        challenges: e.map(|s| s.to_bytes()),
        responses: z.map(|v| v.iter().map(Scalar::to_bytes).collect()),
    })
}
pub fn verify_rerandomization_or(
    pk: &PublicKey,
    old: &EncryptedPoly,
    next: &EncryptedPoly,
    new: &EncryptedPoly,
    proof: &OrRerandProof,
    ctx: &ProofContext,
) -> Result<(), Error> {
    validate_key(pk)?;
    let n = dimensions(&[old, next, new])?;
    if ctx.round < 2 || proof.responses.iter().any(|v| v.len() != n) {
        return Err("invalid OR proof dimensions/context".into());
    }
    let e = [scalar(proof.challenges[0])?, scalar(proof.challenges[1])?];
    // Compressed CDS representation (e_0,e_1,z_0,z_1). Reconstruct both complete
    // polynomial commitments, hash them in branch order, then check e_0+e_1=H.
    // Expanding an accepted proof yields exactly the original CDS transcript.
    let mut commitments = [Vec::with_capacity(n), Vec::with_capacity(n)];
    for (b, candidate) in [old, next].iter().enumerate() {
        for i in 0..n {
            let z = scalar(proof.responses[b][i])?;
            let du = new.0[i].c1 - candidate.0[i].c1;
            let dv = new.0[i].c2 - candidate.0[i].c2;
            let u = RistrettoPoint::vartime_multiscalar_mul([z, -e[b]], [G, du]);
            let v = RistrettoPoint::vartime_multiscalar_mul([z, -e[b]], [pk.0, dv]);
            commitments[b].push([u.compress().to_bytes(), v.compress().to_bytes()]);
        }
    }
    if e[0] + e[1] != challenge(&mut or_transcript(pk, old, next, new, ctx, &commitments)) {
        return Err("OR challenge mismatch".into());
    }
    Ok(())
}

/// Bulletproof R1CS proves committed coefficients are the product of committed roots.
/// A shared-witness Sigma proof links every coefficient commitment to its ElGamal ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialPoK {
    roots: Vec<[u8; 32]>,
    coefficients: Vec<[u8; 32]>,
    circuit: Vec<u8>,
    commitments: Vec<[[u8; 32]; 3]>,
    responses: Vec<[[u8; 32]; 3]>,
}
/// Coefficients and roots are committed BEFORE the random evaluation point.
/// The monic constraint fixes the leading term, so an incorrect relation has
/// at most d-1 roots. Error <=(d-1)/q per attempt, in addition to R1CS/FS security.
fn polynomial_gadget<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    roots: Vec<LinearCombination>,
    coefficients: Vec<LinearCombination>,
) -> Result<(), R1CSError> {
    let d = roots.len();
    cs.constrain(coefficients[d].clone() - Scalar::one());
    if d == 0 {
        return Ok(());
    }
    if d == 1 {
        cs.constrain(coefficients[0].clone() + roots[0].clone());
        return Ok(());
    }
    cs.specify_randomized_constraints(move |cs| {
        let z = cs.challenge_scalar(b"initial-polynomial-identity-point");
        let mut product = LinearCombination::from(z) - roots[0].clone();
        for root in roots.into_iter().skip(1) {
            let (_, _, out) = cs.multiply(product, LinearCombination::from(z) - root);
            product = out.into();
        }
        let mut power = Scalar::one();
        let mut evaluation = LinearCombination::from(Scalar::zero());
        for coefficient in coefficients {
            evaluation = evaluation + coefficient * power;
            power *= z;
        }
        cs.constrain(product - evaluation);
        Ok(())
    })
}
fn initial_multipliers(coefficients: usize) -> usize {
    coefficients.saturating_sub(2)
}
fn initial_transcript(pk: &PublicKey, ct: &EncryptedPoly, ctx: &ProofContext) -> Transcript {
    let mut t = transcript(b"exact::initial-set-pok-v2", pk, ctx);
    append_poly(&mut t, ct);
    t
}
fn glue_transcript(base: &Transcript, proof: &InitialPoK) -> Transcript {
    let mut t = base.clone();
    t.append_message(b"section", b"coefficient-encryption-link");
    for c in &proof.roots {
        t.append_message(b"root", c);
    }
    for c in &proof.coefficients {
        t.append_message(b"coefficient", c);
    }
    t.append_message(b"r1cs", &proof.circuit);
    for triple in &proof.commitments {
        for a in triple {
            t.append_message(b"A", a);
        }
    }
    t
}
#[allow(clippy::too_many_arguments)]
pub fn generate_initial_pok<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    set: &[Scalar],
    randomness: &[Scalar],
    ct: &EncryptedPoly,
    ctx: &ProofContext,
) -> Result<InitialPoK, Error> {
    validate_key(pk)?;
    let n = dimensions(&[ct])?;
    if ctx.round != 1 || set.len() + 1 != n || randomness.len() != n {
        return Err("invalid initial witness/context".into());
    }
    let coeffs = poly_from_roots(set);
    generate_initial_with_coefficients(rng, pk, set, &coeffs, randomness, ct, ctx)
}

/// Compute plaintext coefficients once and keep encryption randomness local.
pub(crate) fn encrypt_and_prove_initial<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    set: &[Scalar],
    ctx: &ProofContext,
) -> Result<(EncryptedPoly, InitialPoK), Error> {
    use crate::crypto::elgamal::Ciphertext;
    if set.len() >= MAX_COEFFICIENTS {
        return Err("invalid initial set dimensions".into());
    }
    let coeffs = zeroize::Zeroizing::new(poly_from_roots(set));
    let randomness = zeroize::Zeroizing::new(
        (0..coeffs.len())
            .map(|_| Scalar::random(rng))
            .collect::<Vec<_>>(),
    );
    let ct = EncryptedPoly(
        coeffs
            .iter()
            .zip(randomness.iter())
            .map(|(m, r)| Ciphertext {
                c1: mul_g(r),
                c2: mul_g(m) + r * pk.0,
            })
            .collect(),
    );
    let proof = generate_initial_with_coefficients(rng, pk, set, &coeffs, &randomness, &ct, ctx)?;
    Ok((ct, proof))
}
#[allow(clippy::too_many_arguments)]
fn generate_initial_with_coefficients<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    set: &[Scalar],
    coeffs: &[Scalar],
    randomness: &[Scalar],
    ct: &EncryptedPoly,
    ctx: &ProofContext,
) -> Result<InitialPoK, Error> {
    validate_key(pk)?;
    let n = dimensions(&[ct])?;
    if ctx.round != 1 || set.len() + 1 != n || coeffs.len() != n || randomness.len() != n {
        return Err("invalid initial witness/context".into());
    }
    for i in 0..n {
        if ct.0[i].c1 != mul_g(&randomness[i])
            || ct.0[i].c2 != mul_g(&coeffs[i]) + randomness[i] * pk.0
        {
            return Err("incorrect set/encryption relation".into());
        }
    }
    let pc = PedersenGens::default();
    let base = initial_transcript(pk, ct, ctx);
    let mut t = base.clone();
    let mut prover = Prover::new(&pc, &mut t);
    let mut proof = InitialPoK {
        roots: Vec::with_capacity(n - 1),
        coefficients: Vec::with_capacity(n),
        circuit: vec![],
        commitments: Vec::with_capacity(n),
        responses: Vec::with_capacity(n),
    };
    let mut roots = Vec::with_capacity(n - 1);
    for s in set {
        let (c, v) = prover.commit(*s, Scalar::random(rng));
        proof.roots.push(c.to_bytes());
        roots.push(v.into());
    }
    let blinds: Vec<_> = (0..n).map(|_| Scalar::random(rng)).collect();
    let mut vars = Vec::with_capacity(n);
    for i in 0..n {
        let (c, v) = prover.commit(coeffs[i], blinds[i]);
        proof.coefficients.push(c.to_bytes());
        vars.push(v.into());
    }
    polynomial_gadget(&mut prover, roots, vars).map_err(|e| format!("initial gadget: {e}"))?;
    proof.circuit = prover
        .prove(&generators(initial_multipliers(n)))
        .map_err(|e| format!("initial prove: {e}"))?
        .to_bytes();
    let nonces: Vec<[Scalar; 3]> = (0..n)
        .map(|_| {
            [
                Scalar::random(rng),
                Scalar::random(rng),
                Scalar::random(rng),
            ]
        })
        .collect();
    for a in &nonces {
        proof.commitments.push([
            RistrettoPoint::multiscalar_mul([a[0], a[1]], [G, pc.B_blinding])
                .compress()
                .to_bytes(),
            mul_g(&a[2]).compress().to_bytes(),
            RistrettoPoint::multiscalar_mul([a[0], a[2]], [G, pk.0])
                .compress()
                .to_bytes(),
        ]);
    }
    let e = challenge(&mut glue_transcript(&base, &proof));
    for i in 0..n {
        proof.responses.push([
            (nonces[i][0] + e * coeffs[i]).to_bytes(),
            (nonces[i][1] + e * blinds[i]).to_bytes(),
            (nonces[i][2] + e * randomness[i]).to_bytes(),
        ]);
    }
    Ok(proof)
}
pub fn verify_initial_pok(
    pk: &PublicKey,
    ct: &EncryptedPoly,
    proof: &InitialPoK,
    ctx: &ProofContext,
) -> Result<(), Error> {
    validate_key(pk)?;
    let n = dimensions(&[ct])?;
    if ctx.round != 1
        || proof.roots.len() + 1 != n
        || proof.coefficients.len() != n
        || proof.commitments.len() != n
        || proof.responses.len() != n
        || proof.circuit.len() > 65536
    {
        return Err("invalid initial proof dimensions/context".into());
    }
    let pc = PedersenGens::default();
    let base = initial_transcript(pk, ct, ctx);
    let e = challenge(&mut glue_transcript(&base, proof));
    for i in 0..n {
        let z = proof.responses[i].map(scalar);
        let [zm, zb, zr] = z;
        let (zm, zb, zr) = (zm?, zb?, zr?);
        let a = proof.commitments[i];
        if RistrettoPoint::vartime_multiscalar_mul(
            [zm, zb, -e, -Scalar::one()],
            [
                G,
                pc.B_blinding,
                point(proof.coefficients[i])?,
                point(a[0])?,
            ],
        ) != RistrettoPoint::identity()
            || RistrettoPoint::vartime_multiscalar_mul(
                [zr, -e, -Scalar::one()],
                [G, ct.0[i].c1, point(a[1])?],
            ) != RistrettoPoint::identity()
            || RistrettoPoint::vartime_multiscalar_mul(
                [zm, zr, -e, -Scalar::one()],
                [G, pk.0, ct.0[i].c2, point(a[2])?],
            ) != RistrettoPoint::identity()
        {
            return Err("invalid coefficient/encryption link".into());
        }
    }
    let mut t = base;
    let mut verifier = Verifier::new(&mut t);
    let roots = proof
        .roots
        .iter()
        .map(|c| verifier.commit(CompressedRistretto(*c)).into())
        .collect();
    let coeffs = proof
        .coefficients
        .iter()
        .map(|c| verifier.commit(CompressedRistretto(*c)).into())
        .collect();
    polynomial_gadget(&mut verifier, roots, coeffs).map_err(|e| format!("initial gadget: {e}"))?;
    let circuit =
        R1CSProof::from_bytes(&proof.circuit).map_err(|e| format!("initial decode: {e}"))?;
    verifier
        .verify(&circuit, &pc, &generators(initial_multipliers(n)))
        .map_err(|e| format!("initial verification: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{encrypt_poly, generate_key_share, rerandomize_poly_with_witness};
    use rand::{rngs::StdRng, SeedableRng};
    fn fixture() -> (StdRng, PublicKey, ProofContext) {
        let mut rng = StdRng::seed_from_u64(84);
        let (_, pk) = generate_key_share(&mut rng);
        (
            rng,
            PublicKey(pk.0),
            ProofContext {
                session: [7; 32],
                round: 1,
            },
        )
    }
    #[test]
    fn randomized_identity_rejects_fully_linked_but_incorrect_polynomials() {
        let (mut rng, pk, ctx) = fixture();
        for set in [
            vec![],
            vec![Scalar::from(2u64)],
            vec![Scalar::from(2u64), Scalar::from(5u64)],
            vec![Scalar::from(2u64); 7],
        ] {
            let correct = poly_from_roots(&set);
            for index in 0..correct.len() {
                let mut coeffs = correct.clone();
                coeffs[index] += Scalar::one();
                let randomness: Vec<_> = coeffs.iter().map(|_| Scalar::random(&mut rng)).collect();
                let ct = EncryptedPoly(
                    coeffs
                        .iter()
                        .zip(&randomness)
                        .map(|(m, r)| crate::crypto::elgamal::Ciphertext {
                            c1: mul_g(r),
                            c2: mul_g(m) + r * pk.0,
                        })
                        .collect(),
                );
                // The encryption link is fully valid. Only the polynomial relation
                // (including the monic constraint) rejects this malicious witness.
                let proof = generate_initial_with_coefficients(
                    &mut rng,
                    &pk,
                    &set,
                    &coeffs,
                    &randomness,
                    &ct,
                    &ctx,
                )
                .unwrap();
                assert!(verify_initial_pok(&pk, &ct, &proof, &ctx).is_err());
            }
        }
        assert_eq!(initial_multipliers(1001), 999);
        assert_eq!(generators(initial_multipliers(1001)).gens_capacity, 1024);
    }
    #[test]
    fn identity_challenge_binds_root_coefficient_and_public_statement_commitments() {
        let (mut rng, pk, ctx) = fixture();
        let set = vec![Scalar::from(3u64), Scalar::from(7u64), Scalar::from(11u64)];
        let (ct, proof) = encrypt_and_prove_initial(&mut rng, &pk, &set, &ctx).unwrap();
        verify_initial_pok(&pk, &ct, &proof, &ctx).unwrap();
        for coefficient in [false, true] {
            let mut changed = proof.clone();
            if coefficient {
                changed.coefficients[0] = proof.coefficients[1];
            } else {
                changed.roots[0] = proof.roots[1];
            }
            assert!(verify_initial_pok(&pk, &ct, &changed, &ctx).is_err());
        }
        assert!(verify_initial_pok(&PublicKey(pk.0 + G), &ct, &proof, &ctx).is_err());
    }
    #[derive(Serialize)]
    struct ExpandedOrReference {
        commitments: [Vec<[[u8; 32]; 2]>; 2],
        challenges: [[u8; 32]; 2],
        responses: [Vec<[u8; 32]>; 2],
    }
    #[allow(clippy::too_many_arguments)]
    fn reference_or(
        rng: &mut StdRng,
        pk: &PublicKey,
        old: &EncryptedPoly,
        next: &EncryptedPoly,
        new: &EncryptedPoly,
        b: usize,
        witness: &[Scalar],
        ctx: &ProofContext,
    ) -> ExpandedOrReference {
        let n = old.0.len();
        let fake = 1 - b;
        let mut e = [Scalar::zero(); 2];
        e[fake] = Scalar::random(rng);
        let k: Vec<_> = (0..n).map(|_| Scalar::random(rng)).collect();
        let mut z = [vec![Scalar::zero(); n], vec![Scalar::zero(); n]];
        let mut a = [Vec::with_capacity(n), Vec::with_capacity(n)];
        for branch in 0..2 {
            for (i, nonce) in k.iter().enumerate() {
                let source = [old, next][branch];
                let (u, v) = if branch == b {
                    (nonce * G, nonce * pk.0)
                } else {
                    z[branch][i] = Scalar::random(rng);
                    (
                        z[branch][i] * G - e[branch] * (new.0[i].c1 - source.0[i].c1),
                        z[branch][i] * pk.0 - e[branch] * (new.0[i].c2 - source.0[i].c2),
                    )
                };
                a[branch].push([u.compress().to_bytes(), v.compress().to_bytes()]);
            }
        }
        e[b] = challenge(&mut or_transcript(pk, old, next, new, ctx, &a)) - e[fake];
        for i in 0..n {
            z[b][i] = k[i] + e[b] * witness[i];
        }
        ExpandedOrReference {
            commitments: a,
            challenges: e.map(|s| s.to_bytes()),
            responses: z.map(|v| v.iter().map(Scalar::to_bytes).collect()),
        }
    }
    #[test]
    fn compressed_cds_matches_expanded_reference_for_both_branches() {
        let (mut rng, pk, mut ctx) = fixture();
        ctx.round = 2;
        for n in [1, 3, 17] {
            let old = encrypt_poly(&mut rng, &pk, &vec![Scalar::one(); n]);
            let next = encrypt_poly(&mut rng, &pk, &vec![Scalar::from(2u64); n]);
            for b in 0..2 {
                let (new, w) = rerandomize_poly_with_witness(&mut rng, &pk, [&old, &next][b]);
                let expanded = reference_or(&mut rng, &pk, &old, &next, &new, b, &w, &ctx);
                let packed = OrRerandProof {
                    challenges: expanded.challenges,
                    responses: expanded.responses.clone(),
                };
                verify_rerandomization_or(&pk, &old, &next, &new, &packed, &ctx).unwrap();
                assert_eq!(
                    bincode::serialized_size(&expanded).unwrap() + 4,
                    192 * n as u64 + 100
                );
                assert_eq!(
                    bincode::serialized_size(&super::super::TPolyProof::RerandomizationOr(packed))
                        .unwrap(),
                    64 * n as u64 + 84
                );
            }
        }
        let packed = OrRerandProof {
            challenges: [[0; 32]; 2],
            responses: [vec![[0; 32]; 1001], vec![[0; 32]; 1001]],
        };
        assert_eq!(
            bincode::serialized_size(&super::super::TPolyProof::RerandomizationOr(packed)).unwrap(),
            64148
        );
    }
    #[test]
    fn initial_relation_and_binding() {
        for set in [
            vec![],
            vec![Scalar::from(3u64)],
            vec![Scalar::from(2u64), Scalar::from(2u64), Scalar::from(5u64)],
        ] {
            let (mut rng, pk, ctx) = fixture();
            let coeffs = poly_from_roots(&set);
            let r: Vec<_> = coeffs.iter().map(|_| Scalar::random(&mut rng)).collect();
            let ct = EncryptedPoly(
                coeffs
                    .iter()
                    .zip(&r)
                    .map(|(m, r)| crate::crypto::elgamal::Ciphertext {
                        c1: r * G,
                        c2: m * G + r * pk.0,
                    })
                    .collect(),
            );
            let p = generate_initial_pok(&mut rng, &pk, &set, &r, &ct, &ctx).unwrap();
            verify_initial_pok(&pk, &ct, &p, &ctx).unwrap();
            let bytes = bincode::serialize(&p).unwrap();
            let decoded = bincode::deserialize(&bytes).unwrap();
            verify_initial_pok(&pk, &ct, &decoded, &ctx).unwrap();
            assert!(bincode::deserialize::<InitialPoK>(&bytes[..bytes.len() - 1]).is_err());
            let mut other = ctx.clone();
            other.session[0] ^= 1;
            assert!(verify_initial_pok(&pk, &ct, &p, &other).is_err());
            other = ctx.clone();
            other.round = 2;
            assert!(verify_initial_pok(&pk, &ct, &p, &other).is_err());
            let mut wrong = ct.clone();
            wrong.0[0].c2 += G;
            assert!(verify_initial_pok(&pk, &wrong, &p, &ctx).is_err());
            assert!(generate_initial_pok(&mut rng, &pk, &set, &r, &wrong, &ctx).is_err());
            let mut damaged = p.clone();
            damaged.responses[0][0] = [255; 32];
            assert!(verify_initial_pok(&pk, &ct, &damaged, &ctx).is_err());
            damaged = p.clone();
            damaged.circuit[0] ^= 1;
            assert!(verify_initial_pok(&pk, &ct, &damaged, &ctx).is_err());
            let mut wrong_set = set.clone();
            wrong_set.push(Scalar::one());
            assert!(generate_initial_pok(&mut rng, &pk, &wrong_set, &r, &ct, &ctx).is_err());
        }
    }
    #[test]
    fn or_both_branches_and_tampering() {
        let (mut rng, pk, mut ctx) = fixture();
        ctx.round = 2;
        for n in [1, 3, 5] {
            let old = encrypt_poly(&mut rng, &pk, &vec![Scalar::one(); n]);
            let next = encrypt_poly(&mut rng, &pk, &vec![Scalar::from(2u64); n]);
            for b in 0..2 {
                let (new, w) = rerandomize_poly_with_witness(&mut rng, &pk, [&old, &next][b]);
                let p = prove_rerandomization_or(&mut rng, &pk, &old, &next, &new, b, &w, &ctx)
                    .unwrap();
                verify_rerandomization_or(&pk, &old, &next, &new, &p, &ctx).unwrap();
                let bytes = bincode::serialize(&p).unwrap();
                assert!(bincode::deserialize::<OrRerandProof>(&bytes[..bytes.len() - 1]).is_err());
                let mut other = ctx.clone();
                other.round += 1;
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &p, &other).is_err());
                other = ctx.clone();
                other.session[0] ^= 1;
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &p, &other).is_err());
                assert!(verify_rerandomization_or(
                    &PublicKey(pk.0 + G),
                    &old,
                    &next,
                    &new,
                    &p,
                    &ctx
                )
                .is_err());
                let mut wrong = old.clone();
                wrong.0[0].c1 += G;
                assert!(verify_rerandomization_or(&pk, &wrong, &next, &new, &p, &ctx).is_err());
                let mut wrong = next.clone();
                wrong.0[0].c2 += G;
                assert!(verify_rerandomization_or(&pk, &old, &wrong, &new, &p, &ctx).is_err());
                let mut wrong = new.clone();
                wrong.0[0].c2 += G;
                assert!(verify_rerandomization_or(&pk, &old, &next, &wrong, &p, &ctx).is_err());
                let mut damaged = p.clone();
                damaged.responses[0][0] = [255; 32];
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &damaged, &ctx).is_err());
                damaged = p.clone();
                damaged.challenges[0] = Scalar::zero().to_bytes();
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &damaged, &ctx).is_err());
                damaged = p.clone();
                damaged.responses[1][0] = [255; 32];
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &damaged, &ctx).is_err());
                damaged = p.clone();
                damaged.responses[0].pop();
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &damaged, &ctx).is_err());
            }
            if n > 1 {
                let (mut mixed, w) = rerandomize_poly_with_witness(&mut rng, &pk, &old);
                mixed.0[1] = rerandomize_poly_with_witness(&mut rng, &pk, &next).0 .0[1].clone();
                for b in 0..2 {
                    assert!(prove_rerandomization_or(
                        &mut rng, &pk, &old, &next, &mixed, b, &w, &ctx
                    )
                    .is_err());
                }
            }
        }
    }
}
