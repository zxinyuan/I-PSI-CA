//! Optional proofs for exact polynomial ciphertexts. Context is supplied locally by both peers.
use super::encryption::encrypt_with_randomness;
use super::performance::table;
use super::sigma::{Base, Statement};
use super::target::{poly_from_roots, EncodedPoly, WireEncryptedPoly};
use crate::crypto::elgamal::{EncryptedPoly, PublicKey};
use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

type Error = String;
use super::MAX_COEFFICIENTS;

#[derive(Clone, Debug)]
pub struct ProofContext {
    pub session: [u8; 32],
    pub round: u64,
}

fn append_poly(t: &mut Transcript, p: &WireEncryptedPoly) {
    t.append_u64(b"length", p.0.len() as u64);
    for c in &p.0 {
        t.append_message(b"U", &c.c1);
        t.append_message(b"V", &c.c2);
    }
}
fn transcript(domain: &'static [u8], pk: &PublicKey, ctx: &ProofContext) -> Transcript {
    let mut t = Transcript::new(domain);
    t.append_message(b"version", b"exact-pok-v7");
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
fn dimensions(polys: &[&EncodedPoly]) -> Result<usize, Error> {
    let n = polys[0].native().0.len();
    if n == 0 || n > MAX_COEFFICIENTS || polys.iter().any(|p| p.native().0.len() != n) {
        return Err("invalid polynomial dimensions".into());
    }
    Ok(n)
}

/// Library OR composition of two complete vector rerandomization relations.
/// The proof contains no real-branch selector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrRerandProof {
    sigma: super::sigma::OrProof,
}
fn rerandomization_statement(
    pk: &PublicKey,
    source: &EncryptedPoly,
    new: &EncryptedPoly,
    context: [u8; 32],
) -> Statement {
    let mut relation = Statement::new(context);
    let (g, h) = (relation.fixed(G), relation.fixed(pk.0));
    for (i, (a, b)) in source.0.iter().zip(&new.0).enumerate() {
        relation.add(b.c1 - a.c1, [(i, g)]);
        relation.add(b.c2 - a.c2, [(i, h)]);
    }
    relation
}
fn or_statements(
    pk: &PublicKey,
    old: &EncodedPoly,
    next: &EncodedPoly,
    new: &EncodedPoly,
    ctx: &ProofContext,
) -> (Statement, Statement) {
    let mut t = transcript(b"exact::sigma-fun-rerandomization-or-v1", pk, ctx);
    for p in [old, next, new] {
        append_poly(&mut t, p.wire());
    }
    let context = super::sigma::context(t);
    (
        rerandomization_statement(pk, old.native(), new.native(), context),
        rerandomization_statement(pk, next.native(), new.native(), context),
    )
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
    let [o, x, w] = [old, next, new].map(|p| EncodedPoly::from_native(p.clone()));
    prove_rerandomization_or_encoded(rng, pk, &o, &x, &w, real_branch, witness, ctx)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_rerandomization_or_encoded<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    old: &EncodedPoly,
    next: &EncodedPoly,
    new: &EncodedPoly,
    real_branch: usize,
    witness: &[Scalar],
    ctx: &ProofContext,
) -> Result<OrRerandProof, Error> {
    validate_key(pk)?;
    let n = dimensions(&[old, next, new])?;
    if ctx.round < 2 || real_branch > 1 || witness.len() != n {
        return Err("invalid OR witness/context".into());
    }
    let statement = or_statements(pk, old, next, new, ctx);
    let real = if real_branch == 0 {
        &statement.0
    } else {
        &statement.1
    };
    if !real.satisfied_by(witness) {
        return Err("invalid rerandomization witness".into());
    }
    let witness = if real_branch == 0 {
        sigma_fun::Either::Left(zeroize::Zeroizing::new(witness.to_vec()))
    } else {
        sigma_fun::Either::Right(zeroize::Zeroizing::new(witness.to_vec()))
    };
    let sigma = super::sigma::or_prover(n).prove(&witness, &statement, Some(rng));
    Ok(OrRerandProof { sigma })
}
pub fn verify_rerandomization_or(
    pk: &PublicKey,
    old: &EncryptedPoly,
    next: &EncryptedPoly,
    new: &EncryptedPoly,
    proof: &OrRerandProof,
    ctx: &ProofContext,
) -> Result<(), Error> {
    let [o, x, w] = [old, next, new].map(|p| EncodedPoly::from_native(p.clone()));
    verify_rerandomization_or_encoded(pk, &o, &x, &w, proof, ctx)
}
pub(crate) fn verify_rerandomization_or_encoded(
    pk: &PublicKey,
    old: &EncodedPoly,
    next: &EncodedPoly,
    new: &EncodedPoly,
    proof: &OrRerandProof,
    ctx: &ProofContext,
) -> Result<(), Error> {
    validate_key(pk)?;
    let n = dimensions(&[old, next, new])?;
    if ctx.round < 2 {
        return Err("invalid OR proof context".into());
    }
    if !super::sigma::or_prover(n).verify(&or_statements(pk, old, next, new, ctx), &proof.sigma) {
        return Err("invalid rerandomization OR proof".into());
    }
    Ok(())
}

/// Library Sigma proof of coefficient and encryption-randomness knowledge.
/// No root witnesses or polynomial factorization constraints are included.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialPoK {
    sigma: super::sigma::Proof,
}
fn initial_statement(pk: &PublicKey, ct: &EncodedPoly, ctx: &ProofContext) -> Statement {
    let mut t = transcript(b"exact::sigma-fun-initial-coefficient-pok-v1", pk, ctx);
    append_poly(&mut t, ct.wire());
    let mut relation = Statement::new(super::sigma::context(t));
    let (g, h): (Base, Base) = (relation.fixed(G), relation.fixed(pk.0));
    for (i, (c, w)) in ct.native().0.iter().zip(&ct.wire().0).enumerate() {
        relation.add_encoded(c.c1, w.c1, [(2 * i + 1, g)]);
        relation.add_encoded(c.c2, w.c2, [(2 * i, g), (2 * i + 1, h)]);
    }
    relation
}
/// Coefficients are supplied in ascending order, as in the ciphertext vector.
pub fn generate_initial_pok<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    coefficients: &[Scalar],
    randomness: &[Scalar],
    ct: &EncryptedPoly,
    ctx: &ProofContext,
) -> Result<InitialPoK, Error> {
    generate_initial_pok_encoded(
        rng,
        pk,
        coefficients,
        randomness,
        &EncodedPoly::from_native(ct.clone()),
        ctx,
    )
}
fn generate_initial_pok_encoded<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    coefficients: &[Scalar],
    randomness: &[Scalar],
    ct: &EncodedPoly,
    ctx: &ProofContext,
) -> Result<InitialPoK, Error> {
    validate_key(pk)?;
    let n = dimensions(&[ct])?;
    if ctx.round != 1 || coefficients.len() != n || randomness.len() != n {
        return Err("invalid initial witness/context".into());
    }
    // Allocated at full size, so that no unwiped partial copy is freed.
    let mut witness = zeroize::Zeroizing::new(Vec::with_capacity(2 * n));
    witness.extend(
        coefficients
            .iter()
            .zip(randomness)
            .flat_map(|(m, r)| [*m, *r]),
    );
    let statement = initial_statement(pk, ct, ctx);
    if !statement.satisfied_by(&witness) {
        return Err("incorrect coefficient/encryption relation".into());
    }
    Ok(InitialPoK {
        sigma: super::sigma::prover(2 * n).prove(&witness, &statement, Some(rng)),
    })
}

/// Compute plaintext coefficients once and keep encryption randomness local.
/// The ciphertext is returned with its wire encoding, compressed once for proof and storage.
pub(crate) fn encrypt_and_prove_initial<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    set: &[Scalar],
    ctx: &ProofContext,
) -> Result<(EncodedPoly, InitialPoK), Error> {
    validate_key(pk)?;
    if set.len() >= MAX_COEFFICIENTS {
        return Err("invalid initial set dimensions".into());
    }
    let coeffs = zeroize::Zeroizing::new(poly_from_roots(set));
    let randomness = zeroize::Zeroizing::new(
        (0..coeffs.len())
            .map(|_| Scalar::random(rng))
            .collect::<Vec<_>>(),
    );
    let pk_table = table(&pk.0);
    let ct = EncodedPoly::from_native(EncryptedPoly(
        coeffs
            .iter()
            .zip(randomness.iter())
            .map(|(m, r)| encrypt_with_randomness(&pk_table, *m, *r))
            .collect(),
    ));
    let proof = generate_initial_pok_encoded(rng, pk, &coeffs, &randomness, &ct, ctx)?;
    Ok((ct, proof))
}
pub fn verify_initial_pok(
    pk: &PublicKey,
    ct: &EncryptedPoly,
    proof: &InitialPoK,
    ctx: &ProofContext,
) -> Result<(), Error> {
    verify_initial_pok_encoded(pk, &EncodedPoly::from_native(ct.clone()), proof, ctx)
}
pub(crate) fn verify_initial_pok_encoded(
    pk: &PublicKey,
    ct: &EncodedPoly,
    proof: &InitialPoK,
    ctx: &ProofContext,
) -> Result<(), Error> {
    validate_key(pk)?;
    let n = dimensions(&[ct])?;
    if ctx.round != 1 || proof.sigma.response.len() != 2 * n {
        return Err("invalid initial proof dimensions/context".into());
    }
    if !super::sigma::prover(2 * n).verify(&initial_statement(pk, ct, ctx), &proof.sigma) {
        return Err("invalid coefficient/encryption knowledge proof".into());
    }
    Ok(())
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
    fn arbitrary_coefficients_and_linear_proof_size() {
        let (mut rng, pk, ctx) = fixture();
        for n in [1, 2, 8, 65] {
            // Includes nonmonic polynomials: no root relation is required.
            let coeffs = vec![Scalar::from(17u64); n];
            let r: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
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
            let proof = generate_initial_pok(&mut rng, &pk, &coeffs, &r, &ct, &ctx).unwrap();
            verify_initial_pok(&pk, &ct, &proof, &ctx).unwrap();
            assert_eq!(
                bincode::serialized_size(&proof).unwrap(),
                39 + 64 * n as u64
            );
            let mut wrong = coeffs.clone();
            wrong[0] += Scalar::one();
            assert!(generate_initial_pok(&mut rng, &pk, &wrong, &r, &ct, &ctx).is_err());
            let mut wrong_r = r.clone();
            wrong_r[0] += Scalar::one();
            assert!(generate_initial_pok(&mut rng, &pk, &coeffs, &wrong_r, &ct, &ctx).is_err());
            assert!(verify_initial_pok(&PublicKey(pk.0 + G), &ct, &proof, &ctx).is_err());
        }
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
            let p = generate_initial_pok(&mut rng, &pk, &coeffs, &r, &ct, &ctx).unwrap();
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
            assert!(generate_initial_pok(&mut rng, &pk, &coeffs, &r, &wrong, &ctx).is_err());
            let mut damaged = p.clone();
            damaged.sigma.response[0] += Scalar::one();
            assert!(verify_initial_pok(&pk, &ct, &damaged, &ctx).is_err());
            damaged = p.clone();
            damaged.sigma.challenge[0] ^= 1;
            assert!(verify_initial_pok(&pk, &ct, &damaged, &ctx).is_err());
            let mut wrong_set = coeffs.clone();
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
                assert_eq!(
                    bincode::serialized_size(&super::super::TPolyProof::RerandomizationOr(
                        p.clone()
                    ))
                    .unwrap(),
                    64 * n as u64 + 82
                );
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
                damaged.sigma.response.0 .0[0] += Scalar::one();
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &damaged, &ctx).is_err());
                damaged = p.clone();
                damaged.sigma.challenge[0] ^= 1;
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &damaged, &ctx).is_err());
                damaged = p.clone();
                damaged.sigma.response.1[0] += Scalar::one();
                assert!(verify_rerandomization_or(&pk, &old, &next, &new, &damaged, &ctx).is_err());
                damaged = p.clone();
                damaged.sigma.response.0 .0.pop();
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
                    // Bypass the honest prover's witness check: mixing coefficients
                    // from different branches must also fail at the verifier.
                    let witness = if b == 0 {
                        sigma_fun::Either::Left(zeroize::Zeroizing::new(w.clone()))
                    } else {
                        sigma_fun::Either::Right(zeroize::Zeroizing::new(w.clone()))
                    };
                    let forged = OrRerandProof {
                        sigma: super::super::sigma::or_prover(n).prove(
                            &witness,
                            &{
                                let [o, x, w] = [&old, &next, &mixed]
                                    .map(|p| EncodedPoly::from_native(p.clone()));
                                or_statements(&pk, &o, &x, &w, &ctx)
                            },
                            Some(&mut rng),
                        ),
                    };
                    assert!(
                        verify_rerandomization_or(&pk, &old, &next, &mixed, &forged, &ctx).is_err()
                    );
                }
            }
        }
    }
    #[test]
    fn library_proofs_preserve_removal_over_multiple_rounds() {
        use crate::crypto::elgamal;
        use crate::exact::{division, encryption};
        for (roots, query, expected_matches) in [
            (vec![7u64, 7, 42], 7u64, 2),
            (vec![7u64, 42], 99u64, 0),
            (vec![], 7u64, 0),
        ] {
            let mut rng = StdRng::seed_from_u64(914);
            let (sk1, pk1) = elgamal::generate_key_share(&mut rng);
            let (sk2, pk2) = elgamal::generate_key_share(&mut rng);
            let pk = elgamal::combine_public_keys(&pk1, &pk2);
            let set: Vec<_> = roots.into_iter().map(Scalar::from).collect();
            let mut ctx = ProofContext {
                session: [21; 32],
                round: 1,
            };
            let (current, proof) = encrypt_and_prove_initial(&mut rng, &pk, &set, &ctx).unwrap();
            verify_initial_pok_encoded(&pk, &current, &proof, &ctx).unwrap();
            let mut current = current.into_native();
            let mut matches = 0;
            for _ in 0..3 {
                let reply = division::prove(
                    &mut rng,
                    &pk,
                    &pk1,
                    &pk2,
                    &sk2,
                    &current,
                    Scalar::from(query),
                    &ctx,
                )
                .unwrap();
                let (next, partial) =
                    division::verify(&pk, &pk1, &pk2, &current, &reply, &ctx).unwrap();
                let branch = usize::from(elgamal::test_zero(&sk1, &partial));
                matches += branch;
                let source = if branch == 0 { &current } else { &next };
                let (updated, randomness) =
                    encryption::rerandomize_poly_with_witness(&mut rng, &pk, source);
                ctx.round += 1;
                let proof = prove_rerandomization_or(
                    &mut rng,
                    &pk,
                    &current,
                    &next,
                    &updated,
                    branch,
                    &randomness,
                    &ctx,
                )
                .unwrap();
                verify_rerandomization_or(&pk, &current, &next, &updated, &proof, &ctx).unwrap();
                current = updated;
            }
            assert_eq!(matches, expected_matches);
        }
    }
    #[test]
    fn zero_coefficients_and_randomness_are_valid_and_encodings_are_canonical() {
        let (mut rng, pk, mut ctx) = fixture();
        let zeros = vec![Scalar::zero(); 2];
        let ct = encrypt_poly(&mut rng, &pk, &zeros);
        let (identity_ct, _) =
            crate::exact::encryption::rerandomize_poly_with_witness(&mut rng, &pk, &ct);
        let zero_ct = EncryptedPoly(vec![
            crate::crypto::elgamal::Ciphertext {
                c1: RistrettoPoint::identity(),
                c2: RistrettoPoint::identity(),
            };
            2
        ]);
        let proof = generate_initial_pok(&mut rng, &pk, &zeros, &zeros, &zero_ct, &ctx).unwrap();
        verify_initial_pok(&pk, &zero_ct, &proof, &ctx).unwrap();
        let mut bytes = bincode::serialize(&proof).unwrap();
        let len = bytes.len();
        bytes[len - 32..].fill(255);
        assert!(bincode::deserialize::<InitialPoK>(&bytes).is_err());
        ctx.round = 2;
        let proof = prove_rerandomization_or(
            &mut rng,
            &pk,
            &zero_ct,
            &identity_ct,
            &zero_ct,
            0,
            &zeros,
            &ctx,
        )
        .unwrap();
        verify_rerandomization_or(&pk, &zero_ct, &identity_ct, &zero_ct, &proof, &ctx).unwrap();
        let mut bytes = bincode::serialize(&proof).unwrap();
        let len = bytes.len();
        bytes[len - 32..].fill(255);
        assert!(bincode::deserialize::<OrRerandProof>(&bytes).is_err());
    }
}
