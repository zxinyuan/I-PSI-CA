//! ElGamal accumulator proof linked to the RLWE proof's Pedersen item commitment.
use super::bloom::BloomFilterConfig;
use crate::crypto::elgamal::{Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare};
use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination as LC, Prover, R1CSError, R1CSProof, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireAccumulatorProof {
    pub arithmetic: Vec<u8>,
    pub encoded: [u8; 32],
    pub e: Vec<[u8; 32]>,
    pub a_e: Vec<[u8; 32]>,
    pub a: [[u8; 32]; 8],
    pub z_e: Vec<[u8; 32]>,
    pub z_blind: Vec<[u8; 32]>,
    pub z_y: [u8; 32],
    pub z_gamma: [u8; 32],
    pub z_x: [u8; 32],
    pub z_rho: [u8; 32],
}
fn scalar(bytes: [u8; 32]) -> Result<Scalar, String> {
    Scalar::from_canonical_bytes(bytes).ok_or_else(|| "noncanonical accumulator response".into())
}
fn point(bytes: [u8; 32]) -> Result<RistrettoPoint, String> {
    CompressedRistretto(bytes)
        .decompress()
        .ok_or_else(|| "invalid accumulator point".into())
}
fn challenge(t: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut bytes = [0u8; 64];
    t.challenge_bytes(label, &mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}
fn bp_transcript(context: &[u8; 32]) -> Transcript {
    let mut t = Transcript::new(b"bf-accumulator-chain-v2");
    t.append_message(b"context", context);
    t
}
fn chain<CS: ConstraintSystem>(
    cs: &mut CS,
    y: bulletproofs::r1cs::Variable,
    encoded: bulletproofs::r1cs::Variable,
    e: &[bulletproofs::r1cs::Variable],
    config: BloomFilterConfig,
    assignment: Option<Scalar>,
    mask: Option<Scalar>,
) -> Result<(), R1CSError> {
    super::protocol_hash::constrain_encoding(cs, y, encoded, config, assignment)?;
    let inv = cs.allocate(mask.map(|m| m.invert()))?;
    let product = cs.multiply(e[0].into(), inv.into()).2;
    cs.constrain(LC::from(product) - Scalar::one());
    for j in 1..e.len() {
        let product = cs.multiply(e[j - 1].into(), encoded.into()).2;
        cs.constrain(LC::from(product) - e[j]);
    }
    Ok(())
}
fn statement(
    context: &[u8; 32],
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    next: &EncryptedPoly,
    scaled: &Ciphertext,
    partial: &Ciphertext,
    y: [u8; 32],
    encoded: [u8; 32],
    e: &[[u8; 32]],
    arithmetic: &[u8],
) -> Transcript {
    let mut t = Transcript::new(b"bf-accumulator-shared-input-sigma-v2");
    t.append_message(b"context", context);
    t.append_message(b"item", &y);
    t.append_message(b"encoded-root", &encoded);
    for p in [&pk.0, &pk1.0, &pk2.0] {
        t.append_message(b"key", p.compress().as_bytes());
    }
    for poly in [current, next] {
        t.append_u64(b"length", poly.0.len() as u64);
        for ct in &poly.0 {
            t.append_message(b"c1", ct.c1.compress().as_bytes());
            t.append_message(b"c2", ct.c2.compress().as_bytes());
        }
    }
    for ct in [scaled, partial] {
        t.append_message(b"c1", ct.c1.compress().as_bytes());
        t.append_message(b"c2", ct.c2.compress().as_bytes());
    }
    for e in e {
        t.append_message(b"power", e);
    }
    t.append_message(b"arithmetic", arithmetic);
    t
}
fn aggregate(
    t: &mut Transcript,
    current: &EncryptedPoly,
    next: &EncryptedPoly,
) -> Result<(Ciphertext, Ciphertext), String> {
    let derived = super::accumulator::scale_component(current, next)?;
    let beta = (0..current.0.len())
        .map(|_| challenge(t, b"root-batch"))
        .collect::<Vec<_>>();
    let aggregate = |p: &EncryptedPoly| Ciphertext {
        c1: RistrettoPoint::multiscalar_mul(&beta, p.0.iter().map(|c| c.c1)),
        c2: RistrettoPoint::multiscalar_mul(&beta, p.0.iter().map(|c| c.c2)),
    };
    Ok((aggregate(current), aggregate(&derived)))
}
fn append_a(t: &mut Transcript, a_e: &[[u8; 32]], a: &[[u8; 32]; 8]) {
    for a in a_e.iter().chain(a) {
        t.append_message(b"nonce", a);
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    context: &[u8; 32],
    config: BloomFilterConfig,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    next: &EncryptedPoly,
    scaled: &Ciphertext,
    partial: &Ciphertext,
    y: Scalar,
    gamma: Scalar,
    y_commitment: [u8; 32],
    mask: Scalar,
    x: Scalar,
    rho: Scalar,
) -> Result<WireAccumulatorProof, String> {
    if current.0.is_empty() || mask == Scalar::zero() {
        return Err("invalid accumulator witness".into());
    }
    let pc = PedersenGens::default();
    let mut t = bp_transcript(context);
    let mut p = Prover::new(&pc, &mut t);
    let (yc, yv) = p.commit(y, gamma);
    if yc.to_bytes() != y_commitment {
        return Err("accumulator input is not the RLWE input commitment".into());
    }
    let root = super::protocol_hash::encode_positions(y, config)?;
    let root_blind = Scalar::random(rng);
    let (root_commitment, root_variable) = p.commit(root, root_blind);
    let mut powers = zeroize::Zeroizing::new(Vec::with_capacity(current.0.len()));
    let mut blinds = zeroize::Zeroizing::new(Vec::new());
    let mut variables = Vec::new();
    let mut e = Vec::new();
    let mut power = mask;
    for _ in 0..current.0.len() {
        let blind = Scalar::random(rng);
        let (c, v) = p.commit(power, blind);
        powers.push(power);
        blinds.push(blind);
        e.push(c.to_bytes());
        variables.push(v);
        power *= root;
    }
    chain(
        &mut p,
        yv,
        root_variable,
        &variables,
        config,
        Some(y),
        Some(mask),
    )
    .map_err(|e| e.to_string())?;
    let bp = BulletproofGens::new(p.metrics().multipliers.max(1).next_power_of_two(), 1);
    let arithmetic = p.prove(&bp).map_err(|e| e.to_string())?.to_bytes();
    let mut t = statement(
        context,
        pk,
        pk1,
        pk2,
        current,
        next,
        scaled,
        partial,
        y_commitment,
        root_commitment.to_bytes(),
        &e,
        &arithmetic,
    );
    let (input, _) = aggregate(&mut t, current, next)?;
    let ky = Scalar::random(rng);
    let kg = Scalar::random(rng);
    let kx = Scalar::random(rng);
    let kr = Scalar::random(rng);
    let ke = zeroize::Zeroizing::new(
        (0..powers.len())
            .map(|_| Scalar::random(rng))
            .collect::<Vec<_>>(),
    );
    let kb = zeroize::Zeroizing::new(
        (0..powers.len())
            .map(|_| Scalar::random(rng))
            .collect::<Vec<_>>(),
    );
    let a_e = ke
        .iter()
        .zip(kb.iter())
        .map(|(&k, &b)| pc.commit(k, b).compress().to_bytes())
        .collect::<Vec<_>>();
    let eval1 =
        RistrettoPoint::multiscalar_mul(ke.iter(), current.0.iter().map(|c| c.c1)) + ke[0] * pc.B;
    let eval2 =
        RistrettoPoint::multiscalar_mul(ke.iter(), current.0.iter().map(|c| c.c2)) + ke[0] * pk.0;
    let a = [
        pc.commit(ky, kg),
        eval1,
        eval2,
        ky * input.c1,
        ky * input.c2,
        kx * pc.B,
        kr * pc.B,
        -kx * scaled.c1 + kr * pk1.0,
    ]
    .map(|p| p.compress().to_bytes());
    append_a(&mut t, &a_e, &a);
    let c = challenge(&mut t, b"challenge");
    Ok(WireAccumulatorProof {
        arithmetic,
        encoded: root_commitment.to_bytes(),
        e,
        a_e,
        a,
        z_e: ke
            .iter()
            .zip(powers.iter())
            .map(|(&k, &e)| (k + c * e).to_bytes())
            .collect(),
        z_blind: kb
            .iter()
            .zip(blinds.iter())
            .map(|(&k, &b)| (k + c * b).to_bytes())
            .collect(),
        z_y: (ky + c * root).to_bytes(),
        z_gamma: (kg + c * root_blind).to_bytes(),
        z_x: (kx + c * x).to_bytes(),
        z_rho: (kr + c * rho).to_bytes(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify(
    context: &[u8; 32],
    config: BloomFilterConfig,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current: &EncryptedPoly,
    next: &EncryptedPoly,
    scaled: &Ciphertext,
    partial: &Ciphertext,
    y_commitment: [u8; 32],
    proof: &WireAccumulatorProof,
) -> Result<(), String> {
    let n = current.0.len();
    if n == 0
        || proof.e.len() != n
        || proof.a_e.len() != n
        || proof.z_e.len() != n
        || proof.z_blind.len() != n
        || proof.arithmetic.len() > 32768
    {
        return Err("invalid accumulator proof dimensions".into());
    }
    let pc = PedersenGens::default();
    let mut t = bp_transcript(context);
    let mut v = Verifier::new(&mut t);
    let y = v.commit(CompressedRistretto(y_commitment));
    let encoded = v.commit(CompressedRistretto(proof.encoded));
    let e = proof
        .e
        .iter()
        .map(|&c| v.commit(CompressedRistretto(c)))
        .collect::<Vec<_>>();
    chain(&mut v, y, encoded, &e, config, None, None).map_err(|e| e.to_string())?;
    let bp = BulletproofGens::new(v.metrics().multipliers.max(1).next_power_of_two(), 1);
    v.verify(
        &R1CSProof::from_bytes(&proof.arithmetic).map_err(|e| e.to_string())?,
        &pc,
        &bp,
    )
    .map_err(|e| e.to_string())?;
    let mut t = statement(
        context,
        pk,
        pk1,
        pk2,
        current,
        next,
        scaled,
        partial,
        y_commitment,
        proof.encoded,
        &proof.e,
        &proof.arithmetic,
    );
    let (input, output) = aggregate(&mut t, current, next)?;
    append_a(&mut t, &proof.a_e, &proof.a);
    let c = challenge(&mut t, b"challenge");
    let a = proof
        .a
        .iter()
        .map(|&p| point(p))
        .collect::<Result<Vec<_>, _>>()?;
    let ae = proof
        .a_e
        .iter()
        .map(|&p| point(p))
        .collect::<Result<Vec<_>, _>>()?;
    let ze = proof
        .z_e
        .iter()
        .map(|&z| scalar(z))
        .collect::<Result<Vec<_>, _>>()?;
    let zb = proof
        .z_blind
        .iter()
        .map(|&z| scalar(z))
        .collect::<Result<Vec<_>, _>>()?;
    let zy = scalar(proof.z_y)?;
    let zg = scalar(proof.z_gamma)?;
    let zx = scalar(proof.z_x)?;
    let zr = scalar(proof.z_rho)?;
    if pc.commit(zy, zg) != a[0] + c * point(proof.encoded)? {
        return Err("accumulator shared-input opening failed".into());
    }
    for j in 0..n {
        if pc.commit(ze[j], zb[j]) != ae[j] + c * point(proof.e[j])? {
            return Err("accumulator power opening failed".into());
        }
    }
    let eval1 =
        RistrettoPoint::multiscalar_mul(&ze, current.0.iter().map(|ct| ct.c1)) + ze[0] * pc.B;
    let eval2 =
        RistrettoPoint::multiscalar_mul(&ze, current.0.iter().map(|ct| ct.c2)) + ze[0] * pk.0;
    if eval1 != a[1] + c * scaled.c1 || eval2 != a[2] + c * scaled.c2 {
        return Err("accumulator evaluation relation failed".into());
    }
    if zy * input.c1 != a[3] + c * output.c1 || zy * input.c2 != a[4] + c * output.c2 {
        return Err("accumulator root insertion failed".into());
    }
    if zx * pc.B != a[5] + c * pk2.0
        || zr * pc.B != a[6] + c * (partial.c1 - scaled.c1)
        || -zx * scaled.c1 + zr * pk1.0 != a[7] + c * (partial.c2 - scaled.c2)
    {
        return Err("accumulator partial decryption failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{
        combine_public_keys, ct_add, ct_scalar_mul, encrypt_poly, eval_poly, generate_key_share,
        partial_decrypt_with_witness,
    };
    #[test]
    fn linked_accumulator_proves_roots_masks_and_partial_decryption() {
        let mut rng = rand::rngs::OsRng;
        let (_s1, p1) = generate_key_share(&mut rng);
        let (s2, p2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&p1, &p2);
        let cfg = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 2,
            target_marked_count: 4,
        };
        let old = encrypt_poly(
            &mut rng,
            &pk,
            &[Scalar::from(5u64), Scalar::from(7u64), Scalar::zero()],
        );
        let y = Scalar::from(3u64);
        let gamma = Scalar::random(&mut rng);
        let yc = PedersenGens::default()
            .commit(y, gamma)
            .compress()
            .to_bytes();
        let mask = Scalar::from(11u64);
        let root = super::super::protocol_hash::encode_positions(y, cfg).unwrap();
        let next = super::super::accumulator::insert_candidate(&old, root);
        let scaled = ct_add(
            &ct_scalar_mul(&eval_poly(&old, &root), &mask),
            &Ciphertext {
                c1: mask * PedersenGens::default().B,
                c2: mask * pk.0,
            },
        );
        let (partial, rho) = partial_decrypt_with_witness(&mut rng, &s2, &p1, &scaled);
        let context = [3; 32];
        let proof = prove(
            &mut rng,
            &context,
            cfg,
            &pk,
            &p1,
            &p2,
            &old,
            &next,
            &scaled,
            &partial,
            y,
            gamma,
            yc,
            mask,
            *s2.as_scalar(),
            rho,
        )
        .unwrap();
        let check = |ctx: &[u8; 32],
                     new: &EncryptedPoly,
                     scaled: &Ciphertext,
                     partial: &Ciphertext,
                     item,
                     proof: &WireAccumulatorProof| {
            verify(
                ctx, cfg, &pk, &p1, &p2, &old, new, scaled, partial, item, proof,
            )
        };
        check(&context, &next, &scaled, &partial, yc, &proof).unwrap();
        assert!(check(&[4; 32], &next, &scaled, &partial, yc, &proof).is_err());
        let mut bad = next.clone();
        bad.0[0].c2 += PedersenGens::default().B;
        assert!(check(&context, &bad, &scaled, &partial, yc, &proof).is_err());
        let mut bad = partial.clone();
        bad.c2 += PedersenGens::default().B;
        assert!(check(&context, &next, &scaled, &bad, yc, &proof).is_err());
        let other = PedersenGens::default()
            .commit(y + Scalar::one(), gamma)
            .compress()
            .to_bytes();
        assert!(check(&context, &next, &scaled, &partial, other, &proof).is_err());
        let mut bad = proof.clone();
        bad.z_e[0][0] ^= 1;
        assert!(check(&context, &next, &scaled, &partial, yc, &bad).is_err());
        // Even a newly generated, internally valid proof must reject an
        // incorrect root update, evaluation, or shared secret-key witness.
        assert_ne!(root, y);
        let bad_next = super::super::accumulator::insert_candidate(&old, y);
        let bad = prove(
            &mut rng,
            &context,
            cfg,
            &pk,
            &p1,
            &p2,
            &old,
            &bad_next,
            &scaled,
            &partial,
            y,
            gamma,
            yc,
            mask,
            *s2.as_scalar(),
            rho,
        )
        .unwrap();
        assert!(check(&context, &bad_next, &scaled, &partial, yc, &bad).is_err());
        let wrong_scaled = Ciphertext {
            c1: scaled.c1,
            c2: scaled.c2 + PedersenGens::default().B,
        };
        let bad = prove(
            &mut rng,
            &context,
            cfg,
            &pk,
            &p1,
            &p2,
            &old,
            &next,
            &wrong_scaled,
            &partial,
            y,
            gamma,
            yc,
            mask,
            *s2.as_scalar(),
            rho,
        )
        .unwrap();
        assert!(check(&context, &next, &wrong_scaled, &partial, yc, &bad).is_err());
    }
}
