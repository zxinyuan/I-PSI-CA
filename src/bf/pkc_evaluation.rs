//! Amortized PKC 2019 proofs of all six native RNS equations together. The same signed
//! coefficients are bound to Bulletproof Pedersen inputs by complete-commitment
//! zero-knowledge inner-product arguments. No auxiliary w_shared field is trusted.
use super::{
    evaluation_proof::{Layout, PublicData},
    proof_values::{Assignments, Bound},
    protocol_math,
};
use bincode::Options;
use bulletproofs::PedersenGens;
use curve25519_dalek_ng::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use logproof::{
    linear_algebra::Matrix, Bounds, InnerProductProof, InnerProductProverKnowledge,
    InnerProductVerifierKnowledge, LogProof, LogProofGenerators, LogProofProverKnowledge,
    LogProofVerifierKnowledge,
};
use merlin::Transcript;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, OnceLock};
use sunscreen_math::{
    poly::Polynomial,
    ring::{BarrettBackend, Ring, Zq},
    BarrettConfig,
};

// Auxiliary embedding ring, not an encryption modulus. Public norm checks
// below ensure its modular equations imply the required INTEGER equalities.
#[derive(BarrettConfig)]
#[barrett_config(
    modulus = "1461501637330902918203684832716283019655932542929",
    num_limbs = 3
)]
struct EmbeddedIntegers;
type Q0 = Zq<3, BarrettBackend<3, EmbeddedIntegers>>;
const PROJECTIONS: usize = 3;

/// Soundness uses bounded residuals, not an exact remainder comparison. Check
/// that even the largest allowed residual and coin still decrypt correctly.
pub(crate) fn validate_decode_bound(
    n: usize,
    count: usize,
    limbs: usize,
    t: u64,
    moduli: &[u64],
) -> Result<(), String> {
    if moduli.len() != 6 || n == 0 || limbs == 0 {
        return Err("invalid PKC decoding budget".into());
    }
    let n = BigUint::from(n);
    let secret = BigUint::from(2 * super::circuit_privacy::ERROR_VARIANCE);
    let fresh = BigUint::from(2u8) * &n * &secret * &secret + &secret;
    let blocks = BigUint::from(count.div_ceil(n.to_usize().ok_or("ring dimension overflow")?));
    let source = blocks * &n * (BigUint::from(1u8) << 55usize) * (fresh + BigUint::from(1u8));
    let public_zero = &n * &secret * BigUint::from(128u16);
    // A strict conservative bound for balanced signed-32 limbs; the sum
    // of negative extrema is slightly larger than 2^(32*limbs-1).
    let residual = (BigUint::from(1u8) + &n * &secret) * (BigUint::from(1u8) << (32 * limbs));
    let divisor: BigUint = moduli[2..].iter().map(|&q| BigUint::from(q)).product();
    let retained = BigUint::from(moduli[0]) * BigUint::from(moduli[1]);
    let numerator = source + public_zero + residual;
    let noise = (numerator + &divisor - BigUint::from(1u8)) / &divisor
        + BigUint::from(t)
        + BigUint::from(2u8);
    if BigUint::from(2u8) * BigUint::from(t) * noise >= retained {
        return Err("PKC residual bounds do not ensure correct decoding".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireRingProof {
    pub relation: Vec<u8>,
    pub link: Vec<u8>,
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > 16384 {
        return Err("oversized PKC proof".into());
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16384)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| e.to_string())
}
fn generators(n: usize) -> Result<Arc<LogProofGenerators>, String> {
    if n == 0 || n > (1 << 25) {
        return Err("PKC generator capacity exceeded".into());
    }
    static CACHE: OnceLock<Mutex<Option<Arc<LogProofGenerators>>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "PKC generator cache poisoned")?;
    if let Some(g) = cache.as_ref().filter(|g| g.g.len() == n) {
        return Ok(g.clone());
    }
    // Retain only one size: 100k proofs must not accumulate multiple GiB caches.
    *cache = None;
    let g = Arc::new(LogProofGenerators::new(n));
    *cache = Some(g.clone());
    Ok(g)
}
fn digest(context: &[u8; 32], commitments: &[[u8; 32]], arithmetic: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"bf-pkc-evaluation-statement/v2");
    h.update(context);
    h.update((commitments.len() as u64).to_le_bytes());
    for c in commitments {
        h.update(c);
    }
    h.update((arithmetic.len() as u64).to_le_bytes());
    h.update(arithmetic);
    h.finalize().into()
}
fn transcript(digest: &[u8; 32], pair: usize, rep: usize) -> Transcript {
    let mut t = Transcript::new(b"bf-pkc-native-rns-linear-relation/v2");
    t.append_message(b"statement", digest);
    t.append_u64(b"pair", pair as u64);
    t.append_u64(b"coordinate", rep as u64);
    t
}
fn challenge(t: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut b = [0u8; 64];
    t.challenge_bytes(label, &mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}
fn modular_adjoint(a: &[u64], gamma: &[u64], q: u64) -> Result<Vec<u64>, String> {
    let n = a.len();
    let mut reversed = vec![BigInt::from(0); n];
    reversed[0] = BigInt::from(gamma[0]);
    for j in 1..n {
        reversed[n - j] = -BigInt::from(gamma[j]);
    }
    let a = a.iter().map(|&a| BigInt::from(a)).collect::<Vec<_>>();
    let conv = protocol_math::convolution(&a, &reversed)?;
    (0..n)
        .map(|j| {
            let v = if j == 0 {
                conv[0].clone()
            } else {
                -&conv[n - j]
            };
            let mut v = v % BigInt::from(q);
            if v.sign() == Sign::Minus {
                v += BigInt::from(q);
            }
            v.to_u64()
                .ok_or_else(|| "adjoint reduction overflow".into())
        })
        .collect()
}
fn indices(layout: &Layout, rep: usize, pair: usize) -> Vec<usize> {
    let l = &layout.reps[rep];
    l.w.clone()
        .chain(l.u.clone())
        .chain(l.ra.clone())
        .chain(l.rb.clone())
        // The recurrence quotient needs its bound only once per coordinate.
        .chain(if pair == 0 {
            l.rec.clone()
        } else {
            l.rec.start..l.rec.start
        })
        .collect()
}
fn width(bound: Bound) -> Result<usize, String> {
    match bound {
        Bound::Signed(n) if (2..=64).contains(&n) => Ok(n as usize),
        _ => Err("unsupported PKC signed coefficient".into()),
    }
}
fn poly<Q: Ring>(v: Q) -> Polynomial<Q> {
    Polynomial::new(&[v])
}

fn embedding_checks(
    vk: &LogProofVerifierKnowledge<Q0>,
    layout: &Layout,
    selected: &[usize],
    max_q: u64,
) -> Result<(), String> {
    let mut sum = BigUint::from(1u8);
    for &i in selected {
        sum += BigUint::from(1u8) << (width(layout.bounds[i])? - 1);
    }
    // Each native coefficient is <q. The two quotient limbs contribute
    // q*(2^63 + 2^64*2^15). All other quotient columns in this row are zero.
    let native_bound = BigUint::from(max_q)
        * (sum + (BigUint::from(1u8) << 63usize) + (BigUint::from(1u8) << 79usize));
    let aux =
        BigUint::parse_bytes(b"1461501637330902918203684832716283019655932542929", 10).unwrap();
    if &native_bound * BigUint::from(2u8) >= aux {
        return Err("native integer equation exceeds auxiliary embedding modulus".into());
    }
    let factor_bound = &aux * (BigUint::from(1u8) << (vk.b_1() as usize - 1));
    let scalar_modulus = BigUint::parse_bytes(
        b"7237005577332262213973186563042994240857116359379907606001950938285454250989",
        10,
    )
    .unwrap();
    if (native_bound + factor_bound) * BigUint::from(2u8) >= scalar_modulus {
        return Err("PKC integer lift exceeds scalar modulus".into());
    }
    Ok(())
}

fn knowledge(
    layout: &Layout,
    data: &PublicData,
    digest: &[u8; 32],
    rep: usize,
) -> Result<(LogProofVerifierKnowledge<Q0>, Vec<usize>), String> {
    let selected = indices(layout, rep, 0);
    let shared = selected.len();
    let rows = data.moduli.len() * (PROJECTIONS + 1);
    let cols = shared + 2 * rows;
    let n = layout.n;
    let count = layout.count;
    let mut a = Matrix::new(rows, cols);
    let mut target = Matrix::new(rows, 1);
    let mut transcript = transcript(digest, 0, rep);
    for (prime, &q) in data.moduli.iter().enumerate() {
        let f = fhe_math::zq::Modulus::new(q).map_err(|e| e.to_string())?;
        let d = (&data.divisor % q).to_u64().unwrap();
        for projection in 0..=PROJECTIONS {
            let row = prime * (PROJECTIONS + 1) + projection;
            let mut coefficients = vec![0u64; shared];
            let mut rhs = 0;
            if projection < PROJECTIONS {
                let gamma = (0..n)
                    .map(|_| {
                        let mut bytes = [0u8; 64];
                        transcript.challenge_bytes(b"native-vector-projection", &mut bytes);
                        (BigUint::from_bytes_le(&bytes) % q).to_u64().unwrap()
                    })
                    .collect::<Vec<_>>();
                for (block, source) in data.source1.iter().enumerate() {
                    let adj = modular_adjoint(&source[prime], &gamma, q)?;
                    for local in 0..(count - block * n).min(n) {
                        coefficients[block * n + local] =
                            adj[if local == 0 { 0 } else { n - local }];
                    }
                }
                let adj = modular_adjoint(&data.pk1[prime], &gamma, q)?;
                coefficients[count..count + n].copy_from_slice(&adj);
                let base = f.reduce_u128(1u128 << 32);
                let mut power = 1;
                for limb in 0..layout.limbs {
                    for j in 0..n {
                        coefficients[count + n + limb * n + j] = f.neg(f.mul(power, gamma[j]));
                    }
                    power = f.mul(power, base);
                }
                for j in 0..n {
                    let out = if prime < 2 {
                        data.outputs[rep].a[prime][j]
                    } else {
                        0
                    };
                    rhs = f.add(rhs, f.mul(gamma[j], f.mul(d, out)));
                }
            } else {
                for index in 0..count {
                    let local = index % n;
                    let v = data.source0[index / n][prime][local];
                    coefficients[index] = if local == 0 { v } else { f.neg(v) };
                }
                for j in 0..n {
                    let v = data.pk0[prime][if j == 0 { 0 } else { n - j }];
                    coefficients[count + j] = if j == 0 { v } else { f.neg(v) };
                }
                let base = f.reduce_u128(1u128 << 32);
                let mut power = 1;
                for limb in 0..layout.limbs {
                    coefficients[count + n + layout.limbs * n + limb] = f.neg(power);
                    power = f.mul(power, base);
                }
                rhs = f.mul(
                    d,
                    if prime < 2 {
                        data.outputs[rep].b[prime]
                    } else {
                        0
                    },
                );
            }
            for (col, value) in coefficients.into_iter().enumerate() {
                a[(row, col)] = poly(Q0::from(value));
            }
            a[(row, shared + 2 * row)] = poly(-Q0::from(q));
            a[(row, shared + 2 * row + 1)] =
                poly(-(Q0::from(q) * Q0::from(1u64 << 32) * Q0::from(1u64 << 32)));
            target[(row, 0)] = poly(Q0::from(rhs));
        }
    }
    let mut bounds = selected
        .iter()
        .map(|&i| width(layout.bounds[i]).map(|n| Bounds(vec![(n - 1) as u32])))
        .collect::<Result<Vec<_>, _>>()?;
    // Only one scalar quotient per projected equation, not N coefficient
    // quotients. They are PKC-internal and need no Pedersen/Bulletproof inputs.
    for _ in 0..rows {
        bounds.extend([Bounds(vec![63]), Bounds(vec![15])]);
    }
    let bounds = Matrix::new_with_data(cols, 1, &bounds);
    let f = Polynomial::new(&[Q0::from(0u64), Q0::from(1u64)]);
    let vk = LogProofVerifierKnowledge::new(a, target, f, bounds);
    embedding_checks(
        &vk,
        layout,
        &selected,
        *data.moduli.iter().max().ok_or("missing native moduli")?,
    )?;
    Ok((vk, selected))
}

/// Link numeric Pedersen inputs directly to the COMPLETE PKC bit commitment.
/// No bit variables or Boolean gates are added to the Bulletproof circuit.
struct LinkMaterial {
    t: Transcript,
    g: Vec<RistrettoPoint>,
    commitment: RistrettoPoint,
    blind_weights: Vec<Scalar>,
}
fn link_material(
    digest: &[u8; 32],
    pair: usize,
    rep: usize,
    ring: &LogProof,
    gens: &LogProofGenerators,
    layout: &Layout,
    selected: &[usize],
    commitments: &[[u8; 32]],
    arithmetic: &[u8],
    pc: &PedersenGens,
) -> Result<LinkMaterial, String> {
    let mut t = Transcript::new(b"bf-pkc-numeric-complete-commitment-link/v2");
    t.append_message(b"statement", digest);
    t.append_u64(b"pair", pair as u64);
    t.append_u64(b"coordinate", rep as u64);
    t.append_message(
        b"ring-proof",
        &bincode::serialize(ring).map_err(|e| e.to_string())?,
    );
    t.append_message(b"arithmetic-proof", arithmetic);
    t.append_u64(b"bits", gens.g.len() as u64);
    let mut g = gens
        .h
        .iter()
        .zip(&gens.g)
        .map(|(h, g)| h - g)
        .collect::<Vec<_>>();
    let mut bit = 0;
    let mut blind_weights = Vec::with_capacity(selected.len());
    let mut points = Vec::with_capacity(selected.len());
    for &index in selected {
        let alpha = challenge(&mut t, b"numeric-opening-batch");
        let point = CompressedRistretto(commitments[index])
            .decompress()
            .ok_or("invalid shared commitment")?;
        points.push(point);
        blind_weights.push(alpha);
        let bits = width(layout.bounds[index])?;
        let mut weight = alpha * pc.B;
        for j in 0..bits {
            if bit >= g.len() {
                return Err("PKC coefficient prefix exceeds commitment".into());
            }
            g[bit] += if j + 1 == bits { -weight } else { weight };
            weight = weight + weight;
            bit += 1;
        }
    }
    let constant = gens.g.iter().copied().sum::<RistrettoPoint>();
    let commitment =
        ring.w - constant + RistrettoPoint::vartime_multiscalar_mul(&blind_weights, &points);
    Ok(LinkMaterial {
        t,
        g,
        commitment,
        blind_weights,
    })
}
fn prove_one<R>(
    rng: &mut R,
    digest: &[u8; 32],
    pc: &PedersenGens,
    layout: &Layout,
    data: &PublicData,
    values: &Assignments,
    commitments: &[[u8; 32]],
    arithmetic: &[u8],
    pair: usize,
    rep: usize,
) -> Result<WireRingProof, String>
where
    R: RngCore + CryptoRng,
{
    let (vk, selected) = knowledge(layout, data, digest, rep)?;
    let shared = selected.len();
    let signed = zeroize::Zeroizing::new(
        selected
            .iter()
            .map(|&i| {
                let bits = width(layout.bounds[i])?;
                i64::try_from(values.encoded[i] as i128 - (1i128 << (bits - 1)))
                    .map_err(|_| "PKC coefficient overflow".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    let mut s = Matrix::new(vk.a.cols, 1);
    for (j, &v) in signed.iter().enumerate() {
        s[(j, 0)] = poly(Q0::from(v));
    }
    for row in 0..vk.a.rows {
        let mut numerator = -BigInt::from(vk.t[(row, 0)].coeffs[0].into_bigint().to_words()[0]);
        for (col, &value) in signed.iter().enumerate() {
            let coefficient = vk.a[(row, col)]
                .coeffs
                .first()
                .map(|v| v.into_bigint().to_words()[0])
                .unwrap_or(0);
            numerator += BigInt::from(coefficient) * BigInt::from(value);
        }
        let q = BigInt::from(data.moduli[row / (PROJECTIONS + 1)]);
        if &numerator % &q != BigInt::from(0) {
            return Err("native projected RLWE relation is inconsistent".into());
        }
        let (lo, hi) = protocol_math::split(&(numerator / q))?;
        if !(-32768..=32767).contains(&hi) {
            return Err("native quotient exceeds PKC bound".into());
        }
        s[(shared + 2 * row, 0)] = poly(Q0::from(lo));
        s[(shared + 2 * row + 1, 0)] = poly(Q0::from(hi as i64));
    }
    let pk = LogProofProverKnowledge::new(&vk.a, &s, &vk.t, &vk.bounds, &vk.f);
    let gens = generators(pk.vk.l() as usize)?;
    let half = Scalar::random(rng);
    let ring = LogProof::create_with_shared(
        &mut transcript(digest, pair, rep),
        &pk,
        &gens.g,
        &gens.h,
        &pc.B_blinding,
        &half,
        &[],
    );
    let bits = LogProof::binary_witness(&pk);
    let mut m = link_material(
        digest,
        pair,
        rep,
        &ring,
        &gens,
        layout,
        &selected,
        commitments,
        arithmetic,
        pc,
    )?;
    let left = zeroize::Zeroizing::new(
        bits.iter()
            .map(|b| Scalar::from(*b as u64))
            .collect::<Vec<_>>(),
    );
    let right = vec![Scalar::zero(); left.len()];
    let blind = half
        + half
        + selected
            .iter()
            .zip(&m.blind_weights)
            .fold(Scalar::zero(), |sum, (&i, &a)| sum + a * values.blinds[i]);
    // The verifier checks the common opening. Recomputing its bit-vector MSM
    // here is redundant and would allocate enormous constant-time lookup tables.
    let knowledge = InnerProductProverKnowledge::new(&left, &right, &blind, &m.commitment);
    // Original g is an independent right family: (h-g+kG,g) is an
    // invertible transformation of the independent original (h,g) families.
    let link = InnerProductProof::create(&mut m.t, &knowledge, &m.g, &gens.g, &pc.B_blinding);
    Ok(WireRingProof {
        relation: bincode::serialize(&ring).map_err(|e| e.to_string())?,
        link: bincode::serialize(&link).map_err(|e| e.to_string())?,
    })
}
fn verify_one(
    digest: &[u8; 32],
    pc: &PedersenGens,
    layout: &Layout,
    data: &PublicData,
    commitments: &[[u8; 32]],
    arithmetic: &[u8],
    pair: usize,
    rep: usize,
    proof: &WireRingProof,
) -> Result<(), String> {
    let (vk, selected) = knowledge(layout, data, digest, rep)?;
    let gens = generators(vk.l() as usize)?;
    let ring: LogProof = decode(&proof.relation)?;
    ring.verify(
        &mut transcript(digest, pair, rep),
        &vk,
        &gens.g,
        &gens.h,
        &pc.B_blinding,
    )
    .map_err(|e| e.to_string())?;
    let mut m = link_material(
        digest,
        pair,
        rep,
        &ring,
        &gens,
        layout,
        &selected,
        commitments,
        arithmetic,
        pc,
    )?;
    let link: InnerProductProof = decode(&proof.link)?;
    let knowledge = InnerProductVerifierKnowledge {
        t: m.commitment,
        x: Scalar::zero(),
    };
    link.verify(&mut m.t, &knowledge, &m.g, &gens.g, &pc.B_blinding)
        .map_err(|e| e.to_string())
}

pub(crate) fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    context: &[u8; 32],
    pc: &PedersenGens,
    layout: &Layout,
    data: &PublicData,
    values: &Assignments,
    commitments: &[[u8; 32]],
    arithmetic: &[u8],
) -> Result<Vec<WireRingProof>, String> {
    let digest = digest(context, commitments, arithmetic);
    let mut result = Vec::new();
    for rep in 0..3 {
        result.push(prove_one(
            rng,
            &digest,
            pc,
            layout,
            data,
            values,
            commitments,
            arithmetic,
            0,
            rep,
        )?);
    }
    Ok(result)
}
pub(crate) fn verify(
    context: &[u8; 32],
    pc: &PedersenGens,
    layout: &Layout,
    data: &PublicData,
    commitments: &[[u8; 32]],
    arithmetic: &[u8],
    proofs: &[WireRingProof],
) -> Result<(), String> {
    if proofs.len() != 3 {
        return Err("incorrect PKC relation count".into());
    }
    let digest = digest(context, commitments, arithmetic);
    for (rep, proof) in proofs.iter().enumerate() {
        verify_one(
            &digest,
            pc,
            layout,
            data,
            commitments,
            arithmetic,
            0,
            rep,
            proof,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn audit_costs(layout: &Layout) {
    let mut bound_sum = BigUint::from(1u8);
    let mut bits = 0;
    for i in indices(layout, 0, 0) {
        let n = width(layout.bounds[i]).unwrap();
        bits += n;
        bound_sum += BigUint::from(1u8) << (n - 1);
    }
    let rows = 6 * (PROJECTIONS + 1);
    bits += rows * (64 + 16);
    bound_sum +=
        BigUint::from(rows) * ((BigUint::from(1u8) << 63usize) + (BigUint::from(1u8) << 15usize));
    let factor_bits = (bound_sum - BigUint::from(1u8)).bits() as usize;
    let length = bits + rows * factor_bits;
    eprintln!("AUDIT amortized PKC: coefficient bits={bits}, proof bits={length}, per-proof G/H bytes={}, three PKC witnesses total={} bits, three links revisit those bits",2*length*std::mem::size_of::<RistrettoPoint>(),3*length);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bf::{
        evaluation_proof::RepLayout,
        rlwe::{generate_keys_with_profile, RlweProfile},
    };
    use curve25519_dalek_ng::traits::MultiscalarMul;

    #[test]
    fn numeric_bridge_rejects_different_bounded_openings_and_valid_proof_splicing() {
        let pc = PedersenGens::default();
        let mut rng = rand::rngs::OsRng;
        let a = Matrix::from([[poly(Q0::from(1u64)), poly(Q0::from(0u64))]]);
        let t = Matrix::from([[poly(Q0::from(3u64))]]);
        let f = Polynomial::new(&[Q0::from(0u64), Q0::from(1u64)]);
        let bounds = Matrix::from([[Bounds(vec![3])], [Bounds(vec![3])]]);
        let problem = |second| {
            let s = Matrix::from([[poly(Q0::from(3u64))], [poly(Q0::from(second))]]);
            LogProofProverKnowledge::new(&a, &s, &t, &bounds, &f)
        };
        let pk = problem(4u64);
        let other = problem(5u64);
        let gens = LogProofGenerators::new(pk.vk.l() as usize);
        let half = Scalar::random(&mut rng);
        let digest = [23; 32];
        let make = |pk, half: &Scalar| {
            LogProof::create_with_shared(
                &mut transcript(&digest, 0, 0),
                pk,
                &gens.g,
                &gens.h,
                &pc.B_blinding,
                half,
                &[],
            )
        };
        let ring = make(&pk, &half);
        let other_ring = make(&other, &Scalar::random(&mut rng));
        for p in [&ring, &other_ring] {
            p.verify(
                &mut transcript(&digest, 0, 0),
                &pk.vk,
                &gens.g,
                &gens.h,
                &pc.B_blinding,
            )
            .unwrap();
        }
        if !cfg!(debug_assertions) {
            // Recompute a proof for a FALSE statement, rather than corrupting
            // an existing transcript. Release verifiers must reject it.
            let bad = LogProofProverKnowledge {
                vk: pk.vk.clone(),
                s: Matrix::from([[poly(Q0::from(4u64))], [poly(Q0::from(4u64))]]),
            };
            let forged = make(&bad, &Scalar::random(&mut rng));
            assert!(forged
                .verify(
                    &mut transcript(&digest, 0, 0),
                    &pk.vk,
                    &gens.g,
                    &gens.h,
                    &pc.B_blinding
                )
                .is_err());
        }
        let layout = Layout {
            bounds: vec![Bound::Signed(4); 2],
            reps: Vec::<RepLayout>::new(),
            n: 16,
            count: 2,
            limbs: 8,
        };
        let selected = [0, 1];
        let blinds = [Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let commitments = [
            pc.commit(Scalar::from(3u64), blinds[0])
                .compress()
                .to_bytes(),
            pc.commit(Scalar::from(4u64), blinds[1])
                .compress()
                .to_bytes(),
        ];
        let arithmetic = b"independently verified arithmetic proof";
        let mut material = link_material(
            &digest,
            0,
            0,
            &ring,
            &gens,
            &layout,
            &selected,
            &commitments,
            arithmetic,
            &pc,
        )
        .unwrap();
        let bits = LogProof::binary_witness(&pk);
        let left = bits
            .iter()
            .map(|b| Scalar::from(*b as u64))
            .collect::<Vec<_>>();
        let zeros = vec![Scalar::zero(); left.len()];
        let blind = half
            + half
            + material
                .blind_weights
                .iter()
                .zip(&blinds)
                .fold(Scalar::zero(), |s, (a, b)| s + a * b);
        assert_eq!(
            RistrettoPoint::multiscalar_mul(
                left.iter().chain([&blind]),
                material.g.iter().chain([&pc.B_blinding])
            ),
            material.commitment
        );
        let knowledge =
            InnerProductProverKnowledge::new(&left, &zeros, &blind, &material.commitment);
        let link = InnerProductProof::create(
            &mut material.t,
            &knowledge,
            &material.g,
            &gens.g,
            &pc.B_blinding,
        );
        let check = |ring, commitments: &[[u8; 32]]| {
            // Hold the digest fixed deliberately: rejection must also follow
            // from the common-opening equation, not only transcript hashing.
            let mut m = link_material(
                &digest,
                0,
                0,
                ring,
                &gens,
                &layout,
                &selected,
                commitments,
                arithmetic,
                &pc,
            )
            .unwrap();
            link.verify(
                &mut m.t,
                &InnerProductVerifierKnowledge {
                    t: m.commitment,
                    x: Scalar::zero(),
                },
                &m.g,
                &gens.g,
                &pc.B_blinding,
            )
        };
        check(&ring, &commitments).unwrap();
        let mut wrong = commitments;
        wrong[1] = pc
            .commit(Scalar::from(5u64), blinds[1])
            .compress()
            .to_bytes();
        assert!(check(&ring, &wrong).is_err());
        let mut outside = commitments;
        outside[1] = pc
            .commit(Scalar::from(20u64), blinds[1])
            .compress()
            .to_bytes();
        assert!(check(&ring, &outside).is_err());
        assert!(check(&other_ring, &commitments).is_err());
        assert!(check(&other_ring, &wrong).is_err());
        let mut encoded = bincode::serialize(&link).unwrap();
        encoded.push(0);
        assert!(decode::<InnerProductProof>(&encoded).is_err());
        // A well-formed encoding can still have an impossible folding length.
        // Match the dependency's field order to exercise its checked shift.
        #[derive(Serialize)]
        struct Malformed {
            t_1: Vec<CompressedRistretto>,
            t_minus1: Vec<CompressedRistretto>,
            w: CompressedRistretto,
            w_prime: CompressedRistretto,
            z_1: Scalar,
            z_2: Scalar,
            tau: Scalar,
        }
        let identity = RistrettoPoint::default().compress();
        let malformed = Malformed {
            t_1: vec![identity; 65],
            t_minus1: vec![identity; 65],
            w: identity,
            w_prime: identity,
            z_1: Scalar::zero(),
            z_2: Scalar::zero(),
            tau: Scalar::zero(),
        };
        let malformed: InnerProductProof =
            decode(&bincode::serialize(&malformed).unwrap()).unwrap();
        assert!(malformed
            .verify(
                &mut Transcript::new(b"malformed-length"),
                &InnerProductVerifierKnowledge {
                    t: RistrettoPoint::default(),
                    x: Scalar::zero()
                },
                &gens.g,
                &gens.h,
                &pc.B_blinding
            )
            .is_err());
    }

    #[test]
    fn auxiliary_embedding_refuses_an_unsafe_scalar_lift() {
        let layout = Layout {
            bounds: vec![Bound::Signed(4)],
            reps: Vec::new(),
            n: 16,
            count: 1,
            limbs: 8,
        };
        let a = Matrix::from([[poly(Q0::from(1u64))]]);
        let t = Matrix::from([[poly(Q0::from(1u64))]]);
        let f = Polynomial::new(&[Q0::from(0u64), Q0::from(1u64)]);
        let safe = LogProofVerifierKnowledge::new(
            a.clone(),
            t.clone(),
            f.clone(),
            Matrix::from([[Bounds(vec![3])]]),
        );
        embedding_checks(&safe, &layout, &[0], 1u64 << 62).unwrap();
        let unsafe_lift =
            LogProofVerifierKnowledge::new(a, t, f, Matrix::from([[Bounds(vec![110])]]));
        assert!(embedding_checks(&unsafe_lift, &layout, &[0], 1u64 << 62).is_err());
    }

    #[test]
    fn public_adjoint_supports_the_adaptive_32k_native_modulus() {
        let (public, _) = generate_keys_with_profile(
            &mut rand09::rng(),
            RlweProfile::for_buckets(20000).unwrap(),
        )
        .unwrap();
        let n = public.ring_dimension();
        assert_eq!(n, 32768);
        let q = public.parameters.moduli()[1];
        let f = fhe_math::zq::Modulus::new(q).unwrap();
        let a = (0..n).map(|i| q / 2 + i as u64).collect::<Vec<_>>();
        let gamma = (0..n).map(|i| q - 1 - i as u64).collect::<Vec<_>>();
        let adj = modular_adjoint(&a, &gamma, q).unwrap();
        // Independent sparse multiplication by B=3+5*X^(N-1).
        let mut lhs = 0;
        for i in 0..n {
            lhs = f.add(lhs, f.mul(gamma[i], f.mul(a[i], 3)));
            let term = f.mul(a[i], 5);
            lhs = if i == 0 {
                f.add(lhs, f.mul(gamma[n - 1], term))
            } else {
                f.sub(lhs, f.mul(gamma[i - 1], term))
            };
        }
        let rhs = f.add(f.mul(adj[0], 3), f.mul(adj[n - 1], 5));
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn relaxed_residual_budget_is_checked_for_the_100k_profile() {
        let (public, _) =
            generate_keys_with_profile(&mut rand09::rng(), RlweProfile::Protocol100k).unwrap();
        let q = public.parameters.moduli();
        validate_decode_bound(16384, 100001, 8, public.plaintext_modulus(), q).unwrap();
        assert!(validate_decode_bound(16384, 100001, 12, public.plaintext_modulus(), q).is_err());
        assert!(
            validate_decode_bound(16384, 100001, 8, public.plaintext_modulus(), &q[..2]).is_err()
        );
    }
}
