//! 2-out-of-2 threshold exponential ElGamal over Ristretto255.
//!
//! Built on [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek) v4,
//! which provides a prime-order group, constant-time arithmetic, and
//! optional SIMD acceleration — all audited.
//!
//! # Key structure
//!
//! ```text
//!   sk1, sk2  ← Zp               (each held by one party)
//!   pk1 = sk1·G,  pk2 = sk2·G   (public shares)
//!   pk  = pk1 + pk2              (joint public key)
//! ```
//!
//! # Ciphertext
//!
//! ```text
//!   Enc_pk(m) = (r·G,  m·G + r·pk)    r ←$ Zp
//! ```
//!
//! # Threshold decryption (THDec / THTest)
//!
//! ```text
//!   THDec[sk2](ct)      → ct' ∈ THCtextSpace[pk1][m]
//!                          ct' = re-randomise(c1,  c2 - sk2·c1)  under pk1
//!
//!   THTest[sk1]{0}{ct'} → true  iff  c2' - sk1·c1'  ==  identity
//! ```
//!
//! # Cargo dependencies
//!
//! ```toml
//! curve25519-dalek = { version = "4", features = ["rand_core"] }
//! rand             = "0.8"
//! zeroize          = { version = "1", features = ["derive"] }
//! ```

use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::Identity,
};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Types ─────────────────────────────────────────────────────────────────────

/// Secret key share held by one party.  Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyShare {
    sk: Scalar,
}

impl SecretKeyShare {
    /// Expose the underlying scalar for use in zero-knowledge proofs.
    /// Visibility is limited to this crate; never send this value on the wire.
    pub(crate) fn as_scalar(&self) -> &Scalar {
        &self.sk
    }
}

/// Public key share corresponding to one secret key share: `sk·G`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyShare(pub RistrettoPoint);

/// Joint public key `pk = pk1 + pk2 = (sk1 + sk2)·G`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub RistrettoPoint);

/// ElGamal ciphertext `(c1, c2)`.
///
/// Under joint public key `pk`:  `c1 = r·G`, `c2 = m·G + r·pk`.
/// Under single share `pk1`:     `c1 = r·G`, `c2 = m·G + r·pk1`.
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
}

/// A vector of ciphertexts representing an encrypted polynomial.
///
/// `poly[d]` encrypts the coefficient of `X^d`.
#[derive(Clone, Debug)]
pub struct EncryptedPoly(pub Vec<Ciphertext>);

#[inline]
fn mul_g(s: &Scalar) -> RistrettoPoint {
    s * &RISTRETTO_BASEPOINT_TABLE
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate one party's key share.  Call once per party; combine with
/// [`combine_public_keys`] to obtain the joint public key.
pub fn generate_key_share<R: CryptoRng + RngCore>(rng: &mut R) -> (SecretKeyShare, PublicKeyShare) {
    let sk = Scalar::random(rng);
    let pk_share = mul_g(&sk);
    (SecretKeyShare { sk }, PublicKeyShare(pk_share))
}

/// Combine two public key shares into the joint public key `pk = pk1 + pk2`.
pub fn combine_public_keys(pk1: &PublicKeyShare, pk2: &PublicKeyShare) -> PublicKey {
    PublicKey(pk1.0 + pk2.0)
}

// ── Encryption ────────────────────────────────────────────────────────────────

/// `THEnc[pk](m)`: encrypt a scalar `m` under the joint public key.
///
/// Maps `m` to the group as `m·G`, then encrypts.
pub fn encrypt<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    msg: &Scalar,
) -> Ciphertext {
    encrypt_point(rng, pk, &mul_g(msg))
}

/// Encrypt a group element directly (used when the plaintext is already a point,
/// e.g. the accumulated polynomial ciphertext for the constant `1`).
pub fn encrypt_point<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    msg_point: &RistrettoPoint,
) -> Ciphertext {
    let r = Scalar::random(rng);
    let r_g = mul_g(&r);
    Ciphertext {
        c1: r_g,
        c2: msg_point + r * pk.0,
    }
}

/// Encrypt the additive identity (zero scalar / identity point).
pub fn encrypt_zero<R: CryptoRng + RngCore>(rng: &mut R, pk: &PublicKey) -> Ciphertext {
    encrypt_point(rng, pk, &RistrettoPoint::identity())
}

/// Encrypt the multiplicative identity as a scalar (`1·G`).
pub fn encrypt_one<R: CryptoRng + RngCore>(rng: &mut R, pk: &PublicKey) -> Ciphertext {
    encrypt(rng, pk, &Scalar::one())
}

// ── Homomorphic operations on single ciphertexts ─────────────────────────────

/// `THAdd[pk]`: homomorphic addition of two ciphertexts.
///
/// If `a` encrypts `m_a` and `b` encrypts `m_b`, the result encrypts `m_a + m_b`.
#[inline]
pub fn ct_add(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    Ciphertext {
        c1: a.c1 + b.c1,
        c2: a.c2 + b.c2,
    }
}

/// `s · THMult[pk]`: scale a ciphertext by a scalar.
///
/// If `ct` encrypts `m`, the result encrypts `s·m`.
#[inline]
pub fn ct_scalar_mul(ct: &Ciphertext, s: &Scalar) -> Ciphertext {
    Ciphertext {
        c1: s * ct.c1,
        c2: s * ct.c2,
    }
}

/// `THRand[pk](ct)`: re-randomize a ciphertext without changing the plaintext.
///
/// Adds a fresh encryption of zero: `(r'·G, r'·pk)`.
pub fn rerandomize<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    ct: &Ciphertext,
) -> Ciphertext {
    let r = Scalar::random(rng);
    Ciphertext {
        c1: ct.c1 + mul_g(&r),
        c2: ct.c2 + r * pk.0,
    }
}

// ── Threshold decryption ──────────────────────────────────────────────────────

/// `THDec[sk2](ct)`: partial decryption by party 2.
///
/// Removes party 2's key-share contribution and re-randomizes so that the
/// result is uniformly distributed in `THCtextSpace[pk1][m]`.  The output
/// is a valid ElGamal ciphertext under `pk1 = sk1·G` alone.
///
/// ```text
///   (c1,  c2 - sk2·c1)   =  (r·G,  m·G + r·pk1)
///   → re-randomise under pk1 with fresh r'
///   → ((r+r')·G,  m·G + (r+r')·pk1)
/// ```
///
/// `pk1` must be the *other* party's public key share.
/// Like [`partial_decrypt`] but also returns the re-randomization scalar `r'`
/// used internally, which is required to generate a `PartialDecryptProof`.
pub fn partial_decrypt_with_witness<R: CryptoRng + RngCore>(
    rng: &mut R,
    sk2: &SecretKeyShare,
    pk1: &PublicKeyShare,
    ct: &Ciphertext,
) -> (Ciphertext, Scalar) {
    let d = ct.c2 - sk2.sk * ct.c1;
    let r_prime = Scalar::random(rng);
    let out = Ciphertext {
        c1: ct.c1 + mul_g(&r_prime),
        c2: d + r_prime * pk1.0,
    };
    (out, r_prime)
}

pub fn partial_decrypt<R: CryptoRng + RngCore>(
    rng: &mut R,
    sk2: &SecretKeyShare,
    pk1: &PublicKeyShare,
    ct: &Ciphertext,
) -> Ciphertext {
    partial_decrypt_with_witness(rng, sk2, pk1, ct).0
}

/// `THTest[sk1]{0}{ct}`: test whether a (partially decrypted) ciphertext
/// encrypts the additive identity (zero / the identity point).
///
/// `ct` must be a ciphertext in `THCtextSpace[pk1]`, i.e. the output of
/// [`partial_decrypt`] called with the *other* party's key share.
///
/// ```text
///   c2 - sk1·c1  ==  identity   ⟺   plaintext == 0
/// ```
pub fn test_zero(sk1: &SecretKeyShare, ct: &Ciphertext) -> bool {
    let m_point = ct.c2 - sk1.sk * ct.c1;
    m_point == RistrettoPoint::identity()
}

/// `THTest[sk1]{m}{ct}`: test whether a (partially decrypted) ciphertext
/// encrypts a specific scalar `msg`.
pub fn test_eq(sk1: &SecretKeyShare, ct: &Ciphertext, msg: &Scalar) -> bool {
    let m_point = ct.c2 - sk1.sk * ct.c1;
    m_point == mul_g(msg)
}

// ── Polynomial ciphertext operations ─────────────────────────────────────────

/// `THEnc[pk](poly)`: encrypt a polynomial coefficient-by-coefficient.
///
/// Returns an [`EncryptedPoly`] where `result[d]` encrypts `poly[d]`
/// (the coefficient of `X^d`).
pub fn encrypt_poly<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    coeffs: &[Scalar],
) -> EncryptedPoly {
    EncryptedPoly(coeffs.iter().map(|c| encrypt(rng, pk, c)).collect())
}

/// `THRand[pk](poly_ct)`: re-randomize every coefficient ciphertext.
///
/// Like [`rerandomize_poly`] but also returns the vector of re-randomization
/// scalars `(r_0, …, r_{n})`, one per coefficient.  Required to generate a
/// `RerandomProof` proving the re-randomization was performed honestly.
pub fn rerandomize_poly_with_witness<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    poly: &EncryptedPoly,
) -> (EncryptedPoly, Vec<Scalar>) {
    let mut r_vec = Vec::with_capacity(poly.0.len());
    let mut out_cts = Vec::with_capacity(poly.0.len());
    for ct in &poly.0 {
        let r = Scalar::random(rng);
        out_cts.push(Ciphertext {
            c1: ct.c1 + mul_g(&r),
            c2: ct.c2 + r * pk.0,
        });
        r_vec.push(r);
    }
    (EncryptedPoly(out_cts), r_vec)
}

/// `THRand[pk](poly_ct)`: re-randomize every coefficient ciphertext.
pub fn rerandomize_poly<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    poly: &EncryptedPoly,
) -> EncryptedPoly {
    rerandomize_poly_with_witness(rng, pk, poly).0
}

/// `THEval[pk]{poly_ct}{x}`: evaluate an encrypted polynomial at a point `x`.
///
/// Uses Horner's method, costing `n` scalar multiplications and `n` additions:
///
/// ```text
///   Enc(P(x)) = Enc(a_n)*x^0 iterated as  acc = acc·x + Enc(a_d)
/// ```
///
/// The result is a single ciphertext encrypting `P(x)`.
pub fn eval_poly(poly: &EncryptedPoly, x: &Scalar) -> Ciphertext {
    assert!(!poly.0.is_empty(), "polynomial must have at least one coefficient");

    // Horner: start from the highest-degree coefficient.
    let mut acc = poly.0.last().unwrap().clone();
    for ct in poly.0[..poly.0.len() - 1].iter().rev() {
        // acc = acc * x + ct
        acc = ct_add(&ct_scalar_mul(&acc, x), ct);
    }
    acc
}

/// `poly_ct THDiv[pk] (X - x)`: divide an encrypted polynomial by the
/// monic linear factor `(X − x)`.
///
/// Caller must ensure that `x` is a root of the plaintext polynomial;
/// the result is undefined (but not unsafe) otherwise.
///
/// Uses the homomorphic synthetic-division recurrence from §2 of the paper:
///
/// ```text
///   b[n-1] = a[n]
///   b[d]   = a[d+1] + x · b[d+1]    for d = n-2 … 0
/// ```
///
/// Costs `n` scalar multiplications and `n` additions.
pub fn div_poly_linear(poly: &EncryptedPoly, x: &Scalar) -> EncryptedPoly {
    let n = poly.0.len().checked_sub(1).expect("polynomial must have degree >= 1");
    assert!(n >= 1, "can only divide a polynomial of degree >= 1");

    let mut quotient = vec![poly.0[0].clone(); n]; // pre-allocate n slots

    // b[n-1] = a[n]  (leading coefficient of the quotient)
    quotient[n - 1] = poly.0[n].clone();

    // b[d] = a[d+1] + x · b[d+1]  for d = n-2 down to 0
    for d in (0..n - 1).rev() {
        let scaled = ct_scalar_mul(&quotient[d + 1], x);
        quotient[d] = ct_add(&poly.0[d + 1], &scaled);
    }

    EncryptedPoly(quotient)
}

/// `poly_mul_scalar`: multiply every coefficient ciphertext by a plaintext scalar.
///
/// If `poly` encrypts `P(X)`, the result encrypts `s · P(X)`.
pub fn poly_scalar_mul(poly: &EncryptedPoly, s: &Scalar) -> EncryptedPoly {
    EncryptedPoly(poly.0.iter().map(|ct| ct_scalar_mul(ct, s)).collect())
}

/// `poly_add`: coefficient-wise homomorphic addition of two encrypted polynomials.
///
/// If `a` encrypts `P(X)` and `b` encrypts `Q(X)`, the result encrypts `P(X) + Q(X)`,
/// padded to the length of the longer operand.
pub fn poly_add(a: &EncryptedPoly, b: &EncryptedPoly) -> EncryptedPoly {
    let (longer, shorter) = if a.0.len() >= b.0.len() {
        (&a.0, &b.0)
    } else {
        (&b.0, &a.0)
    };
    // Clone the longer poly, then fold in the shorter one coefficient-by-coefficient.
    let mut result = longer.clone();
    for (d, ct) in shorter.iter().enumerate() {
        result[d] = ct_add(&result[d], ct);
    }
    EncryptedPoly(result)
}

/// Multiply an encrypted polynomial by the plaintext polynomial `(X − x)`.
///
/// If `poly` encrypts `P(X)`, the result encrypts `P(X)·(X − x)`.
/// This is the inverse of [`div_poly_linear`] and is used in `THMult[pk]`.
///
/// ```text
///   result[0]   = −x · poly[0]
///   result[d]   = poly[d-1] − x · poly[d]    for d = 1 … n-1
///   result[n]   = poly[n-1]
/// ```
pub fn poly_mul_linear(poly: &EncryptedPoly, x: &Scalar) -> EncryptedPoly {
    let n = poly.0.len(); // degree of input is n-1; output degree is n
    let neg_x = -x;
    let mut result = Vec::with_capacity(n + 1);

    // constant term: -x · a[0]
    result.push(ct_scalar_mul(&poly.0[0], &neg_x));

    // middle terms: a[d-1] - x · a[d]
    for d in 1..n {
        let term = ct_add(&poly.0[d - 1], &ct_scalar_mul(&poly.0[d], &neg_x));
        result.push(term);
    }

    // leading term: a[n-1]  (coefficient of X^n)
    result.push(poly.0[n - 1].clone());

    EncryptedPoly(result)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn setup() -> (SecretKeyShare, PublicKeyShare, SecretKeyShare, PublicKeyShare, PublicKey) {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        (sk1, pk1, sk2, pk2, pk)
    }

    // ── Basic encrypt / threshold-decrypt roundtrip ─────────────────────────

    #[test]
    fn test_threshold_decrypt_zero() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        // Encrypt 0.
        let ct = encrypt_zero(&mut rng, &pk);

        // Party 2 partially decrypts; party 1 tests for zero.
        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct);
        assert!(test_zero(&sk1, &ct_half));
    }

    #[test]
    fn test_threshold_decrypt_nonzero() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        // Encrypt a non-zero message.
        let msg = Scalar::from(42u64);
        let ct = encrypt(&mut rng, &pk, &msg);

        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct);
        assert!(!test_zero(&sk1, &ct_half));
        assert!(test_eq(&sk1, &ct_half, &msg));
    }

    // ── Homomorphic add ─────────────────────────────────────────────────────

    #[test]
    fn test_homomorphic_add() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let a = Scalar::from(7u64);
        let b = Scalar::from(11u64);
        let ct_a = encrypt(&mut rng, &pk, &a);
        let ct_b = encrypt(&mut rng, &pk, &b);

        let ct_sum = ct_add(&ct_a, &ct_b);
        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct_sum);
        assert!(test_eq(&sk1, &ct_half, &(a + b)));
    }

    // ── Scalar multiplication ────────────────────────────────────────────────

    #[test]
    fn test_scalar_mul() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let m = Scalar::from(5u64);
        let s = Scalar::from(3u64);
        let ct = encrypt(&mut rng, &pk, &m);

        let ct_scaled = ct_scalar_mul(&ct, &s);
        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct_scaled);
        assert!(test_eq(&sk1, &ct_half, &(m * s)));
    }

    // ── Re-randomization preserves plaintext ────────────────────────────────

    #[test]
    fn test_rerandomize() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let msg = Scalar::from(99u64);
        let ct = encrypt(&mut rng, &pk, &msg);
        let ct_rand = rerandomize(&mut rng, &pk, &ct);

        // Ciphertexts differ (with overwhelming probability).
        assert_ne!(ct.c1, ct_rand.c1);

        // But both decrypt to the same plaintext.
        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct_rand);
        assert!(test_eq(&sk1, &ct_half, &msg));
    }

    // ── Polynomial evaluation ────────────────────────────────────────────────

    #[test]
    fn test_eval_poly() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        // P(X) = 1 + 2X + 3X^2
        let coeffs = [Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let x = Scalar::from(4u64);
        // P(4) = 1 + 8 + 48 = 57
        let expected = Scalar::from(57u64);

        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let eval_ct = eval_poly(&poly_ct, &x);

        let eval_half = partial_decrypt(&mut rng, &sk2, &pk1, &eval_ct);
        assert!(test_eq(&sk1, &eval_half, &expected));
    }

    // ── Polynomial division ──────────────────────────────────────────────────

    #[test]
    fn test_div_poly_linear() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        // P(X) = (X − 2)(X − 3) = X^2 − 5X + 6  →  [6, -5, 1]
        let coeffs = [Scalar::from(6u64), -Scalar::from(5u64), Scalar::from(1u64)];
        let root = Scalar::from(2u64); // divide by (X − 2) to get (X − 3) = [-3, 1]

        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let quot_ct = div_poly_linear(&poly_ct, &root);

        assert_eq!(quot_ct.0.len(), 2);

        // Quotient is (X − 3): constant = −3, leading = 1.
        let c0_half = partial_decrypt(&mut rng, &sk2, &pk1, &quot_ct.0[0]);
        assert!(test_eq(&sk1, &c0_half, &(-Scalar::from(3u64))));

        let c1_half = partial_decrypt(&mut rng, &sk2, &pk1, &quot_ct.0[1]);
        assert!(test_eq(&sk1, &c1_half, &Scalar::from(1u64)));
    }

    // ── div_poly ∘ mul_poly_linear is identity ───────────────────────────────

    #[test]
    fn test_mul_then_div() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let coeffs = [Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let root = Scalar::from(7u64);

        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let expanded = poly_mul_linear(&poly_ct, &root);
        let recovered = div_poly_linear(&expanded, &root);

        assert_eq!(recovered.0.len(), coeffs.len());

        for (d, (orig, recov)) in coeffs.iter().zip(recovered.0.iter()).enumerate() {
            let half = partial_decrypt(&mut rng, &sk2, &pk1, recov);
            assert!(test_eq(&sk1, &half, orig), "mismatch at degree {d}");
        }
    }
}
