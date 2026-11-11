//! Adapter for variable-length linear Ristretto relations in `sigma_fun`.
//!
//! The package supplies Fiat–Shamir, nonce derivation, and OR simulation/composition.
//! Its built-in curve protocols use Edwards points or secp256k1, so this adapter
//! supplies only the linear map over our existing prime-order Ristretto group.
// sigma_fun 0.8 exposes generic-array 0.14 in its public trait API.
#![allow(deprecated)]
use curve25519_dalek_ng::{
    ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, MultiscalarMul, VartimeMultiscalarMul},
};
use rand::{CryptoRng, RngCore, SeedableRng};
use sha2::digest::Update;
use sigma_fun::{generic_array::GenericArray, typenum::U31, FiatShamir, HashTranscript, Sigma};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) type Proof = sigma_fun::CompactProof<Linear>;
pub(crate) type OrProof = sigma_fun::CompactProof<sigma_fun::Or<Linear, Linear>>;
type Transcript = HashTranscript<sha2::Sha256, rand_chacha::ChaCha20Rng>;

/// The group element of one term: a base registered with `Statement::fixed`, or a
/// point used only in this term.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Base {
    Fixed(usize),
    Point(RistrettoPoint),
}
/// A public base shared by many terms. Its encoding and fixed-base table are
/// computed once per statement rather than once per term.
#[derive(Clone)]
struct FixedBase {
    point: RistrettoPoint,
    encoding: CompressedRistretto,
    table: Arc<RistrettoBasepointTable>,
}
impl core::fmt::Debug for FixedBase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("FixedBase").field(&self.encoding).finish()
    }
}
#[derive(Clone, Debug)]
struct Equation {
    image: RistrettoPoint,
    // Canonical encoding of `image`, when the caller already has it.
    encoding: Option<CompressedRistretto>,
    terms: Vec<(usize, Base)>,
}
#[derive(Clone, Debug)]
pub(crate) struct Statement {
    context: [u8; 32],
    fixed: Vec<FixedBase>,
    equations: Vec<Equation>,
}
impl Statement {
    pub fn new(context: [u8; 32]) -> Self {
        Self {
            context,
            fixed: Vec::new(),
            equations: Vec::new(),
        }
    }
    /// Register a public base for use in many terms; repeated points share one entry.
    pub fn fixed(&mut self, point: RistrettoPoint) -> Base {
        if let Some(i) = self.fixed.iter().position(|b| b.point == point) {
            return Base::Fixed(i);
        }
        self.fixed.push(FixedBase {
            point,
            encoding: point.compress(),
            table: super::performance::table(&point),
        });
        Base::Fixed(self.fixed.len() - 1)
    }
    pub fn add(&mut self, image: RistrettoPoint, terms: impl IntoIterator<Item = (usize, Base)>) {
        self.equations.push(Equation {
            image,
            encoding: None,
            terms: terms.into_iter().collect(),
        });
    }
    /// As `add`, for an image whose canonical encoding is already known.
    pub fn add_encoded(
        &mut self,
        image: RistrettoPoint,
        encoding: [u8; 32],
        terms: impl IntoIterator<Item = (usize, Base)>,
    ) {
        debug_assert_eq!(
            image.compress().to_bytes(),
            encoding,
            "image/encoding mismatch"
        );
        self.equations.push(Equation {
            image,
            encoding: Some(CompressedRistretto(encoding)),
            terms: terms.into_iter().collect(),
        });
    }
    fn point(&self, base: &Base) -> RistrettoPoint {
        match base {
            Base::Fixed(f) => self.fixed[*f].point,
            Base::Point(p) => *p,
        }
    }
    /// Constant-time sum of scalars[i] * base over one equation's terms.
    fn evaluate(&self, eq: &Equation, scalars: &[Scalar]) -> RistrettoPoint {
        // Secret-holding vectors are allocated at full size: growing one would free
        // an unwiped copy of its contents.
        let count = dynamic_terms(eq.terms.iter());
        let mut fixed = Zeroizing::new(vec![None::<Scalar>; self.fixed.len()]);
        let mut dynamic = Zeroizing::new(Vec::with_capacity(count));
        let mut points = Vec::with_capacity(count);
        for (i, base) in &eq.terms {
            match base {
                Base::Fixed(f) => *fixed[*f].get_or_insert(Scalar::zero()) += scalars[*i],
                Base::Point(p) => {
                    dynamic.push(scalars[*i]);
                    points.push(*p);
                }
            }
        }
        let mut sum = if points.is_empty() {
            RistrettoPoint::identity()
        } else {
            RistrettoPoint::multiscalar_mul(dynamic.iter(), &points)
        };
        for (s, base) in fixed.iter().zip(&self.fixed) {
            if let Some(s) = s {
                sum += s * &*base.table;
            }
        }
        sum
    }
    /// Prover-side witness check of all equations at once, as one random linear
    /// combination; any unsatisfied equation is caught except with probability 1/l.
    /// Witness-dependent scalars use constant-time arithmetic; only the public
    /// images, weighted by fresh public coefficients, use variable-time MSM.
    /// Verification is unaffected: verifiers check every equation separately.
    pub fn satisfied_by(&self, witness: &[Scalar]) -> bool {
        let terms = || self.equations.iter().flat_map(|eq| &eq.terms);
        if terms().any(|(i, _)| *i >= witness.len()) {
            return false;
        }
        let mut rng = rand_chacha::ChaCha20Rng::from_rng(rand::rngs::OsRng)
            .expect("operating-system randomness");
        let count = dynamic_terms(terms());
        let mut fixed = Zeroizing::new(vec![Scalar::zero(); self.fixed.len()]);
        let mut secret = Zeroizing::new(Vec::with_capacity(count));
        let mut secret_points = Vec::with_capacity(count);
        let mut weights = Vec::with_capacity(self.equations.len());
        for eq in &self.equations {
            let rho = Scalar::random(&mut rng);
            weights.push(-rho);
            for (i, base) in &eq.terms {
                let s = rho * witness[*i];
                match base {
                    Base::Fixed(f) => fixed[*f] += s,
                    Base::Point(p) => {
                        secret.push(s);
                        secret_points.push(*p);
                    }
                }
            }
        }
        let mut sum = RistrettoPoint::vartime_multiscalar_mul(
            &weights,
            self.equations.iter().map(|eq| eq.image),
        );
        if !secret_points.is_empty() {
            sum += RistrettoPoint::multiscalar_mul(secret.iter(), &secret_points);
        }
        for (s, base) in fixed.iter().zip(&self.fixed) {
            sum += s * &*base.table;
        }
        sum == RistrettoPoint::identity()
    }
}
fn dynamic_terms<'a>(terms: impl Iterator<Item = &'a (usize, Base)>) -> usize {
    terms.filter(|(_, b)| matches!(b, Base::Point(_))).count()
}
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Linear(pub usize);
impl sigma_fun::Writable for Linear {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "exact-ristretto-linear-v2({})", self.0)
    }
}
fn challenge(c: &GenericArray<u8, U31>) -> Scalar {
    // A 248-bit challenge embeds injectively in the Ristretto scalar field.
    let mut bytes = [0; 32];
    bytes[..31].copy_from_slice(c);
    Scalar::from_bytes_mod_order(bytes)
}
impl Sigma for Linear {
    type Witness = Zeroizing<Vec<Scalar>>;
    type Statement = Statement;
    type AnnounceSecret = Zeroizing<Vec<Scalar>>;
    type Announcement = Vec<RistrettoPoint>;
    type Response = Vec<Scalar>;
    type ChallengeLength = U31;

    fn gen_announce_secret<R: CryptoRng + RngCore>(
        &self,
        _: &Self::Witness,
        rng: &mut R,
    ) -> Self::AnnounceSecret {
        Zeroizing::new(self.sample_response(rng))
    }
    fn sample_response<R: CryptoRng + RngCore>(&self, rng: &mut R) -> Self::Response {
        (0..self.0).map(|_| Scalar::random(rng)).collect()
    }
    fn announce(&self, statement: &Statement, secret: &Self::AnnounceSecret) -> Self::Announcement {
        statement
            .equations
            .iter()
            .map(|eq| statement.evaluate(eq, secret))
            .collect()
    }
    fn respond(
        &self,
        witness: &Self::Witness,
        _: &Statement,
        secret: Self::AnnounceSecret,
        _: &Self::Announcement,
        c: &GenericArray<u8, U31>,
    ) -> Self::Response {
        let c = challenge(c);
        (0..self.0).map(|i| secret[i] + c * witness[i]).collect()
    }
    fn implied_announcement(
        &self,
        statement: &Statement,
        c: &GenericArray<u8, U31>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        if response.len() != self.0 {
            return None;
        }
        let c = challenge(c);
        statement
            .equations
            .iter()
            .map(|eq| {
                if eq.terms.iter().any(|(i, _)| *i >= self.0) {
                    return None;
                }
                Some(RistrettoPoint::vartime_multiscalar_mul(
                    eq.terms
                        .iter()
                        .map(|(i, _)| response[*i])
                        .chain(std::iter::once(-c)),
                    eq.terms
                        .iter()
                        .map(|(_, b)| statement.point(b))
                        .chain(std::iter::once(eq.image)),
                ))
            })
            .collect()
    }
    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Statement) {
        hash.update(&statement.context);
        hash.update(&(statement.fixed.len() as u64).to_le_bytes());
        for base in &statement.fixed {
            hash.update(base.encoding.as_bytes());
        }
        hash.update(&(statement.equations.len() as u64).to_le_bytes());
        for eq in &statement.equations {
            let image = eq.encoding.unwrap_or_else(|| eq.image.compress());
            hash.update(image.as_bytes());
            hash.update(&(eq.terms.len() as u64).to_le_bytes());
            for (i, base) in &eq.terms {
                hash.update(&(*i as u64).to_le_bytes());
                match base {
                    Base::Fixed(f) => {
                        hash.update(&[0]);
                        hash.update(&(*f as u64).to_le_bytes());
                    }
                    Base::Point(p) => {
                        hash.update(&[1]);
                        hash.update(p.compress().as_bytes());
                    }
                }
            }
        }
    }
    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(&(announcement.len() as u64).to_le_bytes());
        for p in announcement {
            hash.update(p.compress().as_bytes());
        }
    }
    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(&(witness.len() as u64).to_le_bytes());
        for s in witness.iter() {
            hash.update(s.as_bytes());
        }
    }
}
pub(crate) fn prover(n: usize) -> FiatShamir<Linear, Transcript> {
    FiatShamir::new(Linear(n), Transcript::default(), None)
}
pub(crate) fn or_prover(n: usize) -> FiatShamir<sigma_fun::Or<Linear, Linear>, Transcript> {
    FiatShamir::new(
        sigma_fun::Or::new(Linear(n), Linear(n)),
        Transcript::default(),
        None,
    )
}
/// Bind a library proof to the entire application transcript, including R1CS bytes.
pub(crate) fn context(mut transcript: merlin::Transcript) -> [u8; 32] {
    let mut context = [0; 32];
    transcript.challenge_bytes(b"sigma-fun-context-v1", &mut context);
    context
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT as G;

    #[test]
    fn fixed_and_dynamic_bases_evaluate_and_check_identically() {
        let mut rng = rand::thread_rng();
        let (h, p) = (
            RistrettoPoint::random(&mut rng),
            RistrettoPoint::random(&mut rng),
        );
        let w: Vec<_> = (0..3).map(|_| Scalar::random(&mut rng)).collect();
        let mut fixed = Statement::new([1; 32]);
        let (g, hb) = (fixed.fixed(G), fixed.fixed(h));
        assert!(matches!(fixed.fixed(G), Base::Fixed(0)));
        let mut plain = Statement::new([1; 32]);
        let images = [
            w[0] * G + w[1] * h,
            w[2] * p + w[0] * G + w[1] * G,
            w[2] * h,
        ];
        fixed.add(images[0], [(0, g), (1, hb)]);
        fixed.add_encoded(
            images[1],
            images[1].compress().to_bytes(),
            [(2, Base::Point(p)), (0, g), (1, g)],
        );
        fixed.add(images[2], [(2, hb)]);
        plain.add(images[0], [(0, Base::Point(G)), (1, Base::Point(h))]);
        plain.add(
            images[1],
            [
                (2, Base::Point(p)),
                (0, Base::Point(G)),
                (1, Base::Point(G)),
            ],
        );
        plain.add(images[2], [(2, Base::Point(h))]);
        for s in [&fixed, &plain] {
            for (eq, image) in s.equations.iter().zip(&images) {
                assert_eq!(s.evaluate(eq, &w), *image);
            }
            assert!(s.satisfied_by(&w));
            for i in 0..3 {
                let mut wrong = w.clone();
                wrong[i] += Scalar::one();
                assert!(!s.satisfied_by(&wrong));
            }
            assert!(!s.satisfied_by(&w[..2]));
        }
        let witness = Zeroizing::new(w);
        let proof = prover(3).prove(&witness, &fixed, Some(&mut rng));
        assert!(prover(3).verify(&fixed, &proof));
        // Fixed and per-term bases are hashed differently; proofs do not transfer.
        assert!(!prover(3).verify(&plain, &proof));
    }
}
