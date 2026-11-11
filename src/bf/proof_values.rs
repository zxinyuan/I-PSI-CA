//! Blinded numeric inputs shared between the PKC and Bulletproof components.
use super::protocol_math::signed;
use curve25519_dalek_ng::scalar::Scalar;
use rand::{CryptoRng, RngCore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bound {
    None,
    Signed(u8),
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct Assignments {
    pub values: Vec<Scalar>,
    pub blinds: Vec<Scalar>,
    pub encoded: Vec<u64>,
}
impl Assignments {
    pub fn new() -> Self {
        Self {
            values: Vec::new(),
            blinds: Vec::new(),
            encoded: Vec::new(),
        }
    }
    pub fn scalar<R: RngCore + CryptoRng>(&mut self, rng: &mut R, value: Scalar) -> usize {
        let i = self.values.len();
        self.values.push(value);
        self.blinds.push(Scalar::random(rng));
        self.encoded.push(0);
        i
    }
    pub fn signed<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        value: i64,
        bits: u8,
    ) -> Result<usize, String> {
        if !(1..=64).contains(&bits) {
            return Err("invalid signed proof width".into());
        }
        let encoded = value as i128 + (1i128 << (bits - 1));
        if encoded < 0 || encoded >= (1i128 << bits) {
            return Err("signed proof witness exceeds declared range".into());
        }
        let i = self.scalar(rng, signed(value));
        self.encoded[i] = encoded as u64;
        Ok(i)
    }
}
