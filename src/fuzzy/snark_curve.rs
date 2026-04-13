use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct SecretKey(pub Fr);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub EdwardsProjective);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub c1: EdwardsProjective,
    pub c2: EdwardsProjective,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WirePoint {
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireCiphertext {
    pub c1: WirePoint,
    pub c2: WirePoint,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WirePublicKey {
    pub point: WirePoint,
}

pub fn generator() -> EdwardsProjective {
    EdwardsProjective::generator()
}

pub fn scalar_from_u64(value: u64) -> Fr {
    Fr::from(value)
}

pub fn point_coords(point: &EdwardsProjective) -> (Fq, Fq) {
    let affine = point.into_affine();
    (*affine.x().unwrap(), *affine.y().unwrap())
}

impl WirePoint {
    pub fn from_native(point: &EdwardsProjective) -> Self {
        let mut bytes = Vec::new();
        point
            .into_affine()
            .serialize_compressed(&mut bytes)
            .expect("serialize snark point");
        Self { bytes }
    }

    pub fn to_native(&self) -> Result<EdwardsProjective, String> {
        let affine = EdwardsAffine::deserialize_compressed(self.bytes.as_slice())
            .map_err(|e| format!("decode snark point: {e}"))?;
        Ok(affine.into_group())
    }
}

impl WireCiphertext {
    pub fn from_native(ct: &Ciphertext) -> Self {
        Self {
            c1: WirePoint::from_native(&ct.c1),
            c2: WirePoint::from_native(&ct.c2),
        }
    }

    pub fn to_native(&self) -> Result<Ciphertext, String> {
        Ok(Ciphertext {
            c1: self.c1.to_native()?,
            c2: self.c2.to_native()?,
        })
    }
}

impl WirePublicKey {
    pub fn from_native(pk: &PublicKey) -> Self {
        Self {
            point: WirePoint::from_native(&pk.0),
        }
    }

    pub fn to_native(&self) -> Result<PublicKey, String> {
        Ok(PublicKey(self.point.to_native()?))
    }
}

pub fn generate_keypair<R: CryptoRng + RngCore>(rng: &mut R) -> (SecretKey, PublicKey) {
    let sk = Fr::rand(rng);
    let pk = generator().mul_bigint(sk.into_bigint());
    (SecretKey(sk), PublicKey(pk))
}

pub fn encrypt_with_randomness(pk: &PublicKey, msg: u64, randomness: Fr) -> Ciphertext {
    let g = generator();
    Ciphertext {
        c1: g.mul_bigint(randomness.into_bigint()),
        c2: g.mul_bigint(scalar_from_u64(msg).into_bigint())
            + pk.0.mul_bigint(randomness.into_bigint()),
    }
}

pub fn encrypt<R: CryptoRng + RngCore>(rng: &mut R, pk: &PublicKey, msg: u64) -> (Ciphertext, Fr) {
    let randomness = Fr::rand(rng);
    (encrypt_with_randomness(pk, msg, randomness), randomness)
}
