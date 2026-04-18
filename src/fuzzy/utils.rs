use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_TABLE, scalar::Scalar};

use crate::crypto::elgamal::{Ciphertext, PublicKey};

pub(crate) fn encode_scalar_bits(input: &Scalar, vector_size: usize) -> Vec<Scalar> {
    let bytes = input.to_bytes();
    let mut bits = Vec::with_capacity(vector_size);
    for bit_idx in 0..vector_size {
        let bit = if bit_idx < bytes.len() * 8 {
            let byte = bytes[bit_idx / 8];
            ((byte >> (bit_idx % 8)) & 1) as u64
        } else {
            0
        };
        bits.push(Scalar::from(bit));
    }
    bits
}

pub(crate) fn encrypt_with_randomness(pk: &PublicKey, msg: &Scalar, r: Scalar) -> Ciphertext {
    let c1 = &r * &RISTRETTO_BASEPOINT_TABLE;
    let r_pk = r * pk.0;
    let c2 = if *msg == Scalar::zero() {
        r_pk
    } else if *msg == Scalar::one() {
        &Scalar::one() * &RISTRETTO_BASEPOINT_TABLE + r_pk
    } else {
        msg * &RISTRETTO_BASEPOINT_TABLE + r_pk
    };
    Ciphertext { c1, c2 }
}
