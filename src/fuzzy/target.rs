use std::io::{self, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream};

use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::CompressedRistretto,
};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{
    combine_public_keys, ct_scalar_mul, encrypt_one, encrypt_zero, partial_decrypt, test_zero,
    Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::fuzzy::proof;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireCiphertext {
    pub c1: [u8; 32],
    pub c2: [u8; 32],
}

impl WireCiphertext {
    pub fn from_native(ct: &Ciphertext) -> Self {
        Self {
            c1: ct.c1.compress().to_bytes(),
            c2: ct.c2.compress().to_bytes(),
        }
    }

    pub fn to_native(&self) -> Result<Ciphertext, String> {
        let c1 = CompressedRistretto::from_slice(&self.c1)
            .decompress()
            .ok_or("c1 not on curve")?;
        let c2 = CompressedRistretto::from_slice(&self.c2)
            .decompress()
            .ok_or("c2 not on curve")?;
        Ok(Ciphertext { c1, c2 })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireEncryptedPoly(pub Vec<WireCiphertext>);

impl WireEncryptedPoly {
    pub fn from_native(p: &EncryptedPoly) -> Self {
        Self(p.0.iter().map(WireCiphertext::from_native).collect())
    }

    pub fn to_native(&self) -> Result<EncryptedPoly, String> {
        let cts: Result<Vec<_>, _> = self.0.iter().map(|w| w.to_native()).collect();
        Ok(EncryptedPoly(cts?))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TargetToMonitor {
    Outsource {
        accum: WireEncryptedPoly,
        encrypted_item_bits: Vec<Vec<WireCiphertext>>,
    },
    NextRound {
        masked_distances: Vec<WireCiphertext>,
        target_compute_proof_ms: f64,
    },
    Reject {
        reason: String,
        target_compute_proof_ms: f64,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MonitorToTarget {
    pub next_accum: WireEncryptedPoly,
    /// Threshold-partially-decrypted accumulated evaluation in `THCtextSpace[pk1]`.
    pub accum_eval: WireCiphertext,
    pub c: Vec<WireCiphertext>,
    pub proof: Vec<u8>,
}

pub fn send_msg<T: Serialize>(stream: &mut TcpStream, msg: &T) -> io::Result<()> {
    let bytes =
        bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = (bytes.len() as u32).to_be_bytes();
    let mut bufs: &mut [IoSlice<'_>] = &mut [IoSlice::new(&len), IoSlice::new(&bytes)];
    let total = len.len() + bytes.len();
    let mut written = 0;
    while written < total {
        written += stream.write_vectored(bufs)?;
        IoSlice::advance_slices(&mut bufs, written);
    }
    Ok(())
}

pub fn recv_msg<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub struct Target {
    _t_set: Vec<Scalar>,
    _encoded_t_set: Vec<Vec<Scalar>>,
    encrypted_item_bits: Vec<Vec<Ciphertext>>,
    accum_degree: usize,
    sk1: SecretKeyShare,
    _pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    _vector_size: usize,
}

impl Target {
    pub fn new(
        t_set: Vec<Scalar>,
        accum_degree: usize,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        vector_size: usize,
    ) -> Self {
        let encoded_t_set = t_set
            .iter()
            .map(|item| encode_scalar_bits(item, vector_size))
            .collect();
        let pk = combine_public_keys(&pk1, &pk2);
        let encrypted_item_bits = Vec::new();
        Self {
            _t_set: t_set,
            _encoded_t_set: encoded_t_set,
            encrypted_item_bits,
            accum_degree,
            sk1,
            _pk1: pk1,
            pk2,
            pk,
            _vector_size: vector_size,
        }
    }

    pub(crate) fn build_accum_ctext<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
    ) -> EncryptedPoly {
        let mut coeffs = Vec::with_capacity(self.accum_degree + 1);
        coeffs.push(encrypt_one(rng, &self.pk));
        while coeffs.len() < self.accum_degree + 1 {
            coeffs.push(encrypt_zero(rng, &self.pk));
        }
        EncryptedPoly(coeffs)
    }

    pub(crate) fn encrypt_encoded_item_bits<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
    ) -> Vec<Vec<Ciphertext>> {
        self._encoded_t_set
            .iter()
            .map(|encoded_item| {
                encoded_item
                    .iter()
                    .map(|bit| encrypt_with_randomness(&self.pk, bit, Scalar::random(rng)))
                    .collect()
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn set_outsourced_item_bits(&mut self, encrypted_item_bits: Vec<Vec<Ciphertext>>) {
        self.encrypted_item_bits = encrypted_item_bits;
    }

    pub(crate) fn process_round(
        &mut self,
        rng: &mut OsRng,
        current_accum: &EncryptedPoly,
        msg: &MonitorToTarget,
    ) -> Result<(EncryptedPoly, Vec<Ciphertext>), String> {
        let next_accum = msg.next_accum.to_native()?;
        let accum_eval = msg.accum_eval.to_native()?;

        if next_accum.0.len() != current_accum.0.len() {
            return Err("next_accum length mismatch".to_string());
        }
        if msg.c.len() != self._t_set.len() {
            return Err("c length mismatch".to_string());
        }
        let c: Result<Vec<_>, _> = msg
            .c
            .iter()
            .map(|ct| ct.to_native())
            .collect();
        let c = c?;
        proof::verify_round(
            &msg.proof,
            &self.pk,
            &self._pk1,
            &self.pk2,
            current_accum,
            &next_accum,
            &accum_eval,
            &self.encrypted_item_bits,
            &c,
        )?;
        if test_zero(&self.sk1, &accum_eval) {
            return Err("accum_eval decrypts to 0".to_string());
        }

        let mut masked_distances = c
            .iter()
            .map(|ct| self.mask_and_partial_decrypt_distance(rng, ct))
            .collect::<Vec<_>>();
        masked_distances.shuffle(rng);

        Ok((next_accum, masked_distances))
    }

    pub fn run(&mut self, addr: &str) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        eprintln!("[Target] Listening on {addr}");
        let (stream, peer) = listener.accept()?;
        eprintln!("[Target] Monitor connected from {peer}");
        self.handle(stream)
    }

    fn handle(&mut self, mut s: TcpStream) -> io::Result<()> {
        let mut rng = OsRng;
        let t_outsource_start = std::time::Instant::now();
        let mut current_accum = self.build_accum_ctext(&mut rng);
        self.encrypted_item_bits = self.encrypt_encoded_item_bits(&mut rng);
        send_msg(
            &mut s,
            &TargetToMonitor::Outsource {
                accum: WireEncryptedPoly::from_native(&current_accum),
                encrypted_item_bits: self
                    .encrypted_item_bits
                    .iter()
                    .map(|encrypted_bits| {
                        encrypted_bits
                            .iter()
                            .map(WireCiphertext::from_native)
                            .collect()
                    })
                    .collect(),
            },
        )?;
        let outsource_ms = t_outsource_start.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[Target] Outsource Time (compute -> send): {outsource_ms:.3} ms");
        eprintln!(
            "[Target] Sent initial accum ciphertext (deg {})",
            self.accum_degree
        );

        loop {
            let msg: MonitorToTarget = match recv_msg(&mut s) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    eprintln!("[Target] Done.");
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

            let target_round_start = std::time::Instant::now();
            match self.process_round(&mut rng, &current_accum, &msg) {
                Ok((next_accum, masked_distances)) => {
                    let target_compute_proof_ms =
                        target_round_start.elapsed().as_secs_f64() * 1000.0;
                    current_accum = next_accum;
                    eprintln!(
                        "[Target] Accepted fuzzy round update, masked {} ciphertexts in {:.3} ms",
                        masked_distances.len(),
                        target_compute_proof_ms
                    );
                    send_msg(
                        &mut s,
                        &TargetToMonitor::NextRound {
                            masked_distances: masked_distances
                                .iter()
                                .map(WireCiphertext::from_native)
                                .collect(),
                            target_compute_proof_ms,
                        },
                    )?;
                }
                Err(reason) => {
                    let target_compute_proof_ms =
                        target_round_start.elapsed().as_secs_f64() * 1000.0;
                    eprintln!("[Target] Reject: {reason}");
                    send_msg(
                        &mut s,
                        &TargetToMonitor::Reject {
                            reason,
                            target_compute_proof_ms,
                        },
                    )?;
                    return Ok(());
                }
            }
        }
    }

    fn mask_and_partial_decrypt_distance<R: rand::CryptoRng + rand::RngCore>(
        &self,
        rng: &mut R,
        c: &Ciphertext,
    ) -> Ciphertext {
        let z = non_zero_scalar(rng);
        let u = Scalar::random(rng);
        let u_r = Scalar::random(rng);
        let enc_u = encrypt_with_randomness(&self.pk, &u, u_r);
        let cz = ct_scalar_mul(c, &z);
        let masked = Ciphertext {
            c1: cz.c1 + enc_u.c1,
            c2: cz.c2 + enc_u.c2,
        };
        partial_decrypt(rng, &self.sk1, &self.pk2, &masked)
    }
}

fn encode_scalar_bits(input: &Scalar, vector_size: usize) -> Vec<Scalar> {
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

fn non_zero_scalar<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(rng);
        if s != Scalar::zero() {
            return s;
        }
    }
}

fn encrypt_with_randomness(pk: &PublicKey, msg: &Scalar, r: Scalar) -> Ciphertext {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::generate_key_share;
    use crate::fuzzy::monitor::Monitor;

    fn build_monitor_message_for_target(
        rng: &mut OsRng,
        target: &Target,
        sk2: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        m: Scalar,
        accum: &EncryptedPoly,
        encrypted_item_bits: &[Vec<Ciphertext>],
    ) -> MonitorToTarget {
        let monitor = Monitor::new(m, sk2, pk1, pk2, target._vector_size);
        monitor
            .build_round_message(rng, accum, encrypted_item_bits)
            .expect("monitor should build a valid round message")
    }

    #[test]
    fn test_process_round_accepts_message() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let mut target = Target::new(
            vec![Scalar::from(11u64), Scalar::from(13u64)],
            5,
            sk1,
            pk1.clone(),
            pk2,
            12,
        );
        let accum_ct = target.build_accum_ctext(&mut rng);
        let m = Scalar::from(7u64);
        target.encrypted_item_bits = target.encrypt_encoded_item_bits(&mut rng);
        let msg = build_monitor_message_for_target(
            &mut rng,
            &target,
            sk2,
            pk1,
            target.pk2.clone(),
            m,
            &accum_ct,
            &target.encrypted_item_bits,
        );

        let (next_accum_out, masked_distances) =
            target.process_round(&mut rng, &accum_ct, &msg).unwrap();
        assert_eq!(next_accum_out.0.len(), accum_ct.0.len());
        assert_eq!(masked_distances.len(), 2);
    }

    #[test]
    fn test_process_round_rejects_zero_accum_eval() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let mut target = Target::new(
            vec![Scalar::from(11u64)],
            5,
            sk1,
            pk1.clone(),
            pk2,
            8,
        );
        let zero_accum = EncryptedPoly(vec![
            encrypt_zero(&mut rng, &target.pk),
            encrypt_zero(&mut rng, &target.pk),
            encrypt_zero(&mut rng, &target.pk),
        ]);
        let m = Scalar::from(3u64);
        target.encrypted_item_bits = target.encrypt_encoded_item_bits(&mut rng);
        let msg = build_monitor_message_for_target(
            &mut rng,
            &target,
            sk2,
            pk1,
            target.pk2.clone(),
            m,
            &zero_accum,
            &target.encrypted_item_bits,
        );

        let err = target.process_round(&mut rng, &zero_accum, &msg).unwrap_err();
        assert!(
            err == "accum_eval decrypts to 0" || err.contains("sigma"),
            "unexpected rejection reason: {err}"
        );
    }

    #[test]
    fn test_target_encodes_each_set_item() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (_sk2, pk2) = generate_key_share(&mut rng);
        let t_set = vec![Scalar::from(5u64), Scalar::from(9u64), Scalar::from(12u64)];
        let target = Target::new(t_set.clone(), 5, sk1, pk1, pk2, 10);

        assert_eq!(target._t_set.len(), t_set.len());
        assert_eq!(target._encoded_t_set.len(), t_set.len());
        assert_eq!(
            target._encoded_t_set[0],
            encode_scalar_bits(&Scalar::from(5u64), 10)
        );
    }

    #[test]
    fn test_outsource_encrypts_every_item_bit_under_threshold_key() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (_sk2, pk2) = generate_key_share(&mut rng);
        let t_set = vec![Scalar::from(5u64), Scalar::from(9u64), Scalar::from(12u64)];
        let vector_size = 10;
        let target = Target::new(t_set.clone(), 5, sk1, pk1, pk2, vector_size);

        let encrypted_item_bits = target.encrypt_encoded_item_bits(&mut rng);

        assert_eq!(encrypted_item_bits.len(), t_set.len());
        for encrypted_bits in &encrypted_item_bits {
            assert_eq!(encrypted_bits.len(), vector_size);
            for ct in encrypted_bits {
                assert!(
                    ct.c1.compress().to_bytes() != [0u8; 32]
                        || ct.c2.compress().to_bytes() != [0u8; 32]
                );
            }
        }
    }
}
