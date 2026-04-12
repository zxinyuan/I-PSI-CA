use std::io::{self, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream};

use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
};
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{
    combine_public_keys, encrypt_one, encrypt_zero, test_zero, Ciphertext, EncryptedPoly,
    PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::fuzzy::proof;
use crate::fuzzy::target_proof::{self, WireTargetHybridProof};

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
    Outsource { accum: WireEncryptedPoly },
    NextRound {
        masked_distances: Vec<WireCiphertext>,
        masked_distance_proofs: Vec<WireTargetHybridProof>,
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
    pub encrypted_input_bits: Vec<WireCiphertext>,
    /// Placeholder until the fuzzy proof system is wired in.
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
    accum_degree: usize,
    sk1: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    monitor_pk: PublicKey,
    vector_size: usize,
}

impl Target {
    pub fn new(
        t_set: Vec<Scalar>,
        accum_degree: usize,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        monitor_pk: PublicKey,
        vector_size: usize,
    ) -> Self {
        let encoded_t_set = t_set
            .iter()
            .map(|item| encode_scalar_bits(item, vector_size))
            .collect();
        Self {
            _t_set: t_set,
            _encoded_t_set: encoded_t_set,
            accum_degree,
            sk1,
            pk1,
            pk2,
            pk: combine_public_keys(&pk1, &pk2),
            monitor_pk,
            vector_size,
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

    pub(crate) fn process_round(
        &mut self,
        rng: &mut OsRng,
        current_accum: &EncryptedPoly,
        msg: &MonitorToTarget,
    ) -> Result<(EncryptedPoly, Vec<Ciphertext>, Vec<WireTargetHybridProof>), String> {
        let next_accum = msg.next_accum.to_native()?;
        let accum_eval = msg.accum_eval.to_native()?;

        if next_accum.0.len() != current_accum.0.len() {
            return Err("next_accum length mismatch".to_string());
        }
        if msg.encrypted_input_bits.len() != self.vector_size {
            return Err("encrypted_input_bits length mismatch".to_string());
        }
        let encrypted_input_bits: Result<Vec<_>, _> =
            msg.encrypted_input_bits.iter().map(|ct| ct.to_native()).collect();
        let encrypted_input_bits = encrypted_input_bits?;
        proof::verify_round(
            &msg.proof,
            &self.monitor_pk,
            &self.pk,
            &self.pk1,
            &self.pk2,
            current_accum,
            &next_accum,
            &accum_eval,
            &encrypted_input_bits,
        )?;
        if test_zero(&self.sk1, &accum_eval) {
            return Err("accum_eval decrypts to 0".to_string());
        }

        let masked_distances = self
            ._encoded_t_set
            .iter()
            .map(|encoded_x| {
                masked_distance_with_proof_for_item(
                    rng,
                    &self.monitor_pk,
                    encoded_x,
                    &encrypted_input_bits,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (masked_distances, masked_distance_proofs): (Vec<_>, Vec<_>) =
            masked_distances.into_iter().unzip();

        Ok((next_accum, masked_distances, masked_distance_proofs))
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
        send_msg(
            &mut s,
            &TargetToMonitor::Outsource {
                accum: WireEncryptedPoly::from_native(&current_accum),
            },
        )?;
        let outsource_ms = t_outsource_start.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[Target] Outsource Time (compute -> send): {outsource_ms:.3} ms");
        eprintln!("[Target] Sent initial accum ciphertext (deg {})", self.accum_degree);

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
                Ok((next_accum, masked_distances, masked_distance_proofs)) => {
                    let target_compute_proof_ms =
                        target_round_start.elapsed().as_secs_f64() * 1000.0;
                    current_accum = next_accum;
                    eprintln!(
                        "[Target] Accepted fuzzy round update, produced {} masked distances in {:.3} ms",
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
                            masked_distance_proofs,
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

fn masked_distance_with_proof_for_item<R: rand::CryptoRng + rand::RngCore>(
    rng: &mut R,
    monitor_pk: &PublicKey,
    encoded_x: &[Scalar],
    encrypted_y: &[Ciphertext],
) -> Result<(Ciphertext, WireTargetHybridProof), String> {
    if encoded_x.len() != encrypted_y.len() {
        return Err("masked distance witness length mismatch".to_string());
    }

    let mut acc = Ciphertext {
        c1: RistrettoPoint::default(),
        c2: RistrettoPoint::default(),
    };
    let mut bit_randomness = Vec::with_capacity(encoded_x.len());
    for (x_j, y_j) in encoded_x.iter().zip(encrypted_y.iter()) {
        let x_r = Scalar::random(rng);
        bit_randomness.push(x_r);
        let enc_x = encrypt_with_randomness(monitor_pk, x_j, x_r);
        let coeff = Scalar::one() - Scalar::from(2u64) * *x_j;
        acc.c1 += enc_x.c1 + coeff * y_j.c1;
        acc.c2 += enc_x.c2 + coeff * y_j.c2;
    }

    let u = Scalar::random(rng);
    let u_r = Scalar::random(rng);
    let z = Scalar::random(rng);
    let enc_u = encrypt_with_randomness(monitor_pk, &u, u_r);
    let ciphertext = Ciphertext {
        c1: z * acc.c1 + enc_u.c1,
        c2: z * acc.c2 + enc_u.c2,
    };

    let (pc_gens, bp_gens) = target_proof::default_gens(encoded_x.len());
    let proof = target_proof::prove(
        rng,
        &pc_gens,
        &bp_gens,
        monitor_pk,
        &ciphertext,
        encrypted_y,
        encoded_x,
        &bit_randomness,
        z,
        u,
        u_r,
    )?;

    Ok((ciphertext, WireTargetHybridProof::from_native(&proof)))
}

fn encrypt_with_randomness(pk: &PublicKey, msg: &Scalar, r: Scalar) -> Ciphertext {
    Ciphertext {
        c1: &r * &RISTRETTO_BASEPOINT_TABLE,
        c2: msg * &RISTRETTO_BASEPOINT_TABLE + r * pk.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{
        ct_add, ct_scalar_mul, eval_poly, generate_key_share, partial_decrypt_with_witness,
        poly_scalar_mul,
    };
    use crate::fuzzy::proof;
    use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_TABLE;

    fn non_zero_scalar(rng: &mut OsRng) -> Scalar {
        loop {
            let s = Scalar::random(rng);
            if s != Scalar::zero() {
                return s;
            }
        }
    }

    fn encrypt_with_randomness(pk: &PublicKey, msg: &Scalar, r: Scalar) -> Ciphertext {
        Ciphertext {
            c1: &r * &RISTRETTO_BASEPOINT_TABLE,
            c2: msg * &RISTRETTO_BASEPOINT_TABLE + r * pk.0,
        }
    }

    fn mask_eval(pk: &PublicKey, eval_ct: Ciphertext, mask: Scalar) -> Ciphertext {
        let scaled_no_blind = ct_scalar_mul(&eval_ct, &mask);
        let enc_zero_mask = Ciphertext {
            c1: &mask * &RISTRETTO_BASEPOINT_TABLE,
            c2: mask * pk.0,
        };
        ct_add(&scaled_no_blind, &enc_zero_mask)
    }

    #[test]
    fn test_process_round_accepts_message() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let (_monitor_sk, monitor_pk_share) = generate_key_share(&mut rng);
        let monitor_pk = PublicKey(monitor_pk_share.0);
        let mut target = Target::new(
            vec![Scalar::from(11u64), Scalar::from(13u64)],
            5,
            sk1,
            pk1.clone(),
            pk2,
            monitor_pk,
            12,
        );
        let accum_ct = target.build_accum_ctext(&mut rng);
        let m = Scalar::from(7u64);
        let next_accum = poly_scalar_mul(&accum_ct, &m);
        let accum_eval_joint = eval_poly(&accum_ct, &m);
        let accum_mask = non_zero_scalar(&mut rng);
        let accum_scaled_eval = mask_eval(&target.pk, accum_eval_joint, accum_mask);
        let (accum_eval, accum_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &accum_scaled_eval);
        let input_bits = encode_scalar_bits(&m, 12);
        let (encrypted_input_bits_native, input_bit_randomness): (Vec<_>, Vec<_>) = input_bits
            .iter()
            .map(|bit| {
                let r = Scalar::random(&mut rng);
                (encrypt_with_randomness(&monitor_pk, bit, r), r)
            })
            .unzip();
        let proof = proof::prove_round(
            &mut rng,
            &monitor_pk,
            &target.pk,
            &target.pk1,
            &target.pk2,
            &accum_ct,
            &next_accum,
            &accum_scaled_eval,
            &accum_eval,
            m,
            &input_bits,
            &input_bit_randomness,
            accum_mask,
            accum_r_prime,
            &sk2,
            &encrypted_input_bits_native,
        )
        .unwrap();
        let msg = MonitorToTarget {
            next_accum: WireEncryptedPoly::from_native(&next_accum),
            accum_eval: WireCiphertext::from_native(&accum_eval),
            encrypted_input_bits: encrypted_input_bits_native
                .iter()
                .map(WireCiphertext::from_native)
                .collect(),
            proof,
        };

        let (next_accum_out, masked_distances, masked_distance_proofs) =
            target.process_round(&mut rng, &accum_ct, &msg).unwrap();
        assert_eq!(next_accum_out.0.len(), accum_ct.0.len());
        assert_eq!(masked_distances.len(), 2);
        assert_eq!(masked_distance_proofs.len(), 2);
    }

    #[test]
    fn test_process_round_rejects_zero_accum_eval() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let (_monitor_sk, monitor_pk_share) = generate_key_share(&mut rng);
        let monitor_pk = PublicKey(monitor_pk_share.0);
        let mut target = Target::new(vec![Scalar::from(11u64)], 5, sk1, pk1.clone(), pk2, monitor_pk, 8);
        let zero_accum = EncryptedPoly(vec![
            encrypt_zero(&mut rng, &target.pk),
            encrypt_zero(&mut rng, &target.pk),
            encrypt_zero(&mut rng, &target.pk),
        ]);
        let next_accum = zero_accum.clone();
        let m = Scalar::from(3u64);
        let zero_eval_joint = eval_poly(&zero_accum, &m);
        let accum_mask = non_zero_scalar(&mut rng);
        let accum_scaled_eval = mask_eval(&target.pk, zero_eval_joint, accum_mask);
        let (zero_eval, accum_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &accum_scaled_eval);
        let input_bits = encode_scalar_bits(&m, 8);
        let (encrypted_input_bits_native, input_bit_randomness): (Vec<_>, Vec<_>) = input_bits
            .iter()
            .map(|bit| {
                let r = Scalar::random(&mut rng);
                (encrypt_with_randomness(&monitor_pk, bit, r), r)
            })
            .unzip();
        let proof = proof::prove_round(
            &mut rng,
            &monitor_pk,
            &target.pk,
            &target.pk1,
            &target.pk2,
            &zero_accum,
            &next_accum,
            &accum_scaled_eval,
            &zero_eval,
            m,
            &input_bits,
            &input_bit_randomness,
            accum_mask,
            accum_r_prime,
            &sk2,
            &encrypted_input_bits_native,
        )
        .unwrap();
        let msg = MonitorToTarget {
            next_accum: WireEncryptedPoly::from_native(&next_accum),
            accum_eval: WireCiphertext::from_native(&zero_eval),
            encrypted_input_bits: encrypted_input_bits_native
                .iter()
                .map(WireCiphertext::from_native)
                .collect(),
            proof,
        };

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
        let (_monitor_sk, monitor_pk_share) = generate_key_share(&mut rng);
        let monitor_pk = PublicKey(monitor_pk_share.0);
        let t_set = vec![Scalar::from(5u64), Scalar::from(9u64), Scalar::from(12u64)];
        let target = Target::new(t_set.clone(), 5, sk1, pk1, pk2, monitor_pk, 10);

        assert_eq!(target._t_set.len(), t_set.len());
        assert_eq!(target._encoded_t_set.len(), t_set.len());
        assert_eq!(
            target._encoded_t_set[0],
            encode_scalar_bits(&Scalar::from(5u64), 10)
        );
    }
}
