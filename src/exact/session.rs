//! Transport-independent adapter for the unchanged exact proof operations.
//!
//! A shared set uses one threshold key. Its monitor share belongs to a trusted
//! client group, never the target. Every update carries the original division
//! proof so a different monitor can verify the entire intervening history.
use super::{division, proofs, target::EncodedPoly, target::WireEncryptedPoly, TPolyProof};
use crate::crypto::elgamal::{self, PublicKey, PublicKeyShare, SecretKeyShare};
use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar, traits::Identity};
use rand::{rngs::OsRng, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
pub struct InitialState {
    pub target_key: [u8; 32],
    pub monitor_key: [u8; 32],
    pub context: [u8; 32],
    pub ciphertext: WireEncryptedPoly,
    pub proof: TPolyProof,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Update {
    pub version: u64,
    pub context: [u8; 32],
    pub report: Vec<u8>,
    pub ciphertext: WireEncryptedPoly,
    pub proof: TPolyProof,
}

struct Keys {
    sk: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
}

/// Immutable snapshots make computation transactional: only the caller commits
/// the returned state, after all proofs have been generated successfully.
pub struct TargetState {
    keys: Arc<Keys>,
    current: EncodedPoly,
    pub version: u64,
    pub distinct_matches: u64,
}

fn key(bytes: [u8; 32]) -> Result<PublicKeyShare, String> {
    let point = CompressedRistretto(bytes)
        .decompress()
        .ok_or("invalid key")?;
    if point == curve25519_dalek_ng::ristretto::RistrettoPoint::identity() {
        return Err("identity key".into());
    }
    Ok(PublicKeyShare(point))
}

/// Deterministic *synthetic* inputs, not cryptographic randomness. Root zero is
/// common across sets to exercise independent histories for the same item.
pub fn synthetic_item(seed: u64, set: usize, index: u64, member: bool) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"exact-benchmark-input-v1");
    h.update(seed.to_le_bytes());
    h.update((if index == 0 { 0 } else { set } as u64).to_le_bytes());
    h.update(index.to_le_bytes());
    h.update([u8::from(member)]);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// Domain-separated per-set key shares from a secret, randomly generated file.
/// The public benchmark seed MUST NOT be used as this secret.
pub fn monitor_key(secret: &[u8; 32], set: usize) -> (SecretKeyShare, PublicKeyShare) {
    let mut h = Sha256::new();
    h.update(b"exact-benchmark-monitor-key-v1");
    h.update(secret);
    h.update((set as u64).to_le_bytes());
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(h.finalize().into());
    elgamal::generate_key_share(&mut rng)
}

pub fn request_context(epoch: &[u8; 32], session: &[u8; 32], seq: u64, version: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"exact-benchmark-request-v1");
    h.update(epoch);
    h.update(session);
    h.update(seq.to_le_bytes());
    h.update(version.to_le_bytes());
    h.finalize().into()
}

impl TargetState {
    pub fn initialize(
        roots: &[Scalar],
        monitor_public: [u8; 32],
        context: [u8; 32],
    ) -> Result<(Self, InitialState), String> {
        if roots.is_empty() || roots.len() >= super::MAX_COEFFICIENTS {
            return Err("invalid set size".into());
        }
        let mut rng = OsRng;
        let (sk, pk1) = elgamal::generate_key_share(&mut rng);
        let pk2 = key(monitor_public)?;
        let pk = elgamal::combine_public_keys(&pk1, &pk2);
        let (current, proof) = proofs::encrypt_and_prove_initial(
            &mut rng,
            &pk,
            roots,
            &proofs::ProofContext {
                session: context,
                round: 1,
            },
        )?;
        let initial = InitialState {
            target_key: pk1.0.compress().to_bytes(),
            monitor_key: monitor_public,
            context,
            ciphertext: current.wire().clone(),
            proof: TPolyProof::Initial(proof),
        };
        Ok((
            Self {
                keys: Arc::new(Keys { sk, pk1, pk2, pk }),
                current,
                version: 0,
                distinct_matches: 0,
            },
            initial,
        ))
    }

    pub fn propose(
        &self,
        report: Vec<u8>,
        context: [u8; 32],
    ) -> Result<(Self, Update, bool), String> {
        use bincode::Options;
        let reply: division::DivisionReply = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(report.len() as u64)
            .reject_trailing_bytes()
            .deserialize(&report)
            .map_err(|e| e.to_string())?;
        let ctx = proofs::ProofContext {
            session: context,
            round: self.version + 1,
        };
        let (next, partial) = division::verify_encoded(
            &self.keys.pk,
            &self.keys.pk1,
            &self.keys.pk2,
            &self.current,
            &reply,
            &ctx,
        )?;
        let matched = elgamal::test_zero(&self.keys.sk, &partial);
        let source = if matched { &next } else { &self.current };
        let (updated, witness) = super::encryption::rerandomize_poly_with_witness(
            &mut OsRng,
            &self.keys.pk,
            source.native(),
        );
        let updated = EncodedPoly::from_native(updated);
        let proof = proofs::prove_rerandomization_or_encoded(
            &mut OsRng,
            &self.keys.pk,
            &self.current,
            &next,
            &updated,
            usize::from(matched),
            &witness,
            &proofs::ProofContext {
                session: context,
                round: ctx.round + 1,
            },
        )?;
        let update = Update {
            version: self.version + 1,
            context,
            report,
            ciphertext: updated.wire().clone(),
            proof: TPolyProof::RerandomizationOr(proof),
        };
        Ok((
            Self {
                keys: Arc::clone(&self.keys),
                current: updated,
                version: update.version,
                distinct_matches: self.distinct_matches + u64::from(matched),
            },
            update,
            matched,
        ))
    }
}

pub struct MonitorState {
    sk: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    current: EncodedPoly,
    pub version: u64,
}

impl MonitorState {
    pub fn deploy(secret: &[u8; 32], set: usize, initial: &InitialState) -> Result<Self, String> {
        let (sk, pk2) = monitor_key(secret, set);
        if pk2.0.compress().to_bytes() != initial.monitor_key {
            return Err("monitor group key mismatch".into());
        }
        let pk1 = key(initial.target_key)?;
        let pk = elgamal::combine_public_keys(&pk1, &pk2);
        let current = EncodedPoly::from_wire(initial.ciphertext.clone())?;
        match &initial.proof {
            TPolyProof::Initial(p) => proofs::verify_initial_pok_encoded(
                &pk,
                &current,
                p,
                &proofs::ProofContext {
                    session: initial.context,
                    round: 1,
                },
            )?,
            _ => return Err("expected deployment proof".into()),
        }
        Ok(Self {
            sk,
            pk1,
            pk2,
            pk,
            current,
            version: 0,
        })
    }

    pub fn report(&self, item: Scalar, context: [u8; 32]) -> Result<Vec<u8>, String> {
        let (reply, _) = division::prove_with_candidate_started_at(
            &mut OsRng,
            &self.pk,
            &self.pk1,
            &self.pk2,
            &self.sk,
            &self.current,
            item,
            &proofs::ProofContext {
                session: context,
                round: self.version + 1,
            },
            super::measurements::unix_ns().map_err(|e| e.to_string())?,
        )?;
        bincode::serialize(&reply).map_err(|e| e.to_string())
    }

    pub fn apply(&mut self, update: &Update) -> Result<(), String> {
        use bincode::Options;
        if update.version != self.version + 1 {
            return Err("nonconsecutive update".into());
        }
        let reply: division::DivisionReply = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(update.report.len() as u64)
            .reject_trailing_bytes()
            .deserialize(&update.report)
            .map_err(|e| e.to_string())?;
        let (next, _) = division::verify_encoded(
            &self.pk,
            &self.pk1,
            &self.pk2,
            &self.current,
            &reply,
            &proofs::ProofContext {
                session: update.context,
                round: update.version,
            },
        )?;
        let updated = EncodedPoly::from_wire(update.ciphertext.clone())?;
        match &update.proof {
            TPolyProof::RerandomizationOr(p) => proofs::verify_rerandomization_or_encoded(
                &self.pk,
                &self.current,
                &next,
                &updated,
                p,
                &proofs::ProofContext {
                    session: update.context,
                    round: update.version + 1,
                },
            )?,
            _ => return Err("expected reporting proof".into()),
        }
        self.current = updated;
        self.version = update.version;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_set_removes_once_and_other_set_is_independent() {
        let secret = [71; 32];
        let (_, pk) = monitor_key(&secret, 0);
        let roots = vec![Scalar::from(7u64), Scalar::from(42u64)];
        let (mut target, initial) =
            TargetState::initialize(&roots, pk.0.compress().to_bytes(), [1; 32]).unwrap();
        let mut a = MonitorState::deploy(&secret, 0, &initial).unwrap();
        let mut b = MonitorState::deploy(&secret, 0, &initial).unwrap();
        for (i, which) in [0, 1, 0, 1].into_iter().enumerate() {
            let context = request_context(&[1; 32], &[which + 2; 32], i as u64, target.version);
            let monitor = if which == 0 { &mut a } else { &mut b };
            if i > 0 {
                assert_eq!(monitor.version, target.version);
            }
            let packet = monitor.report(Scalar::from(7u64), context).unwrap();
            let (next, update, matched) = target.propose(packet, context).unwrap();
            assert_eq!(matched, i == 0);
            a.apply(&update).unwrap();
            b.apply(&update).unwrap();
            target = next;
        }
        assert_eq!(target.distinct_matches, 1);
        let (other, initial) =
            TargetState::initialize(&roots, pk.0.compress().to_bytes(), [9; 32]).unwrap();
        let monitor = MonitorState::deploy(&secret, 0, &initial).unwrap();
        let report = monitor.report(Scalar::from(7u64), [3; 32]).unwrap();
        assert!(other.propose(report, [3; 32]).unwrap().2);
    }
    #[test]
    fn tampering_wrong_context_and_out_of_order_updates_do_not_advance_state() {
        let secret = [72; 32];
        let (_, pk) = monitor_key(&secret, 0);
        let (target, initial) =
            TargetState::initialize(&[Scalar::one()], pk.0.compress().to_bytes(), [1; 32]).unwrap();
        let mut monitor = MonitorState::deploy(&secret, 0, &initial).unwrap();
        let report = monitor.report(Scalar::one(), [2; 32]).unwrap();
        assert!(target.propose(report.clone(), [3; 32]).is_err());
        assert_eq!(target.version, 0);
        assert_eq!(target.distinct_matches, 0);
        let (_, update, _) = target.propose(report, [2; 32]).unwrap();
        let mut bad = update.clone();
        bad.ciphertext.0[0].c1 = [255; 32];
        assert!(monitor.apply(&bad).is_err());
        assert_eq!(monitor.version, 0);
        monitor.apply(&update).unwrap();
        assert!(monitor.apply(&update).is_err());
        assert!(MonitorState::deploy(&[99; 32], 0, &initial).is_err());
    }
}
