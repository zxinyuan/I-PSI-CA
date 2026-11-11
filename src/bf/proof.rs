//! Complete BF report proof: RLWE evaluation plus the linked ElGamal accumulator.
use super::{
    accumulator_proof::WireAccumulatorProof,
    evaluation_proof::WireEvaluationProof,
    target::{ReportBody, TargetToMonitor},
};
use crate::crypto::elgamal::PublicKeyShare;
use crate::crypto::{
    elgamal::{Ciphertext, EncryptedPoly},
    sigma::{self, PolyScalarMulProof},
};
use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::io::{self, Write};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundProof {
    pub evaluation: WireEvaluationProof,
    pub accumulator: WireAccumulatorProof,
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The signed statement excludes its authentication evidence. This also keeps
/// the evaluation transcript independent of which valid authentication nonce
/// was used. Bincode encodes this tuple exactly like the original round body.
pub(crate) fn target_statement(incoming: &TargetToMonitor) -> impl Serialize + '_ {
    (
        incoming.version,
        &incoming.session,
        incoming.round,
        incoming.bf_config,
        incoming.accum_degree,
        &incoming.rlwe_context,
        &incoming.t_poly_ct,
        &incoming.accum,
    )
}

fn authentication_relation(
    incoming: &TargetToMonitor,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
) -> Result<(EncryptedPoly, EncryptedPoly), String> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(b"i-psi-ca/bf/target-key-authentication/v1");
    bincode::serialize_into(
        &mut writer,
        &(
            target_statement(incoming),
            pk1.0.compress().to_bytes(),
            pk2.0.compress().to_bytes(),
        ),
    )
    .map_err(|e| e.to_string())?;
    let h = Scalar::from_bytes_mod_order_wide(&Sha512::digest(writer.0.finalize()).into());
    if h == Scalar::zero() {
        return Err("degenerate target authentication challenge".into());
    }
    Ok((
        EncryptedPoly(vec![Ciphertext {
            c1: h * RISTRETTO_BASEPOINT_POINT,
            c2: RISTRETTO_BASEPOINT_POINT,
        }]),
        EncryptedPoly(vec![Ciphertext {
            c1: h * pk1.0,
            c2: pk1.0,
        }]),
    ))
}

pub(crate) fn authenticate_target<R: RngCore + CryptoRng>(
    rng: &mut R,
    incoming: &TargetToMonitor,
    sk1: &Scalar,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
) -> Result<PolyScalarMulProof, String> {
    let (input, output) = authentication_relation(incoming, pk1, pk2)?;
    Ok(sigma::prove_poly_scalar_mul(
        rng, sk1, &input, &output, &pk1.0,
    ))
}
pub(crate) fn verify_target(
    incoming: &TargetToMonitor,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
) -> Result<(), String> {
    let proof = incoming
        .authentication
        .as_ref()
        .ok_or("missing target key authentication")?;
    let (input, output) = authentication_relation(incoming, pk1, pk2)?;
    sigma::verify_poly_scalar_mul(proof, &input, &output, &pk1.0)
        .map_err(|e| format!("target key authentication: {e}"))
}

/// Hash the entire public round statement with unambiguous bincode lengths.
/// Both proof components receive this identical context; no witness is hashed.
pub(crate) fn context(
    incoming: &TargetToMonitor,
    report: &ReportBody,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
) -> Result<[u8; 32], String> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(b"i-psi-ca/bf/complete-rlwe-round/v4");
    bincode::serialize_into(
        &mut writer,
        &(
            target_statement(incoming),
            report,
            pk1.0.compress().to_bytes(),
            pk2.0.compress().to_bytes(),
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(writer.0.finalize().into())
}
