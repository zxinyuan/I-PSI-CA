//! Fixed-capacity ElGamal polynomial accumulator used only by the BF protocol.
use crate::crypto::elgamal::{ct_scalar_mul, Ciphertext, EncryptedPoly};
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};

/// Full candidate (X-y)A, including its extra leading coefficient. The target
/// adopts it only when its fixed-capacity accumulator has room for a new root.
pub(crate) fn insert_candidate(a: &EncryptedPoly, y: Scalar) -> EncryptedPoly {
    EncryptedPoly(
        (0..=a.0.len())
            .map(|i| {
                let scaled =
                    a.0.get(i)
                        .map(|c| ct_scalar_mul(c, &y))
                        .unwrap_or(Ciphertext {
                            c1: RistrettoPoint::identity(),
                            c2: RistrettoPoint::identity(),
                        });
                let previous = i.checked_sub(1).map(|j| &a.0[j]);
                Ciphertext {
                    c1: previous.map_or(RistrettoPoint::identity(), |p| p.c1) - scaled.c1,
                    c2: previous.map_or(RistrettoPoint::identity(), |p| p.c2) - scaled.c2,
                }
            })
            .collect(),
    )
}

/// Rearrange next = XA-yA into yA = XA-next, so the existing Sigma
/// scalar-multiplication relation can prove the insertion without new primitives.
pub(crate) fn scale_component(
    a: &EncryptedPoly,
    next: &EncryptedPoly,
) -> Result<EncryptedPoly, String> {
    if a.0.is_empty() || a.0.len().checked_add(1) != Some(next.0.len()) {
        return Err("invalid accumulator update dimensions".into());
    }
    let leading = next.0.last().unwrap();
    let old_leading = a.0.last().unwrap();
    if leading.c1 != old_leading.c1 || leading.c2 != old_leading.c2 {
        return Err("invalid accumulator leading coefficient".into());
    }
    Ok(EncryptedPoly(
        next.0[..a.0.len()]
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let previous = i.checked_sub(1).map(|j| &a.0[j]);
                Ciphertext {
                    c1: previous.map_or(RistrettoPoint::identity(), |p| p.c1) - c.c1,
                    c2: previous.map_or(RistrettoPoint::identity(), |p| p.c2) - c.c2,
                }
            })
            .collect(),
    ))
}
