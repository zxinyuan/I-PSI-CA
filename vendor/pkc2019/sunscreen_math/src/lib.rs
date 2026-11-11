#![deny(missing_docs)]
//! CPU arithmetic subset of Sunscreen math, adapted to curve25519-dalek-ng.
mod cpu;
/// Field traits.
pub mod field;
/// Polynomial arithmetic.
pub mod poly;
/// Finite-ring arithmetic.
pub mod ring;
pub use cpu::{CpuRistrettoPointVec, CpuScalarVec};
/// CPU point-vector backend.
pub type RistrettoPointVec = CpuRistrettoPointVec;
/// CPU scalar-vector backend.
pub type ScalarVec = CpuScalarVec;
mod error;
pub use error::*;
mod misc_traits;
pub use misc_traits::*;
pub use sunscreen_math_macros::{refify_binary_op, BarrettConfig};
