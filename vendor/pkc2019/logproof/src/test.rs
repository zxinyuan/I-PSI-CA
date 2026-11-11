use crate::{linear_algebra::Matrix, Bounds};
use sunscreen_math::{poly::Polynomial, ring::Ring};
/// All information for a problem of the form `AS = T` in `Z_q[X]/f`. Useful for
/// demonstrating full knowledge proofs for small testing polynomials.
pub struct LatticeProblem<Q>
where
    Q: Ring,
{
    /// Public A
    pub a: Matrix<Polynomial<Q>>,

    /// Private message and encryption components S
    pub s: Matrix<Polynomial<Q>>,

    /// Result of A * S
    pub t: Matrix<Polynomial<Q>>,

    /// Polynomial divisor
    pub f: Polynomial<Q>,

    /// Bounds on elements in S
    pub b: Matrix<Bounds>,
}
