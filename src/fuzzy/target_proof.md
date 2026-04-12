# Bulletproof–Sigma Hybrid Proof Summary

## Problem Statement

Prove in zero-knowledge knowledge of secret values:
- bits: x_0, ..., x_n
- scalars: z, u

such that:

c = Enc( z * sum_{i=0}^n (x_i + m_i - 2 x_i m_i) + u )

Where:
- m_i ∈ {0,1} are public
- c is a public exponential ElGamal ciphertext

---

## Key Simplification

Since m_i are bits:

x_i + m_i - 2 x_i m_i = x_i ⊕ m_i

Define:
- y_i = x_i ⊕ m_i
- s = sum_i y_i

Then:

c = Enc(z * s + u)

---

## Proof Goal

Prove knowledge of:

(x_0, ..., x_n, s, z, u, t, r)

such that:

1. x_i ∈ {0,1}
2. s = sum_i (x_i ⊕ m_i)
3. t = z * s
4. c = Enc(t + u; r)

---

## Hybrid Approach

### 1. Bulletproof (Arithmetic Constraints)

Prove:
- Bitness: x_i(x_i - 1) = 0
- Linear relation:
  s = sum_{i: m_i=0} x_i + sum_{i: m_i=1} (1 - x_i)
- Multiplication:
  t = z * s

All values are committed using Pedersen commitments.

---

### 2. Sigma Protocol (ElGamal Consistency)

Prove:
- c = Enc(t + u; r)

This is a standard Schnorr / Chaum–Pedersen style proof linking:
- committed values t, u
- ciphertext c

---

## Why Hybrid?

- Bulletproof efficiently handles:
  - many bit constraints
  - linear relations
  - one multiplication

- Sigma proof efficiently handles:
  - algebraic consistency in ElGamal

---

## Optimization Insight

Instead of proving:

z * (x_i ⊕ m_i) for each i

We:
1. Aggregate first: s = sum_i (x_i ⊕ m_i)
2. Multiply once: t = z * s

This reduces cost significantly.

---

## Complexity (n ≤ 32)

Let N = n + 1 (number of bits)

### Estimated Costs

- Proof size: ~0.9–1.0 KB
- Prover time: ~1–4.5 ms
- Verifier time: ~0.25–0.7 ms

---

## Comparison

| Approach | Pros | Cons |
|----------|------|------|
| Pure Sigma | Simple algebra | Inefficient for hidden multiplication |
| Bulletproof only | Strong arithmetic support | Harder ElGamal linking |
| Hybrid (recommended) | Best balance | Slightly more complex |

---

## Key Takeaway

- Pure Σ-protocol is insufficient due to hidden multiplication (z * s)
- Hybrid approach is optimal:
  - Bulletproof → arithmetic constraints
  - Sigma → encryption consistency

---

## Notes

- Commitments to x_i are necessary for soundness
- Without commitments, individual x_i are not extractable
- The construction follows a "Σ-Bullet" paradigm similar to Zether-style designs
