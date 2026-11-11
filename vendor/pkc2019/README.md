# PKC 2019 proof dependency

CPU-only adaptation of Sunscreen's `logproof`, `sunscreen_math` and
`sunscreen_math_macros`, pinned to upstream commit
`f8ee4a0dc32418f2acd9e176c6f0af73cdf68d40` (version 0.8.1).
Source: https://github.com/Sunscreen-tech/Sunscreen

The copied code is licensed AGPL-3.0-only; see LICENSE. The user explicitly
authorized this dependency/adaptation. This notice does not change the license
of independently authored repository code.

Adaptations: alias the curve backend to the repository's curve25519-dalek-ng 4;
retain CPU arithmetic, generic ring relations, generators and the existing ZK
inner-product proof; exclude GPU, SEAL and unrelated statistics modules;
replace workspace manifests with explicit dependency manifests. Upstream generic
proof tests are retained. No new inner-product argument is implemented.

The `bulletproofs` directory is the existing MIT-licensed version 4.0.0,
with three API-only extensions: read the complete first-phase input commitment,
read its sensitive input-wire opening, and supply a uniformly sampled input
blinding scalar. Generator iterators are public. Its proof equations and wire
format are unchanged. The application does not rely on upstream's partial
`w_shared` / `A_I1_shared` commitments for cross-proof consistency.

The active BF path now calls LogProof for native RNS-pair linear relations.
Numeric Pedersen openings are linked through the existing ZK inner-product
argument and the complete `w` commitment. The earlier full-Bulletproof-wire link
remains a regression-tested reference. A malformed recursive proof's folding
length is checked before a machine-word shift, so oversized lengths reject
instead of panicking.

Memory-only adaptations consume padded IPA vectors during folding and avoid
copying the full H generator family when no partial shares are requested.
These preserve the proof equations, transcript, randomness and wire format.
The active numeric bridge also omits a redundant prover-side bit-vector MSM;
the complete common-opening equation is checked by the verifier.
