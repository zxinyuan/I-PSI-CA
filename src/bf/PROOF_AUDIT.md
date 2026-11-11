# RLWE proof cost audit

The migrated protocol is not the old ElGamal Sigma-bullet proof plus a small
constant-cost adapter. Packing made native encryption cheap, but the chosen
privacy parameters and proof representation introduced large fixed witnesses.
A short PKC proof does not imply a small amount of prover work.

## Measurements and reproducible counts

Release audit, 20 Bloom hashes, production N=16,384, six 62-bit ciphertext
primes, three coordinates of one extension-field result:

| Quantity at 1,000 buckets | Before this audit | After optimizations |
| --- | ---: | ---: |
| Bulletproof multiplication gates, before deferred recurrence gates | 1,494,185 | 713,405 |
| Bulletproof generator capacity | 2,097,152 | 1,048,576 |
| PKC proofs | 9 | 3 |
| Separate complete-opening links | 9 | 3 |
| Total PKC bit-witness length | 39,620,787 | 13,339,119 |
| Individual shared Pedersen commitments | 448,399 | 448,399 |
| Shared-commitment payload | 14,348,768 bytes | 14,348,768 bytes |

At 100,000 buckets the gate counts are 1,494,199 -> 713,419 and PKC bit-witness
length is 107,634,027 -> 48,088,551. These are **circuit/witness counts**, not
measurements of complete interaction latency. Each linking argument also
processes its underlying PKC bit vector. No 2.5-second production round is
claimed for this implementation.

Source root construction plus fresh encryption took about 0.014 seconds at 1k
and 0.145 seconds at 100k in the optimized audit. Key generation is outside
those timers. Payload sizes are exact for the current serialization:

| Target polynomial | 1k buckets | 100k buckets |
| --- | ---: | ---: |
| Packed native RLWE ciphertext, including metadata | 1,523,804 bytes, 1 block | 10,666,316 bytes, 7 blocks |
| Raw ElGamal coefficient payload, without metadata | 64,064 bytes | 6,400,064 bytes |

The public RLWE context adds 762,000 bytes. Thus **the current RLWE target
ciphertext is larger**, including at 1k; packing reduces the number of objects,
not necessarily bytes. The large modulus gap comes from the selected 128-bit
statistical circuit-privacy transformation. A smaller encryption-only reference
profile cannot replace it without reestablishing the privacy and decoding bounds.

## Why the baseline is cheaper

The checked-in ElGamal baseline (`1f8b490:src/bf/proof.rs`) sets
`term_masks = positions.clone()`. It does not evaluate and prove the current
`HashToField(item, index)`. Its scalar arithmetic runs directly in the Ristretto
field, without non-native plaintext-field reduction or ciphertext noise/rounding
witnesses. At 1k and k=20, its evaluation gadget uses about 20,041 multiplication
gates, versus 713,405 in the optimized current arithmetic frontend.

That baseline also uses scalar-only accumulator multiplication and raw-item
evaluation, while the current relation proves root insertion and evaluation at
an encoding hash of the position list. Its CLI target construction encrypts the
polynomial rooted at *all* buckets rather than the selected marked set. These
are differences in the available historical code; they should not be attributed
to a separately measured revision without checking that revision.

The historical target's printed send-to-reply latency excludes target proof
verification, which it times separately. Compare monitor computation **and**
target verification when measuring a full interaction.

## Remaining costs

At 1k, the optimized arithmetic breakdown is:

| Component | Multiplication gates |
| --- | ---: |
| Item/index hashes and canonical hash reduction | 467,651 |
| Characteristic polynomial and canonical positions | 75,597 |
| Initial position powers | 76,000 |
| Extension mask and multiplication | 78,805 |
| Three initial-moment batches | 14,070 |
| Three recurrence boundary batches | 1,260 |
| Input bounds | 22 |

The three deferred recurrence identities add three gates later. The six fixed
hash rejection candidates are all proved, across twenty indices and three
coordinates. Arithmetic modulo the 55-bit plaintext prime is implemented inside
the different Ristretto scalar field.

The largest fixed PKC witness is the rounding residual: eight signed 32-bit
limbs for each of 16,384 c1 coefficients, or **4,194,304 bits per coordinate**.
This cost exists even when the source has only 1,001 coefficients. Small proof
size and faster native NTT arithmetic do not remove those elliptic-curve proof
operations. Individually committing all the shared inputs is another avoidable
representation cost, not a lower bound from PKC 2019.

## Implemented optimizations

- Amortize all six native moduli into one PKC statement per coordinate, with
  explicit integer-embedding bounds. Previously each CRT pair repeated most
  of the same bounded witness in another proof and linking argument.
- Reduce each initial evaluation dot product once, rather than reducing every
  product and partial sum separately.
- Remove the redundant canonical comparison on product quotients. Bounded
  inputs/result and the bounded integer equality already imply that comparison.
- Reuse multiplication-output wires when importing Arkworks constraints into
  Bulletproofs; do not allocate another witness and equality for each output.
  Pure linear equations do not receive multiplication gates.

The encryption, hash mapping, nonzero-mask constraints and privacy budget are
unchanged. Wire version 4 identifies the amortized proof format.

A substantially faster design still needs a more compact shared-witness
representation and a justified way to reduce the ring-sized rounding witness.
Removing the corresponding constraints without replacing their guarantees
would allow false ciphertext/commitment relations. In particular, private coins
and residuals must be bound **before** vector-projection challenges; merely
omitting their commitments would let the prover adapt to those challenges.

## Commands

```sh
# About twelve seconds locally: assembles circuits; does NOT generate full proofs.
cargo test --release audit_proof_costs -- --ignored --nocapture

# Full one-round production 1k latency, including report verification and update.
cargo test --release authenticated_production_1000_report -- --ignored --nocapture

# Full one-round production 100k latency.
cargo test --release authenticated_production_100k_report -- --ignored --nocapture
```

[PKC 2019](https://eprint.iacr.org/2019/057) provides short ciphertext/commitment
equality proofs and amortization. Its small proof payload is not a promise of
constant proving time for this much larger evaluated-ciphertext witness.

## Adaptive packing update

The fixed ring choice is now replaced by `PackingPlan::for_buckets`. It prefers
a single ciphertext at the smallest supported secure dimension (16k or 32k).
When splitting is necessary, it minimizes total padded coefficient slots and
then N, which governs the fixed coin/residual witness. See the packing table in
[RLWE.md](RLWE.md#adaptive-dimension-and-splitting).

The 1k and 100k measurements above still select N=16,384. They do not improve
from dimension selection alone: the current ~372-bit modulus is too large for
the smaller N=1,024--8,192 reference security limits. At 20k, the planner chooses
one N=32,768 ciphertext. This prioritizes the requested single-ciphertext form;
it is not a claim that the larger ring makes that proof faster.
