# BF protocol: packed RLWE target, ElGamal accumulator

The BF network protocol now uses native `fhe` 0.1.0 BFV/RLWE encryption for
`TPolyCtext` and its evaluated result. The target owns the only RLWE secret key;
the monitor imports the public key and parameters. The accumulator retains its
separate, two-share Ristretto ElGamal keys. Accepted reports require both the
complete PKC/Bulletproof RLWE evaluation proof and the linked ElGamal accumulator proof.
There is no unchecked RLWE report path.

The historical feature name is `experimental-rlwe`; it is **enabled by default**.
Rust 1.88 or later is required by the native dependencies. BF round wire version
4 binds the item/index hash, hashed accumulator root and amortized PKC bridge; native key/ciphertext format 4
retains the base-field packing representation. Exact-only builds can
use `--no-default-features`; BF is unavailable in those builds. Neither protocol
needs Go at runtime.

## Parameters, representation and ciphertext size

`PackingPlan::for_buckets(m)` selects the production dimension from supported
secure profiles. BF supports up to **100,000 buckets** and 64 Bloom hashes,
subject to the existing positive bounded-input domain. `Protocol100k` retains
the N=16,384 profile; `ProtocolSized` supplies the N=32,768 profile.

| Parameter | Value |
| --- | --- |
| Ring | Z_Q[X]/(X^N+1), N selected from 16,384 and 32,768 |
| Plaintext prime t | 36,028,796,991,700,993 (55 bits) |
| Ciphertext modulus Q | Six 62-bit NTT primes compatible with the selected N |
| Final ciphertext modulus q | Product of the first two primes (about 124 bits) |
| Terminal divisor D=Q/q | Product of the other four primes (about 248 bits) |
| Error/secret distribution | Native centered binomial, variance 10, support [-20,20] |
| Logical result | One F_(t^3) value encoded in three native coordinates |
| Transport limits | 128 MiB per framed message; strict bounded decoding |

For m buckets, the target constructs `P(Z)=product_(marked i)(Z-i)` directly in
F_t, then pads to **m+1 coefficients regardless of target density**. Consecutive
coefficients occupy the power basis of each RLWE plaintext, exactly as in the
Go packing reference; these are not batching slots. The final block has zero
padding. At 100,000 buckets, 100,001 coefficients occupy **7 ciphertexts**.
Ciphertext size depends on bucket count, not accumulator capacity or number of
marked positions. Root construction uses the native NTT through a product tree.
Ristretto polynomial coefficients are never reduced into F_t.

### Adaptive dimension and splitting

The planner counts **m+1 coefficients**, including the leading coefficient.
It chooses the smallest admissible ring that holds the entire polynomial in one
ciphertext. If no supported ring can hold it, it minimizes total padded
coefficient slots; ties prefer smaller N because private coins and rounding
proof work grow with the ring dimension. Fewer ciphertext objects alone is not
the optimization objective in this split case.

| Buckets m | Coefficients | Selected N | Ciphertexts |
| --- | ---: | ---: | ---: |
| 1,000 | 1,001 | 16,384 | 1 |
| 16,383 | 16,384 | 16,384 | 1 |
| 16,384 | 16,385 | 32,768 | 1 |
| 20,000 | 20,001 | 32,768 | 1 |
| 32,767 | 32,768 | 32,768 | 1 |
| 32,768 | 32,769 | 16,384 | 3 |
| 50,000 | 50,001 | 16,384 | 4 |
| 100,000 | 100,001 | 16,384 | 7 |

For example, 100k at N=32,768 needs four blocks/131,072 coefficient slots;
N=16,384 needs seven blocks/114,688 slots and a smaller proof witness. At 50k,
both choices use 65,536 slots, so the smaller ring wins the proof-cost tie.
The single-ciphertext preference can therefore make N nonmonotonic in m.

**Why not N=1,024 for 1,000 buckets?** Capacity permits it, but the current
ciphertext modulus has about 372 bits. The classical 128-bit modulus-size
screening limits are 27, 54, 109, 218, 438 and 881 bits for N=1,024 through
32,768, respectively. N=16,384 is the first admissible dimension for this
modulus. See the [SEAL reference policy](https://github.com/microsoft/SEAL/blob/main/native/src/seal/util/hestdparms.h)
and [HE security guidelines](https://eprint.iacr.org/2024/463). These tables are
parameter-screening guidelines, not a security certificate for this prototype.
The circuit-privacy and decoding budgets are checked independently. Simply
retaining this modulus while shrinking N would not preserve the security target.

The current supported maximum is N=32,768: a six-prime source ciphertext fits
the existing 4 MiB per-ciphertext transport bound, and the public-adjoint
implementation supports that dimension. N=65,536 exceeds that transport bound
and requires separate proof/resource validation. This cap is an implementation
policy, not a mathematical upper limit for RLWE.

The 16k prime chain remains unchanged for compatibility. The 32k chain is
regenerated with the correct 2N-th roots; primes suitable for 16k cannot just
be reused at a larger degree. Context import verifies the exact selected chain,
and the monitor/proof verifier checks N against the authenticated Bloom config.

The public context carries the exact parameters and public key, with a version
and fingerprint. The protocol needs no automorphism, relinearization or
key-switch keys. Import checks exact permitted profiles, canonical key encoding,
component counts, levels and packing dimensions. The RLWE secret wrapper has no
serialization or Debug implementation. The monitor verifies the existing Sigma scalar-multiplication proof under its
configured target ElGamal public share before using an incoming round. Its
message-derived group statement authenticates the full RLWE key/context, source
ciphertexts, accumulator, configuration, session and round. This prevents a
network attacker from substituting its own RLWE key. Authentication evidence
is excluded from the evaluation transcript; the authenticated semantic fields
are all included. This authenticates the configured target's statement, not honest RLWE setup.

Every round uses a fresh public-key
encryption of the retained target polynomial; source noise never accumulates.

Reference helpers retain the old Go-compatible and wide trace-based profiles.
Their result wire types differ from the protocol's extracted result. In tests
only, `ProofTest` uses N=16 with the same plaintext/ciphertext primes and the
same complete proof equations. It tests proof logic, not lattice security, and
production context import cannot select it.

## Evaluated relation and hash encoding

The existing Bloom positions remain `p_j=(j+1)*y+j`, with
`1 <= y <= floor((m-k+1)/k)`. These are distinct, strictly increasing positions
in 1..=m. The logical plaintext field is the cubic extension
`K=F_t[u]/(u^3-5)`. Here 5 is a cubic non-residue; native extension arithmetic
reuses Arkworks `Fp3`. P has coefficients in the base field F_t, embedded in K.
The encrypted logical scalar is exactly

```text
M = r * sum_(i in I_y) HashToField(y, i) * P(i)  in K
```

Each hash has three independently domain-separated base-field coordinates.
The mask r is uniform over K*, sampled as a canonical triple with the all-zero
triple rejected. The three native ciphertext results encode **one** K element;
the membership check requires all three decrypted coordinates to be zero.
Multiplication by uniform r maps every nonzero sum uniformly onto K*. Thus even
the pattern of zero coordinates reveals no additional input information.
Independent masks on three separate sums would preserve that pattern and are
not used by the accepted protocol.

For a nonzero P evaluation vector, the random-oracle cancellation probability
is `1/|K| = t^-3`, approximately 2^-165 per fixed query. This bound is separate
from Bloom false positives and from adversarial query/grinding budgets.

The weights hash the **item and bucket index**, as in the requested predicate.
The sponge operates over the Ristretto scalar field, with width 4, rate 2,
capacity 2, exponent 5, 8 full and 60 partial rounds. Parameters and constraints
come from Arkworks. The prefix is `[domain, t, m, k, y]`, where domain is SHA-512
of `i-psi-ca/bf/poseidon-item-index-weight/v4`, reduced into that field. Each
candidate continues a copy of this sponge with `[coordinate, i, retry]`, then
squeezes 8 bytes interpreted as LE64. Accept the first candidate below
`u64::MAX - u64::MAX % t` and reduce modulo t. Six candidates are constrained
with a fixed proof shape; exhaustion rejects. There is no biased fallback.

The user-selected accumulator encoding is a separate domain-separated Poseidon
hash into the Ristretto scalar field:

```text
z = Poseidon([encoding_domain, m, k, p_0, ..., p_(k-1)])
encoding_domain = SHA512("i-psi-ca/bf/bloom-set-to-scalar/v1") mod l
```

It squeezes one field element directly. Bulletproof arithmetic proves this exact
encoding from the same private item and affine positions. The sparse sorted
position list completely determines the monitor Bloom filter. There is no
separate m-bit vector, population-count check or bit-vector fingerprint in the
accepted proof. The positive input bounds remain necessary for the existing
nonwrapping affine position functions; arbitrary field elements are still not
supported as inputs by those functions.

## Homomorphic evaluation and scalar extraction

Let `E_j=r*sum_i(h_i*p_i^j)` in K. The proof constrains the common nonzero
extension mask and the full extension multiplication for every hash. For each
base-field coordinate c, let E_(j,c) be that coefficient in F_t. For a source
block beginning at global degree d, multiply it by the signed plaintext
polynomial

```text
W[0]   = centered(E_(d,c))
W[N-j] = -centered(E_(d+j,c)),  1 <= j < populated block length
```

Negacyclic convolution makes the product's constant coefficient the desired
dot product. Powers continue across blocks. Sum the block products, add a
fresh encryption of zero, and perform one exact componentwise `floor(c/D)`.
All operations reuse native ring arithmetic and public-key encryption equations.

Only the constant coefficient of the resulting c0 and the full c1 polynomial
are transported, in the two retained RNS primes. This is scalar RLWE-to-LWE
coefficient extraction under the **same secret**. The target reconstructs c0
with zero nonconstant coefficients and uses native decryption to read only
coefficient zero. The other decoded coefficients are irrelevant. Sending all
of c0 would expose unintended plaintext coefficients; the wire type cannot do
that. There is no hidden trace or automorphism computation to leave unproved.

## Complete evaluation proof

`pkc_evaluation.rs` invokes the adapted Sunscreen implementation of
[Short Discrete Log Proofs for FHE and Ring-LWE Ciphertexts (PKC 2019)](https://www.iacr.org/archive/pkc2019/114420236/114420236.pdf).
Bulletproof R1CS handles generic arithmetic constraints; Arkworks supplies those
constraints over the identical Ristretto scalar field, without another proving
backend.

The statement binds parameters, public keys, source/output ciphertexts, Bloom
configuration, session, round, current accumulator, root-insertion candidate and
partial decryption. Both components use the **same blinded Pedersen item
commitment** `C_y=yG+gamma*H`.

The components are:

1. **Bulletproof arithmetic:** affine positions; item/index Poseidon weights;
   canonical hash reduction; one nonzero extension-field mask and its complete
   multiplication; and all evaluation coefficients. The first k values are
   computed directly. `C(Z)=product_i(1-p_i Z)` determines the remaining sequence
   through a bounded integer recurrence and a randomized polynomial identity,
   including constrained low/high boundaries.
2. **Amortized PKC linear relations:** all six native ciphertext primes are
   checked together, once per result coordinate: **three PKC proofs** total.
   Three independent random-vector projections check c1 in each native prime;
   the c0 constant relation is checked directly. Every projected equation has
   one signed scalar quotient, represented by 64+16-bit limbs inside PKC. They
   are not extra Pedersen inputs or per-coefficient quotient arrays.
   The 24 equations per coordinate are embedded in a fixed ~160-bit auxiliary
   ring. Runtime norm checks establish both that the native integer equation
   fits below half the auxiliary modulus and that PKC's integer lift fits below
   half the Ristretto modulus. Consequently auxiliary modular equality implies
   the required exact integer equality, hence equality in each native prime.
   The auxiliary modulus does not change the encryption parameters.
   Projection challenges follow all shared commitments and the arithmetic
   proof, so the private coefficients cannot adapt to the projections.
3. **Complete-commitment links:** three zero-knowledge inner-product arguments
   prove that PKC's bounded signed coefficients open the same Pedersen inputs
   used by Bulletproofs. They bind the complete proof-checked `w`, including
   quotient/lift-factor bits. The unauthenticated auxiliary `w_shared` field is
   never used as evidence of equality. Numeric inputs are linked directly;
   PKC bit variables are not duplicated as Bulletproof Boolean gates.
4. **ElGamal proof:** a second Bulletproof computes the hashed position encoding
   z and masked powers from the common item commitment. Linked Sigma equations
   prove `(X-z)A`, masked evaluation at z, possession of the monitor's key share,
   and correctly rerandomized partial decryption.

### Removed checks and necessary bounds

There are **no separate Bulletproof range arguments**, per-coefficient RNS
quotient witnesses, remainder/slack comparison proofs, or full Bloom-vector
checks in the active proof. `proof_values.rs` only stores blinded numeric inputs.
PKC's intrinsic signed coefficient bounds remain part of the ring relation:
weights use 56 bits, recurrence quotients 61 bits, coins 8 bits, and residual
limbs 32 bits. Canonical field-representation constraints and nonzero-mask checks
remain necessary for soundness.

The honest evaluator still adds fresh Enc(0) and performs the exact floor
sanitizer. The proof only needs to establish the requested plaintext relation,
so it absorbs fresh errors into bounded residuals and proves

```text
sum_b source_c1[b]*W[b] + pk_c1*u - R_a = D*output_a mod Q
constant(sum_b source_c0[b]*W[b] + pk_c0*u) - R_b = D*output_b mod Q
```

Each R is an eight-limb balanced signed base-2^32 integer. Honest witnesses encode
`floor_remainder - fresh_error`. The prover need not establish that R lies in
`[0,D)`: that would prove the implementation's particular floor rather than the
plaintext relationship. `validate_decode_bound` checks that **every** allowed
residual and coin still yields the claimed decoded plaintext under honestly
bounded target keys and fresh sources. This relaxation does not change the
honest circuit-privacy transformation or its privacy assumptions.

The auxiliary modulus is about 160 bits. Native coefficients are below 2^62;
shared witnesses have at most 61 signed bits, and each projected quotient uses
64+16 bits. `embedding_checks` proves the necessary integer bounds from the
actual statement rather than assuming that embedding a modular equation is
sound. A false c1 vector in
either prime survives three independent projections with probability at most
`q_i^-3` (plus negligible challenge-reduction bias). The coefficient recurrence
contributes at most `(m+1+k)/l` per coordinate. These errors are separate from
Bloom false positives, hash cancellation and the underlying arguments' security.

## Circuit privacy and assumptions

The implemented approach follows the rerandomize-and-terminal-floor method in
[Fast Vector Oblivious Linear Evaluation from Ring Learning with Errors,
section 3](https://eprint.iacr.org/2020/685.pdf). Fresh zero encryption removes
circuit-dependent public-component structure; the large terminal modulus gap
hides the bounded evaluated error. Merely adding an ordinary encryption of zero
without this final step would not establish circuit privacy.

`circuit_privacy.rs` checks conservative, exact worst-case noise bounds, not
sampled noise measurements. Its union bound includes all ring coefficients and
three coordinates at a 128-bit statistical budget; it separately checks final
correct decoding. Coefficient extraction keeps only one plaintext coefficient,
so the ideal output simulation needs only the intended logical scalar's three coordinates. This last
observation is the implementation's projection of the full-ring construction.

This guarantee is **conditional on honestly generated keys and fresh bounded
source ciphertexts**, as supplied by `Target`. Syntactic public-key/ciphertext
validation does not prove honest setup. No claim of circuit privacy against a
target that constructs arbitrary malformed keys or sources is made. The report
proof authenticates the monitor's arithmetic; it cannot prove that private
coins were sampled uniformly. Fresh honest coins remain necessary for privacy.
The selected lattice/Poseidon parameters and proof composition are research
parameters requiring independent cryptographic review, not a security
certification. Peer ElGamal public shares must be provisioned authentically;
TCP itself supplies no TLS or separate peer-identity layer.

## ElGamal accumulator and counting

With the user's approved correction, the accumulator starts at A=1, padded
with encrypted zeros, and the candidate is `(X-z)A`. Its proof constrains
`e_j=mask*z^j`, a nonzero mask, masked evaluation, knowledge of the monitor's
ElGamal share, partial decryption and rerandomization. A linked Schnorr proof
opens the proved encoding commitment to establish `zA=XA-next`; the extra leading ciphertext is checked
explicitly. The old scalar-only `y*A` update is not accepted.

After verifying **both** proofs, the target decrypts the RLWE scalar results
and the ElGamal accumulator evaluation. It counts and inserts only when the
Bloom membership predicate is true and A(z) is nonzero. Repeats and nonmembers
retain the count; the accumulator is rerandomized each accepted round. Capacity
exhaustion rejects before mutation. The extra encrypted padding is dropped
only when the capacity invariant ensures its plaintext is zero. Failed proof,
parameter, session, round and replay checks leave target state unchanged.
Library callers can use `Monitor::set_input` between `compute_round` calls to
submit distinct queries without changing the session's ElGamal key share.

## Validation and costs

```sh
cargo +1.88.0 check --all-targets
cargo +1.88.0 check --no-default-features
cargo +1.88.0 test --release
# Complete production-sized report, intentionally expensive:
cargo +1.88.0 test --release authenticated_production_100k_report -- --ignored --nocapture
```

Tests include the Go coefficient oracle, packing boundaries, global powers,
100,000 distinct roots, independent public-context transport, direct plaintext
weighted evaluations, malformed parameters/ciphertexts, Bloom/hash/modular
constraints, full evaluation proofs and complete multi-round reports. A genuine
well-formed encryption of zero made with incorrect hash weights is rejected by
the evaluation verifier. Accumulator tests reject newly generated proofs of
incorrect root insertion or masked evaluation, not just corrupted proof bytes.

At 100k buckets the target ciphertext measures 10,666,316 bytes plus a
762,000-byte public context in the current native encoding. This exceeds the
6,400,064-byte raw ElGamal coefficient payload: the large circuit-privacy modulus
trades communication for the terminal privacy guarantee. Packing reduces the
number of ciphertext objects, not necessarily their total byte count.

The report still has **linear communication and substantial proving cost** because
its cross-proof numeric inputs use individual Pedersen commitments. At 100k
buckets it has **1,042,399 shared commitments (33,356,768 bytes)**, compared with
2,374,657 commitments (75,989,024 bytes) in the retired integer-lift/range-batch
path. The three amortized PKC relations and three links add logarithmic proof payloads.
The layout test budgets the complete report, including a 100k-capacity
accumulator, below the 128 MiB frame limit. Generator caches retain one PKC size
at a time to avoid accumulating several large generator sets.

The old 52.5-minute / 79.75-MB benchmark belongs to the retired proof path and is
**not a measurement of this version**. The ignored production test remains the
way to measure the complete current report, verification and target update.
Production-size proving time has not been remeasured for this PKC version.

A reproducible [proof-cost audit](PROOF_AUDIT.md) compares this path with the
checked-in ElGamal baseline and records circuit sizes at 1k and 100k buckets.
