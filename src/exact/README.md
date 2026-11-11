# Exact protocol: proofs, measurements, and optimizations

For `sbatch run.sh S N M` with skynet-02 as the 12-core target and automatic
Linux monitor placement, see [the single-batch latency instructions](RUN.md).

For the distributed multi-set, multi-monitor benchmark, see
[the benchmark guide](benchmark/README.md). It includes the separate target and
load-generator roles, Slurm scripts, experiment sweeps, and result analysis.
The sections below describe the original single-process runner.

The exact implementation uses polynomial division and removal in both `pok`
modes. It has no accumulator or accumulator-size argument. The BF variant retains
its existing accumulator argument. For all parameters, defaults, and copyable
terminal commands, see [the root README](../../README.md#invoke-exact-with-all-parameters).

The optional `degree` and `in_set` positionals precede the flags:

```
cargo run --release -- exact 10 true --pok true --round1 true
cargo run --release -- exact 10 true --pok true --round1 false
```

The exact endpoints read the flag locally. Library callers can instead call
`with_config(ProtocolConfig { pok: true, round1: false })` on both endpoints. A locally enabled
mode cannot be disabled by a wire field. The single-process runner uses CLI
configuration. Omitted `--pok` means true; `--pok false` explicitly opts out of target proofs. There is no third positional argument:
`exact 10 true --pok true --round1 false` is the complete invocation. Both
positionals may also be omitted: `exact --pok true --round1 false` uses the
default degree and query selection. The target constructor is
`Target::new(t_set, sk1, pk1, pk2)`.

## `round1` and measurement boundaries

`round1` is a boolean, defaults to **true**, and must agree on both endpoints.
It selects a measurement phase, not an unauthenticated cryptographic round index.
Target knowledge proofs are enabled by default. `--pok false` explicitly opts
out of the target initial and disjunction proofs; monitor Sigma–Bulletproofs
remain mandatory during interactions.

* `--round1 true`: construct and store the initial TPolyCtext and coefficient
  PoK, then upload both for monitor verification. **Deployment Latency** is in
  seconds and runs from polynomial construction through encryption, proof
  generation, and the local storage update. It excludes key generation,
  session setup, upload, and monitor verification. **Ciphertext Storage**,
  **Proof Storage**, and **Total Storage** are reported separately in MB.
  No query or division reply is computed.
* `--round1 false`: the target sends its initial ciphertext and coefficient
  PoK. After verifying that upload, the monitor starts computation and returns
  the ciphertexts and joint Sigma–Bulletproof. The target verifies the reply,
  selects the quotient or old polynomial, rerandomizes it, generates the
  disjunction proof, and replaces its local ciphertext/proof storage.
  **Interaction Latency**, in seconds, runs from the monitor's receipt of the complete target
  payload, before verification, through that target storage replacement. Target
  upload transfer is excluded; target-proof verification is included. The new storage is uploaded as the target's
  next request, including the final update, and verified by the monitor.

All reported durations and MB values use **four significant digits**, retaining
trailing zeros (`1.000 s`, `0.001235 MB`) and scientific notation for very small
or large values. MB is decimal (`1 MB = 1,000,000 bytes`). Exact byte counts remain
available in the measurement structs. Storage counts canonical bincode
ciphertext/proof payloads, including the proof-type tag; it excludes keys,
private witnesses, session metadata, framing, RAM overhead, and disk I/O.

For each update, the output reports:

* **Monitor Send**: the serialized ciphertexts, Sigma–Bulletproof, and computation
  start timestamp, plus the message's four-byte frame header, in MB.
* **New Storage (ciphertext + disjunction proof)**: the target's serialized
  updated ciphertext and proof payload, in MB. This becomes its next upload.
* **Communication (monitor send + next target payload)**: the sum of those two
  quantities, in MB. It excludes the initial target upload, session setup,
  and the next target upload's four-byte frame header.

`InteractionCosts::recurring_bytes()` implements this reported sum.
`InteractionCosts::total_bytes()` separately retains complete wire accounting,
including initial upload when present and the next target frame. A previous
update is the next request; it is not sent a second time.

With `--round1 false`, **Monitor Time** runs from receipt/deserialization of the
complete target payload through target-proof verification and completion of the
monitor computation and proof, before sending the reply. **Target Time** runs
from receipt/deserialization of the monitor reply through proof verification,
decryption and match testing, rerandomization, disjunction proof generation (when
PoK is enabled), and storage. These durations use local monotonic clocks.
**Interaction Latency** starts at the same receipt boundary as Monitor Time and
includes monitor reply transport, so it equals the two local times plus reply
serialization, transport, deserialization, and intervening overhead (subject to
wall-clock adjustments). `InteractionMeasurement::target_time_s` exposes
the target duration programmatically.

To measure the requested interval across endpoints, the monitor records a Unix
nanosecond timestamp on receipt of the target payload, before verification, and
binds it into the Sigma proof. The target subtracts that start from its timestamp immediately
after replacing storage. The demo runs both roles on one host and uses the same
wall clock. Separate hosts need synchronized clocks; backwards intervals are
rejected. The public records expose `latency_s`, `monitor_started_unix_ns`, and
`target_stored_unix_ns` (the latter two on interaction records). A change to the
monitor timestamp invalidates the proof. Wall-clock adjustments can affect this
cross-endpoint measurement.

The deployment and interaction measurements are also available through
`Target::deployment_measurement()` and `Target::interaction_measurements()`.
The executable currently requests one interaction. Library callers can supply
more through `run(addr, rounds)`; deployment mode always performs one deployment.

## Cryptographic packages and local adapters

The exact path uses these external implementations:

* [`bulletproofs` 4](https://docs.rs/bulletproofs/4.0.0/bulletproofs/r1cs/index.html)
  supplies Pedersen commitments and the monitor R1CS prover/verifier.
* [`sigma_fun` 0.8](https://docs.rs/sigma_fun/0.8.0/sigma_fun/)
  supplies Fiat–Shamir, synthetic nonce derivation, compact proofs, and OR
  simulation/composition. Initial and monitor proofs use `FiatShamir<Linear, _>`;
  the update proof uses `FiatShamir<Or<Linear, Linear>, _>`.

ElGamal is implemented natively over the shared repository ciphertext types.
`encryption.rs` encrypts as (rG, mG + rPK) and rerandomizes with explicit
randomness, which the proof witnesses require. Multiplications by G use the static
basepoint table and multiplications by PK a fixed-base table for that key, built
once per key and cached (`performance::table`). Partial decryption and zero
testing use the shared `crypto::elgamal` functions. An earlier version used the
`elastic-elgamal` package through its Serde API; that conversion compressed and
decompressed every point and multiplied by PK without a table, which made
rerandomization about 4x slower than the native code.

`sigma.rs` is the remaining local linear-relation adapter. The built-in
`sigma_fun` curve protocols use Edwards points or secp256k1; its `All` combinator
has a compile-time length. This protocol instead needs runtime-length Ristretto
relations with shared scalar variables. The adapter defines the linear map,
response arithmetic, and unambiguous statement encoding; it delegates the
Fiat–Shamir transcript, nonce derivation, and OR logic to the package. It uses
248-bit challenges, embedded injectively in the scalar field. The package's
`HashTranscript` uses SHA-256 and ChaCha20; a Merlin-derived context binds the
entire application statement, including completed R1CS bytes for monitor proofs.

Public bases that occur in many terms (G, PK, the Pedersen blinding base) are
registered once per statement as fixed bases. Each carries its encoding and a
cached fixed-base table. Nonce commitments multiply fixed bases through their
tables, in constant time. The statement hash encodes each fixed base once and
refers to it by index; other points are hashed in full. Images whose canonical
encoding the endpoint already holds (received or stored wire bytes) are hashed
from those bytes rather than compressed again. Application transcripts bind the
same wire bytes, so each party compresses a ciphertext point at most once.

Before proving, the honest prover checks its witness against all equations as one
random linear combination with fresh coefficients. A bad witness passes only with
probability 1/l. This check guards against prover bugs. It is not part of
verification, which checks each equation separately.

Polynomial construction, synthetic division, R1CS constraint selection, and the
choice of which witnesses occur in which equations remain application code.
There is no new standalone Sigma–Bulletproof primitive: the monitor composes the
library R1CS proof with a library Sigma proof opening those same commitments.
The shared crypto and BF implementations outside `src/exact` are unchanged;
package declarations and the lockfile are updated at the repository root.

The selected versions build with the existing Rust 1.81 toolchain. The general `sigma-proofs` 0.2.2
backend was also examined, but its current transitive dependencies require a
newer compiler. Updating the compiler and backend is a separate migration.

## Initial proof

The target computes ascending polynomial coefficients from its set locally. The
first-round proof witnesses only these coefficients a[i] and their encryption
randomness r[i], for ciphertexts U[i] = r[i]G, V[i] = a[i]G + r[i]PK.

For each coefficient, the library samples fresh nonces alpha[i], rho[i] and
computes A[i] = rho[i]G and B[i] = alpha[i]G + rho[i]PK. A single Fiat–Shamir challenge e
binds the public key, complete ciphertext vector, protocol version, session,
round 1, and all nonce commitments. Responses are z_a = alpha + e*a and
z_r = rho + e*r. The verifier checks both equations for every coefficient:

```text
z_r G = A + e U
z_a G + z_r PK = B + e V
```

Coefficients and randomness remain private. There are no root commitments,
Pedersen coefficient commitments, or initial R1CS circuit. Proof generation,
verification, and size are linear in coefficient count n. The serialized
`InitialPoK` is `64*n + 39` bytes, excluding the enclosing enum and frame.
The compact encoding sends a 31-byte challenge and 2*n scalar responses; nonce
commitments are reconstructed during verification.
`generate_initial_pok` accepts coefficients directly, rather than roots.

This proves knowledge of the encrypted coefficients, without proving monicity,
factorization into known roots, or equality to an authenticated original set.
The proof encoding and transcript domain differ from the prior root proof;
both peers must use the updated implementation.

## Monitor Sigma–Bulletproof, every round

Every monitor reply contains one shared-witness Sigma–Bulletproof covering the
following complete relation. Write C[i] = (U[i], V[i]), with PK = PK1 + PK2.
The private witnesses are the query m, nonzero multiplication mask a, independent
encryption randomness eta, monitor key share sk2, partial-decryption randomness r,
and quotient-rerandomization witnesses.

```
e[i] = a * m^i,              a * inverse_a = 1
scaled.U = sum_i e[i] U[i] + eta G
scaled.V = sum_i e[i] V[i] + eta PK
PK2 = sk2 G
partial.U - scaled.U = r G
partial.V - scaled.V = -sk2 scaled.U + r PK1
```

The monitor computes the synthetic quotient by (X-m), pads it to C's length with
a zero coefficient, and independently rerandomizes EVERY coefficient, including
the padding. Call the resulting ciphertext Q. The proof additionally establishes:

```
Q[last] = Encrypt(0; rho_top)
Q[i-1].U - C[i].U = m Q[i].U + lambda[i] G       (i >= 1)
Q[i-1].V - C[i].V = m Q[i].V + lambda[i] PK      (i >= 1)
```

If rho[i] is the actual blinding of each quotient coefficient, the honest witness
is lambda[i] = rho[i-1] - m*rho[i]. Conversely, these recurrences and the top-zero
relation imply that Q encrypts the synthetic quotient. Division need not be exact
on a nonmatch; the omitted constant remainder is P(m). The separately proved
nonzero-masked evaluation lets the target test whether this remainder is zero.
For a constant polynomial the quotient is encrypted zero.

The Bulletproof R1CS commits to every e[i], m, and inverse_a. A single Sigma proof
proves openings of ALL those commitments and uses the SAME value responses in
the ciphertext equations above. Thus a valid circuit cannot be paired with an
unrelated linear combination of ciphertext coefficients. The same query response
also appears in every division equation. Each group equation is checked directly;
there is no unchecked or probabilistically batched equality in the Sigma link.

Both proof transcripts bind the protocol version, fresh session identifier,
round, all three public keys, C, Q, scaled, and partial. The Sigma challenge also
binds all circuit commitments, the completed R1CS proof, and every Sigma commitment.
All proof scalars must have canonical encodings, and every supplied group element
is decoded as a Ristretto point. Key shares must be nonidentity and sum to PK.
The proof establishes knowledge of valid randomness and a nonzero mask; it cannot
certify that a malicious prover sampled those witnesses uniformly. Honest
production generation uses cryptographically secure randomness.

The proof publishes no query tag mG. Quotient blinding is necessary because a
raw deterministic quotient can give a target that knows coefficient encryption
randomness a handle for testing guesses about m. Fresh rerandomization prevents
that direct algebraic disclosure. This is not a formal proof of privacy for the
whole application or against arbitrary malicious inputs in proof-disabled mode.

The target verifies the ENTIRE monitor proof before testing the remainder,
incrementing its match counter, or storing Q. On a match it chooses Q for the next
round; otherwise it chooses C. This removes one occurrence of m per match.
Neither mode constructs, sends, receives, updates, or proves an accumulator.
The explicit `--pok false` mode omits only the target initial/OR proofs; monitor
proofs remain mandatory and are verified in both modes.

The exact path no longer uses the legacy shared Sigma–Bulletproof glue: that
implementation did not prove that its ciphertext weights open the circuit's
weight commitments. Shared code and BF behavior outside `src/exact` are unchanged.

## OR proof and state

At the start of round r > 1 the two public candidates are:

* C_old: the ciphertext accepted by the monitor in round r-1.
* C_next: the quotient sent by the monitor and verified by the target in round r-1.

Both exist before the target generates C_new. The target rerandomizes the selected
candidate with independent fresh randomness per coefficient. The library composes
an OR of two complete vector Chaum–Pedersen relations:

```
for every i: C_new[i].U - C_branch[i].U = rho[i] G
             C_new[i].V - C_branch[i].V = rho[i] PK
```

The `sigma_fun::Or` compact encoding contains the overall 31-byte challenge,
one branch's 31-byte challenge, and both scalar response vectors. The package
uses XOR to split the overall challenge between the simulated and real branches.
Each branch uses one challenge for every coefficient. Nonce commitments are
reconstructed during verification; no branch selector is serialized. The tagged
`TPolyProof::RerandomizationOr` is `64*n + 82` bytes for n coefficients.

The application binds both candidates, output, key, session, round, and version;
the library also hashes the complete linear relations and nonce commitments.
The monitor only advances accepted ciphertext state after successful verification,
and never uses candidates supplied alongside C_new. Missing, truncated,
wrong-round, or invalid proofs reject the session. A mixed selection of individual
coefficients from different candidates does not satisfy either complete branch.
Older wire versions are rejected during session negotiation.
The OR proof authorizes either candidate; it does not prove the target's private
match-dependent selection policy.

The session identifier binds the protocol version, locally selected `pok` and `round1` flags, and
fresh target and monitor nonces in a 108-byte setup exchange (including frame
headers), in BOTH modes. Mismatched flags or versions are rejected before rounds. A final target update
is uploaded for verification even when there is no following query.
The current negotiation/proof version is v7. v7 changed the Sigma statement
hash (fixed bases), so v6 peers are rejected during negotiation. Public keys must be provisioned by
the caller as in the existing protocol. This
adds proof-authenticated state transitions, not authenticated TCP peer identities.

## Validation and measurements

`proofs.rs` tests initial relations, duplicate/empty root lists, both OR branches,
public-key/candidate/output tampering, challenges/responses, noncanonical
scalars, truncation, replay, dimensions, and malicious mixed-coefficient branches.
An in-process integration test runs all three library-backed proof phases over
multiple rounds, including repeated removal, nonmembers, and constant polynomials.
`division.rs` tests constant and nonconstant quotient relations, query variants,
reply tampering, independent rerandomization, and transcript binding. Malicious-
prover tests construct valid group transcripts with unrelated circuit weights,
zero masks, different division queries, false evaluations, incorrect partial
decryptions, and a nonzero quotient leading coefficient; all must be rejected. TCP integration tests cover three-round
proof-disabled/proof-enabled sessions, mode mismatches, repeated removal, duplicate roots,
nonmembers, and constant polynomials.

Deployment and interaction logs follow the phase boundaries and byte accounting
specified above. These are runtime measurements, not a statistically controlled
benchmark.

Proof inputs are limited to 16384 coefficients (16383 set elements for the initial
proof), and frames to 64 MiB. The executable
rejects degree zero and rejects degrees above 16383 before starting either
endpoint when `--pok true` or `--round1 false`. Deployment without proofs
(`--pok false --round1 true`) does not use these bounded proof/update paths. Decoded dimensions and canonical
group/scalar encodings are checked. The initial coefficient proof is linear
in set size. The plaintext polynomial is computed from the roots once, during
the target's deployment flow, with a Karatsuba product tree (`crypto::poly`):
about O(n^1.59) field multiplications, instead of O(n^2) for root-by-root
expansion.

This implementation inherits the experimental Bulletproof R1CS dependency
(`yoloproofs`) and has not been independently audited. Security relies on discrete-log/DDH
assumptions for Ristretto, computational binding of Pedersen commitments, the
Bulletproof R1CS argument, and Fiat–Shamir in the random-oracle model. The
`sigma_fun` package is also experimental. Package reuse does not constitute an
audit of the application relation or its composition. No proof-system setup
ceremony is introduced.


## Optimizations and representative measurements

The recorded timings below predate the coefficient-only initial proof and the
package refactor; they do not describe the current implementation.

The exact path implements:

* Right-sized, process-wide `Arc<BulletproofGens>` reuse. Only public generator
  sets of capacities 64, 128, ..., 16384 are cached. Secret witnesses, encryption
  randomness, masks, and nonces are freshly generated and are not cached.
* A direct initial coefficient Sigma proof, requiring no R1CS multipliers or
  Bulletproof generators.
* Constant-time prover MSM and fixed-base multiplication. Fixed-base tables for
  G, PK, and the Pedersen blinding base are cached; they contain only public
  points. Verifier-only operations may use variable-time MSM because the proof
  responses are public. The verifier checks each Sigma relation independently.
  Only the prover's own pre-proof witness check uses a random linear combination.
* Library compact OR messages, retaining complete-polynomial branch semantics.
* Native quotient reuse during monitor proof generation and candidate storage.
  Received wire data is validated on decoding, and its canonical encodings are
  reused in transcripts.
* Shared application transcript prefixes and preallocated vectors. The Sigma
  package hashes the explicit linear relation in addition to the application
  context.

Runtime output reports **Public Generator Cache** builds, setup milliseconds,
and hits. Setup that occurs inside a measurement stays inside its latency.
Counters are process-wide: the demo's two threads can share public setup; separate
processes have separate caches. Compare cold first calls and warm repeated calls
explicitly. In library measurement records this is `generator_setup`.

Run the ignored microbenchmark from the repository root:

```sh
cargo test --release exact::benchmarks -- --ignored --nocapture --test-threads=1
EXACT_BENCH_LARGE=1 cargo test --release exact::benchmarks -- --ignored --nocapture --test-threads=1
```

It resets the generator cache before the initial and monitor proof phases at
each size, reports setup separately, and uses seeded test randomness. Production
uses cryptographically secure randomness. Verification and repeated generation
use the warmed cache. This measures individual proof operations; it excludes
TCP and the complete deployment encryption/storage flow.

Historical single local release runs, in ms (prior root-based implementation):

| Operation, 128 roots | Before optimization | After optimization |
|---|---:|---:|
| Initial PoK generation, first call | 3060.833 | 75.178 |
| Initial PoK generation, repeat | 3046.741 | 72.445 |
| Initial PoK verification | 760.343 | 30.599 |
| Monitor joint proof generation | 131.784 | 105.261 |
| Monitor joint proof verification | 75.812 | 35.293 |
| OR proof generation | 48.198 | 32.840 |
| OR proof verification | 48.455 | 27.188 |

The earlier implementation rebuilt generators for each operation. In the
optimized run the first initial/monitor calls included fresh setup (1.914 ms and
3.746 ms respectively); verification/repeats were warm. These differences are
part of the optimization and must not be interpreted as isolated arithmetic
speedups or distributed-network benchmarks.

A separate optimized run with 1000 roots measured initial generation at 635.363 ms
(first call) and 600.370 ms (repeat), monitor generation at 667.542 ms, and OR
proof generation at 255.567 ms. For that size:

| Serialized component | Bytes | Decimal MB |
|---|---:|---:|
| Initial PoK, including proof-type tag | 257421 | 0.257421 |
| TPolyCtext | 64072 | 0.064072 |
| Compressed OR proof, including proof-type tag | 64148 | 0.064148 |
| Updated ciphertext + OR proof storage | 128220 | 0.128220 |
| Framed target update | 128224 | 0.128224 |

The table above records the old proof encoding. Current v7 sizes for n
coefficients, including proof-type tags, are `64*n + 43` bytes for the initial
proof and `64*n + 82` bytes for the OR proof. At 1000 roots (1001 coefficients),
these are 64,107 and 64,146 bytes respectively. Ciphertext storage is 64,072 bytes;
updated ciphertext plus OR proof storage is 128,218 bytes, or 128,222 bytes with
the frame header. Monitor proofs retain all shared-witness links,
partial-decryption checks, and quotient-blinding checks.

Single local release runs at 1000 roots (`EXACT_BENCH_DEGREE=1000`), in seconds.
"Before" is the package-adapter implementation, built without LTO or native CPU
flags. "After, portable" adds the code changes and the LTO release profile;
"After" also uses `target-cpu=native`. Proof sizes are unchanged.

| Operation, 1000 roots | Before | After, portable | After |
|---|---:|---:|---:|
| Initial PoK generation, first call | 0.2428 | 0.06569 | 0.05816 |
| Initial PoK verification | 0.1268 | 0.1123 | 0.09998 |
| Monitor joint proof generation | 0.7770 | 0.6252 | 0.5384 |
| Monitor joint proof verification | 0.2693 | 0.2347 | 0.2185 |
| OR proof generation | 0.3275 | 0.1703 | 0.1632 |
| OR proof verification | 0.2392 | 0.2179 | 0.2193 |

About 0.27 s of monitor proof generation is the library Bulletproof R1CS prover.
Verifiers are linear in equation count, because compact proofs recompute every
nonce commitment.


Construction references: [Bulletproofs paper](https://web.stanford.edu/~buenz/pubs/bulletproofs.pdf)
and [CDS94](https://ir.cwi.nl/pub/1456/). These references establish the underlying
constructions, not a security audit of this Rust implementation or its composition.

To validate and time all proof paths at 10,000 items:

```bash
EXACT_BENCH_DEGREE=10000 cargo test --release exact::benchmarks -- --ignored --nocapture
```
