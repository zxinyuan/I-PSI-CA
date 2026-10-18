# Exact protocol: proofs, measurements, and optimizations

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
mode cannot be disabled by a wire field. There is no JSON configuration in this
project. Omitted `--pok` means false. There is no third positional argument:
`exact 10 true --pok true --round1 false` is the complete invocation. Both
positionals may also be omitted: `exact --pok true --round1 false` uses the
default degree and query selection. The target constructor is
`Target::new(t_set, sk1, pk1, pk2)`.

## `round1` and measurement boundaries

`round1` is a boolean, defaults to **true**, and must agree on both endpoints.
It selects a measurement phase, not an unauthenticated cryptographic round index.
Use `pok=true` for the requested proof-bearing measurements. With `pok=false`,
the target initial/OR proofs remain disabled and their reported size is zero;
the monitor's joint proof is still mandatory for update interactions.

* `--round1 true`: construct and store the initial TPolyCtext and initial PoK.
  Print **Deployment Latency** in milliseconds, and **Ciphertext Storage**,
  **Proof Storage**, and **Total Storage** separately in MB. The latency starts
  before polynomial construction/encryption and ends when the ciphertext/proof
  are in local storage. It excludes key generation, socket/session setup,
  communication, and monitor verification. The deployment is uploaded and its
  proof verified by the monitor; no query or division reply is computed.
* `--round1 false`: prepare a valid initial ciphertext/PoK outside the interaction
  timer. Send it, verify the monitor's joint proof, choose the old polynomial or
  verified quotient, rerandomize, generate the OR proof, and atomically replace
  local ciphertext/proof/round storage. **Interaction Latency** runs from just
  before the target send through this complete local storage update. The new OR
  proof is then uploaded and verified by the monitor, including the final update.
  That final upload/verification is outside the requested send-to-storage latency.
  A fresh process performs real initial-proof verification rather than pretending
  it already has authenticated prior state. This option does not resume a prior
  process or reuse a proof under a different session identifier.

All MB values are decimal (`1 MB = 1,000,000 bytes`), with exact byte counts also
printed. Storage means canonical bincode ciphertext/proof payload sizes, including
the proof-type tag; it excludes keys, private witnesses, session metadata, frame
headers, RAM allocation overhead, and disk I/O. Storage is in-memory protocol
state, accessible through `Target::stored_polynomial()`.

For each update, report the monitor reply, updated target ciphertext, disjunction
proof, and framed target-update send sizes separately. **Monitor + Target Update
Communication** is the recurring reply plus updated-ciphertext/OR upload.
**Total Communication** also includes the initial target ciphertext/PoK upload
on the first interaction. Every actual message's 4-byte frame header is counted.
The session-negotiation exchange is excluded. For multiple interactions, the
previous uploaded update is the next request: it is neither resent nor counted
again, so summing the totals counts every transfer once. The next latency interval
starts just before that shared upload; logging/size accounting are outside it.

The deployment and interaction measurements are also available through
`Target::deployment_measurement()` and `Target::interaction_measurements()`.
The executable currently requests one interaction. Library callers can supply
more through `run(addr, rounds)`; deployment mode always performs one deployment.

## Initial proof

For a scalar root list S of size d (including its multiplicities), coefficients
are in ascending order and P(X) = product (X - s). The statement binds the public
key, ciphertext vector, protocol version, session identifier, and round 1.

The initial R1CS uses a randomized polynomial-identity check. Roots and all d+1
coefficients are privately committed before the evaluation challenge z is sampled
through Bulletproofs' second-phase randomized-constraint API. The circuit fixes
the leading coefficient to 1 and checks:

```text
sum_i coefficient[i] * z^i = product_s (z - s)
```

For d >= 2 this uses d-1 multiplication constraints. An incorrect monic polynomial
has a nonzero difference of degree at most d-1, so the additional one-challenge
identity-testing error is at most `(d-1)/q`, on top of the underlying R1CS and
Fiat–Shamir assumptions. Empty and singleton root lists use exact linear
constraints instead. Challenge grinding must be accounted for in the usual
random-oracle security model; the bound is not a certification of the full
application's security.

A shared-witness Sigma proof links each committed coefficient D = aG + bH to
its ciphertext U = rG, V = aG + rPK. It checks every coefficient's opening and
both ciphertext components. The link transcript binds the completed R1CS proof,
all root/coefficient commitments, and the complete public statement. Roots,
plaintext coefficients, blindings, and encryption randomness remain private.

There is no independently authenticated original-set commitment in this protocol.
The initial proof establishes knowledge of a root list underlying the deployment
ciphertext, rather than equality to an externally specified original set.

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
The default mode omits only the target initial/OR proofs; monitor proofs remain
mandatory and are verified in both modes.

The exact path no longer uses the legacy shared Sigma–Bulletproof glue: that
implementation did not prove that its ciphertext weights open the circuit's
weight commitments. Shared code and BF behavior outside `src/exact` are unchanged.

## OR proof and state

At the start of round r > 1 the two public candidates are:

* C_old: the ciphertext accepted by the monitor in round r-1.
* C_next: the quotient sent by the monitor and verified by the target in round r-1.

Both exist before the target generates C_new. The target rerandomizes the selected
candidate with independent fresh randomness per coefficient. The CDS94 proof is
an OR of two complete vector Chaum–Pedersen relations:

```
for every i: C_new[i].U - C_branch[i].U = rho[i] G
             C_new[i].V - C_branch[i].V = rho[i] PK
```

The v4 wire representation sends only both branch challenges and response
vectors. It omits the commitments, reconstructing them during verification as:

```text
A[j,i].U = z[j,i] G  - e[j] (C_new[i].U - C_branch[j][i].U)
A[j,i].V = z[j,i] PK - e[j] (C_new[i].V - C_branch[j][i].V)
```

The verifier then requires `e[0] + e[1] = H(statement, A[0], A[1])`. Expanding an
accepted compressed proof yields the original CDS94 transcript. No branch
selector is serialized, and no per-coefficient branch selection is introduced.
Older wire versions are rejected during session negotiation.

Each branch has one challenge shared by all coefficients. The simulated and real
branch challenges sum to the Fiat–Shamir challenge. The proof contains no branch
selector. The transcript binds both candidates, output, key, session, round,
version, and every commitment. The monitor only advances accepted ciphertext
state after successful verification, and never uses candidates supplied alongside
C_new. Missing, truncated, wrong-round, or invalid proofs reject the session.
The OR proof authorizes either candidate; it does not prove the target's private
match-dependent selection policy.

The session identifier binds the protocol version, locally selected `pok` and `round1` flags, and
fresh target and monitor nonces in a 108-byte setup exchange (including frame
headers), in BOTH modes. Mismatched flags or versions are rejected before rounds. A final target update
is uploaded for verification even when there is no following query.
The current negotiation/proof version is v4. Public keys must be provisioned by
the caller as in the existing protocol. This
adds proof-authenticated state transitions, not authenticated TCP peer identities.

## Validation and measurements

`proofs.rs` tests initial relations, duplicate/empty root lists, both OR branches,
public-key/candidate/output tampering, challenges/responses, malformed points and
scalars, truncation, replay, dimensions, and mixed-coefficient branches.
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

Proof inputs are limited to 4096 coefficients (4095 set elements for the initial
proof), frames to 64 MiB, and initial R1CS proof bytes to 64 KiB. The executable
rejects degree zero; its positional parser does not itself enforce the upper
bound, which is checked by the proof/update path. Decoded dimensions and canonical
group/scalar encodings are checked. The randomized initial R1CS circuit is linear
in set size; the ordinary plaintext polynomial-from-roots routine remains
quadratic. It is computed once during the target's deployment flow.

This implementation inherits the experimental Bulletproof R1CS dependency
(`yoloproofs`) and has not been independently audited. Security relies on discrete-log/DDH
assumptions for Ristretto, computational binding of Pedersen commitments, the
Bulletproof R1CS argument, and Fiat–Shamir in the random-oracle model. No additional dependencies or proof-system setup ceremony are introduced.


## Optimizations and representative measurements

The exact path implements:

* Right-sized, process-wide `Arc<BulletproofGens>` reuse. Only public generator
  sets of capacities 64, 128, ..., 4096 are cached. Secret witnesses, encryption
  randomness, masks, and nonces are freshly generated and are not cached.
* A randomized initial identity circuit with d-1 multipliers instead of
  d(d+1)/2 for d >= 2. At 1000 roots, this is 999 multipliers and generator
  capacity 1024, versus 500,500 multipliers and capacity 1,048,576 previously.
* Constant-time prover MSM and fixed-base multiplication. Verifier-only operations
  may use variable-time MSM because the proof responses are public. Each Sigma
  relation is still checked independently; this is not randomized batch checking.
* Compressed CDS94 OR messages, retaining complete-polynomial branch semantics.
* Native quotient reuse during monitor proof generation and candidate storage,
  avoiding internal serialization/decompression round trips. Received wire data
  is still validated.
* Shared transcript prefixes and preallocated vectors. Ciphertext encodings are
  not recompressed for a second copy of the same local statement prefix.

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

Representative single local release runs, in ms (not averages or guarantees):

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

For n coefficients, the tagged OR proof is `64*n + 84` bytes, compared with
`192*n + 100` previously. The 1000-root target update was previously 256,368 bytes;
compression reduces that upload by about 50%. Monitor proofs retain all shared-
witness links, partial-decryption checks, and quotient-blinding checks.


Construction references: [Bulletproofs paper](https://web.stanford.edu/~buenz/pubs/bulletproofs.pdf)
and [CDS94](https://ir.cwi.nl/pub/1456/). These references establish the underlying
constructions, not a security audit of this Rust implementation or its composition.
