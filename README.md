# i-psi-ca

A Rust research prototype for interactive private-set-intersection cardinality,
using ElGamal over Ristretto255, packed RLWE for BF target polynomials,
Bulletproof R1CS, and Sigma proofs. The **Scribe / Target** holds the private set; the **Lookout / Monitor**
holds a query. The target verifies the monitor's proof and tests for a match.

| Variant | Encoding and match rule | State update |
|---|---|---|
| `exact` | Encrypted polynomial with set elements as roots; query equals a root | Remove one occurrence of a matching query by verified polynomial division |
| `bf` | Packed RLWE polynomial over Bloom buckets, authenticated hash-weighted evaluations | ElGamal root accumulator counts distinct matches |

**Exact does not construct, send, receive, or prove an accumulator.** Its optional
`pok` mode, enabled by default, adds an initial coefficient-knowledge proof and
subsequent library OR proofs. `--pok false` explicitly opts out.
The monitor's joint evaluation/masking/partial-decryption/division proof is
mandatory for exact interactions in both modes. See the
[exact protocol guide](src/exact/README.md) for proof relations and assumptions.

## Build

Requires Rust/Cargo 1.88 or later (edition 2021). Dependencies are Rust
crates; no external cryptographic service or trusted setup ceremony is used.
`rust-toolchain.toml` selects Rust 1.88.0 automatically when using rustup,
even if your global default is older. If needed, install it with
`rustup toolchain install 1.88.0 --profile minimal`.
Run commands from the repository root:

```sh
cargo build --release
```

Release builds use fat LTO with one codegen unit (`Cargo.toml`), and
`.cargo/config.toml` compiles for the build machine's CPU (`-C target-cpu=native`,
10-16% faster curve arithmetic in local measurements). The resulting binaries may
not run on CPUs without the same instruction-set extensions; delete that file, or
set `RUSTFLAGS=""`, to build portable binaries. Record these settings alongside
any reported timings.

Use release builds for timing measurements. The binary starts both roles as
threads in one process and connects them over TCP at `127.0.0.1:7878`. No separate
server terminal is needed. Each invocation creates fresh inputs, key shares,
proof randomness, and a session. Timings and costs are printed to stdout/stderr.

## Invoke exact with all parameters

```text
cargo run --release -- exact [degree] [in_set] --pok <true|false> --round1 <true|false>
```

The text in angle brackets denotes values to replace, not literal arguments.

| Parameter | Accepted values | Default | Meaning |
|---|---|---|---|
| `degree` | Positive integer; use `1..16383` for proof/update flows | `1000` | Number of uniformly sampled private set elements; ciphertext length is `degree + 1` |
| `in_set` | `true` or `false` | `true` | Select a query from the set, or sample an independent query expected not to match |
| `--pok` | Explicit `true` or `false` | `true` | Enable the target's initial coefficient PoK and subsequent OR proofs |
| `--round1` | Explicit `true` or `false` | `true` | Select deployment-only measurement or a complete query/update interaction |

Exact accepts only two positional values: `degree` and `in_set`. Put any supplied
positionals before the flags. Both positionals may be omitted to use defaults;
for example, `exact --pok true --round1 false` uses degree 1000 and `in_set=true`.
There is no accumulator-size argument. The two named flags may appear in either
order, and both require an explicit boolean value. Unknown flags, duplicate
flags, and extra positional values are rejected.

### Deployment: ciphertext plus initial PoK

```sh
cargo run --release -- exact 1000 true --pok true --round1 true
```

Computes and stores TPolyCtext and the initial proof, then uploads them for monitor
verification. Reports:

- **Deployment Latency** in s: polynomial construction, encryption, proof
  generation, and local storage update. Networking and monitor verification are
  excluded.
- **Ciphertext Storage**, **Proof Storage**, and **Total Storage** in MB.
- **Public Generator Cache** builds, setup time, and hits. Setup performed during
  the measurement remains included in its latency.

This phase performs no query or polynomial division. The final match count stays
zero even if the executable's input summary prints `Expected = MATCH`.

### Interaction: matching query and polynomial removal

```sh
cargo run --release -- exact 1000 true --pok true --round1 false
```

A fresh run prepares its initial ciphertext/PoK outside the interaction timer.
The target sends that state, the monitor verifies it and returns the joint proof,
and the target verifies the reply. The target then rerandomizes either the
verified quotient on a match or the current polynomial on a nonmatch, generates
the disjunction proof, and replaces its local ciphertext/proof storage. The final
update is uploaded and verified by the monitor too.

Reports:

- **Interaction Latency** in s, from monitor computation start through target
  reply verification, update, disjunction-proof generation, and storage replacement.
- **Monitor Send** in MB, including ciphertexts, the Sigma–Bulletproof, the
  computation-start timestamp, and message framing.
- **New Storage (ciphertext + disjunction proof)** in MB, which becomes the
  target's next upload payload.
- **Communication (monitor send + next target payload)** in MB: the sum of those
  two quantities, excluding initial upload and the next target frame header.
- Generator-cache activity, with setup time in s.

The latency ends at the local storage update; the final update upload and the
monitor's OR-proof verification occur afterward. `round1=false` does not load a
previous process's state or bypass the initial proof.

### Nonmatch and proof-disabled examples

```sh
# Independent random query, expected not to match
cargo run --release -- exact 1000 false --pok true --round1 false

# Same update flow, without the target initial/OR proofs
cargo run --release -- exact 1000 true --pok false --round1 false

# Deployment without a target PoK; reported proof storage is zero
cargo run --release -- exact 1000 true --pok false --round1 true

# All defaults: exact deployment, degree 1000, target coefficient PoK enabled
cargo run --release -- exact
```

With `pok=false`, monitor proofs are still generated and verified during
interactions; target proof sizes are reported as zero. To run the built binary
directly instead of through Cargo:

```sh
./target/release/i-psi-ca exact 1000 true --pok true --round1 false
```

All exact durations and MB values use **four significant digits**, preserving
small nonzero values and trailing zeros. MB is decimal: **1 MB = 1,000,000 bytes**.
Storage counts canonical serialized ciphertext/proof payloads. Monitor send size
includes its four-byte frame header; new target storage excludes framing. Raw
byte counts remain available through the measurement structs. Session setup is
excluded. Storage is in memory, not a file on disk.

The monitor start timestamp is bound to its Sigma proof. The demo runs both roles
on the same host; separate hosts need synchronized clocks for the requested
monitor-start-to-target-storage interval. See the [measurement details](src/exact/README.md#round1-and-measurement-boundaries).

The CLI runs one interaction when `round1=false`, or one deployment when true.
There are no CLI options for a round count, address, port, key files, or JSON
configuration. Library users can configure both roles with
`ProtocolConfig { pok: true, round1: false }` and pass a round count to
`run(addr, rounds)`. Repeated matches remove one occurrence at a time.

## Bloom-filter variant

```text
cargo run --release -- bf [bloom_filter_size] [in_set] [accum_degree]
```

| Parameter | Meaning | Default |
|---|---|---|
| `bloom_filter_size` | Number of Bloom-filter positions | `1000` |
| `in_set` | Whether the query hashes to marked positions | `true` |
| `accum_degree` | Degree of the accumulator polynomial | `5` |

```sh
cargo run --release -- bf 1000 true 5
cargo run --release -- bf 1000 false 5
```

The number of hashes (`20`) and marked-position fraction (`50%`) are fixed by the
executable. BF supports up to **100,000 buckets**. Its target polynomial has
`bloom_filter_size + 1` coefficients. A security-constrained planner prefers one
ciphertext using N=16,384 or N=32,768; otherwise it minimizes padded slots and
proof dimension. For example, 20,000 buckets use one N=32,768 ciphertext, while
100,000 buckets use **7 N=16,384 ciphertexts**. At 1,000 buckets N remains
16,384 because the current modulus does not permit a smaller secure profile. The target alone holds the
non-threshold RLWE secret key. The accumulator still uses two-share ElGamal,
with verified root insertion and distinct-match counting.

Every report proves the item/index hash-weighted RLWE evaluation and its
consistency with the ElGamal accumulator at a hash of the same Bloom positions.
PKC 2019 proves bounded native ciphertext relations; Bulletproofs proves generic
arithmetic constraints, with complete-commitment links between them. Separate
range arguments, full Bloom-vector checks and exact-floor comparison proofs
are omitted; bounded rounding residuals ensure the claimed plaintext. The
complete proof is large and expensive; target ciphertext packing does not make
the proof logarithmic in communication. Circuit privacy assumes honest target
keys and freshly encrypted sources. See the [BF protocol guide](src/bf/RLWE.md)
for parameters, relations, costs and test commands. The `experimental-rlwe`
feature is enabled by default; `--no-default-features` builds only exact.
`pok` and `round1` remain exact-only options.

## Tests and exact microbenchmarks

```sh
cargo check
cargo test --release
cargo clippy --all-targets

# Exact correctness tests only
cargo test --release exact::

# Opt-in release microbenchmark, 32 and 128 roots
cargo test --release exact::benchmarks -- --ignored --nocapture --test-threads=1

# Also measure 1000 roots
EXACT_BENCH_LARGE=1 cargo test --release exact::benchmarks -- --ignored --nocapture --test-threads=1
```

Tests include real proofs and loopback TCP sessions. The microbenchmark is
ignored in ordinary test runs. It clears the public generator cache before each
initial/monitor proof phase and identifies first-call setup versus warm repeats
and verifiers. It measures proof operations, not end-to-end TCP latency. Library
and runtime measurements also expose cache activity; cached objects contain only
public generators, never secret witnesses, masks, or proof nonces.

The exact path uses a linear-size coefficient PoK, library Sigma/OR composition,
constant-time prover multiscalar multiplication with cached fixed-base tables,
public-scalar verifier MSM, shared public generators, and native ElGamal
operations. For 1000 roots, the
initial proof is **64,107 bytes** and the OR proof is **64,146 bytes**, including
proof-type tags. The framed ciphertext/OR update is **128,222 bytes**.
Details and historical timings are in the [exact guide](src/exact/README.md#optimizations-and-representative-measurements).

## Security and compatibility

This is an unaudited research prototype using experimental Bulletproof R1CS
support (`yoloproofs`). The exact proof/wire version is **v7**; peers reject
mismatched versions, `pok`, or `round1` choices. Proofs bind the session, round,
keys, statements, and commitments. Key provisioning is trusted by the application;
the TCP transport does not authenticate peer identities.

The initial proof establishes knowledge of the encrypted coefficients and their
encryption randomness. It does not prove factorization into known roots,
monicity, or equality to an externally registered set. The OR proof permits
either authenticated candidate; it does not enforce the target's private
match-dependent choice. The [exact guide](src/exact/README.md) describes these
assumptions and the quotient-blinding requirement.

## Layout

```text
src/
  main.rs                  positional CLI and one-process demo runner
  crypto/
    elgamal.rs             threshold ElGamal and polynomial operations
    poly.rs                plaintext polynomial from roots (Karatsuba product tree)
    bulletproof.rs         shared legacy arithmetic gadgets
    sigma.rs               shared legacy Sigma proofs
    sigma-bullet.rs        shared legacy Sigma/Bulletproof composition
  exact/
    mod.rs                 pok/round1 configuration and v7 session negotiation
    target.rs              target storage, interaction flow, serialization, timings
    monitor.rs             target-proof verification and monitor interaction flow
    proofs.rs              initial coefficient PoK and library OR composition
    division.rs            joint monitor Sigma–Bulletproof
    sigma.rs               dynamic Ristretto adapter for sigma_fun
    encryption.rs          ElGamal with explicit witness randomness, fixed-base tables
    measurements.rs        serialized storage and communication accounting
    performance.rs         public generator and fixed-base table caches
    benchmarks.rs          ignored release microbenchmark
    README.md              exact proof equations, measurements, and assumptions
  bf/
    bloom.rs               hashing and position sampling
    target.rs, monitor.rs, proof.rs
```
