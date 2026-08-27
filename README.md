# i-psi-ca

A Rust implementation of an interactive private-set-intersection-cardinality (I-PSI-CA) protocol between two roles, **Scribe** and **Lookout**, built on threshold ElGamal encryption over Ristretto255 and Bulletproofs R1CS zero-knowledge proofs.

The Scribe holds a private set and outsources an encrypted encoding of it to the Lookout. The Lookout holds a private query element, homomorphically evaluates it against the Scribe's encrypted set, and returns a partially-decrypted result together with a zero-knowledge proof that the evaluation was computed correctly. The Scribe verifies the proof and locally learns only whether the query matched — the Lookout never learns the Scribe's set, and the Scribe never learns the Lookout's query.

Two matching variants are implemented, selected via the CLI:

| Variant | Match rule | Set encoding |
|---|---|---|
| `exact` | Query equals a set element | Roots of an encrypted polynomial over the set elements |
| `bf` | Query hashes (via `k` hash functions) to positions that are all marked in a Bloom filter | Roots of an encrypted polynomial over *every* Bloom-filter position |

Both variants share the same round structure: an accumulator polynomial is also evaluated and updated every round, letting the Scribe track a running match count across repeated rounds without the Lookout learning which round(s) matched.

## Requirements

- Rust and Cargo — this crate targets edition 2021 and was developed against `rustc 1.81.0`. Any reasonably recent stable toolchain should work; no nightly features are used.
- No system dependencies beyond a standard Rust toolchain — all cryptography (curve arithmetic, Bulletproofs, ElGamal) is pure-Rust via crates.io (`curve25519-dalek-ng`, `bulletproofs`, `merlin`).

## Build

```sh
git clone <this-repo>
cd i-psi-ca
cargo build --release
```

Always use `--release` when actually running a protocol round — the Bulletproofs R1CS proofs involved are computationally heavy, and a debug build is 10-50x slower.

## Run

There is one binary. It spins up a Scribe (TCP server) and a Lookout (TCP client) as two threads in the same process, connected over `127.0.0.1:7878`, and drives one protocol round end to end, printing timing and network-traffic measurements to stdout/stderr.

```sh
cargo run --release -- <protocol> [args...]
```

`<protocol>` is one of `exact` or `bf`. If omitted, it defaults to `exact`. Each variant takes its own positional arguments, described below; any trailing argument can be omitted to fall back to its default.

### `exact`

```
cargo run --release -- exact [degree] [in_set] [accum_degree]
```

| Position | Meaning | Default |
|---|---|---|
| `degree` | Size of the Scribe's set `TSet` (count of uniformly random field elements) | `1000` |
| `in_set` | `true`/`false` — whether the Lookout's query is drawn from `TSet` (match) or is an independent random element (no match) | `true` |
| `accum_degree` | Degree of the accumulator polynomial carried across rounds | `5` |

Examples:

```sh
cargo run --release -- exact 1000 true      # degree 1000, expect a match
cargo run --release -- exact 1000 false     # degree 1000, expect no match
cargo run --release -- exact 1000 true 8    # accum_degree = 8
```

### `bf` (Bloom filter)

```
cargo run --release -- bf [bloom_filter_size] [in_set] [accum_degree]
```

| Position | Meaning | Default |
|---|---|---|
| `bloom_filter_size` (`n`) | Number of positions in the Bloom filter | `1000` |
| `in_set` | `true`/`false` — whether the Lookout's query hashes to marked positions | `true` |
| `accum_degree` | Degree of the accumulator polynomial | `5` |

The number of hash functions (`k = 20`) and the fraction of positions marked (`50%` of `bloom_filter_size`) are fixed internally, not CLI-configurable. Every position in the Bloom filter — marked or not — is encrypted into the Scribe's outsourced polynomial (`TPolyCtext`), so its size is always `bloom_filter_size + 1` ciphertexts regardless of how many positions are actually marked.

Because the encrypted polynomial spans the entire filter, the underlying R1CS circuit has on the order of `k * (bloom_filter_size + 1)` multiplication gates — cost scales with `bloom_filter_size`, not with the marked-position count. Sizes above a few tens of thousands will take minutes per round; see the timing figures gathered in this repo's benchmarking notes for concrete numbers.

Examples:

```sh
cargo run --release -- bf 1000 true       # 1000 positions, expect a match
cargo run --release -- bf 1000 false      # 1000 positions, expect no match
cargo run --release -- bf 1000 true 8     # accum_degree = 8
```

### Reading the output

Each run prints, from both the Scribe's and Lookout's perspective:

- **Deploy time** — Scribe's time to build and encrypt its outsourced polynomial (and the initial accumulator), up to the first send.
- **Latency** — wall-clock time from the Scribe sending its round message to receiving the Lookout's full reply (network round trip + the Lookout's proof computation). This dominates total round time for larger inputs.
- **Verification time** — Scribe's time to verify the Lookout's round proof.
- **Network traffic** — bytes sent in each direction (Scribe→Lookout and Lookout→Scribe), reported in KB.
- **match** — whether the Scribe's local zero-test on the (partially decrypted) result was zero, i.e., a genuine match.

## Test

```sh
cargo test --release
```

The release flag matters here too — several tests build real Bulletproofs and are painfully slow in debug mode. Both protocol variants have unit tests covering both the match and no-match cases, proof-rejection tests for tampered inputs, and standalone tests for the underlying primitives (`crypto/elgamal.rs`, `crypto/sigma.rs`, `crypto/sigma-bullet.rs`, `crypto/bulletproof.rs`).

## Layout

```
src/
  main.rs              CLI entry point; wires up Scribe + Lookout for a single demo round
  lib.rs                crate root, re-exports the modules below
  crypto/
    elgamal.rs          threshold ElGamal: key generation, encryption, homomorphic ops, partial decryption
    bulletproof.rs       Bulletproofs-based polynomial evaluation-chain proof (used by the accumulator)
    sigma.rs             Sigma-protocol proofs (partial decryption, poly-scalar-mul)
    sigma-bullet.rs      the Sigma/Bulletproof "glue" proof binding a committed evaluation chain to a ciphertext
  exact/
    target.rs, monitor.rs   exact-match variant
  bf/
    bloom.rs             Bloom-filter hashing and position sampling
    target.rs, monitor.rs, proof.rs   Bloom-filter variant and its round proof
```

Each variant's `target.rs` and `monitor.rs` implement the TCP framing and the two roles' round logic; `bf/proof.rs` holds the round's zero-knowledge proof construction and verification (the `exact` variant's proof logic lives inline in `exact/monitor.rs` / `exact/target.rs`).
