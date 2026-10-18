# Polynomial encryption benchmark

Requires Go 1.25 or newer. Dependencies are pinned to Lattigo v6.2.0 and
Kyber v4.0.1.

```sh
go test ./...
go run . --n 1000 --mode elgamal
go run . --n 1000 --mode rlwe
go run . --n 1000 --mode bfv
go run . --n 1000 --mode all
go run . --n 5000 --mode all
```

`--n` and `--mode` are required. `--trials` defaults to 5 and `--seed` to 1.
Roots are reproducible elements of Z_65537; cryptographic randomness is fresh
and independent of the root seed. Polynomial construction is quadratic in n.
Supported roots: 1..131071; lattice dimensions: 2048..131072 (logN 11..17).
This is a repository test limit; Lattigo supports logN up to 20.
For 95935 roots, both lattice modes use N=131072 and logN=17.

Each successful mode prints one line ending in `verify=PASS`. Encryption
latency is the median of all trials, with no discarded trials. The measured
interval contains ciphertext generation only, including its allocations;
message encoding, setup, serialization, decryption, and verification are
outside it. Threshold decryption is measured separately once, on the last
ciphertext, including share generation, aggregation, key switching, and
zero-key decryption (or curve partial decryptions and their combination).
Decoding and correctness comparisons are outside that timer.
`ciphertext_kb` uses **1024-byte KB**, measured from actual serialized payloads.
The CLI sets GOMAXPROCS to 1.

ElGamal encrypts each coefficient as an Ed25519 group element with two
independent secret shares. It verifies group elements without discrete logs.
Plain RLWE uses core/rlwe directly with Delta=floor(Q/65537) coefficient
encoding and centered scale-and-round decoding. Both lattice modes use the
same Q, ring dimension, secret distribution, and error distribution, with
one approximately 50-bit prime and no auxiliary modulus chain or evaluation
keys. They use native multiparty collective public-key generation and
collective key switching from the two secret shares to zero. The joint
secret is never reconstructed.

## Lattigo v6.2.0 BFV API

The requested `schemes/bfv` directory in v6.2.0 has no Go package: its README
states that BFV is implemented in the unified `schemes/bgv` package. This
benchmark uses that official implementation for `bfv`, with
`IsBatched=false` and its normal encoder/decoder. The BFV scale-invariant
flag belongs to the evaluator and changes multiplication/rescaling only;
this encryption-only benchmark needs no evaluator. Plain RLWE does not use
that encoder. See the dependency's `schemes/bfv/README.md` for details.

The parameters are a computation/storage comparison, not a certified
security parameter set or a production threshold service. Both parties run
locally; no networking is included.
