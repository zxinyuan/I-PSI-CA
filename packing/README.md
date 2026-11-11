# Polynomial encryption benchmark

## Exact set vs Bloom packing sweep

```sh
go run . --compare --trials 5 --out results/packing-comparison-three.csv
MPLCONFIGDIR=/tmp/packing-matplotlib python3 plot_comparison.py
```

The three-curve figures were generated with this shorter sweep, covering every
ring dimension and the full supported item-count range:

```sh
go run . --compare --trials 3 --sizes 1,10,100,214,500,855,1000,1710,3419,5000,6838,13674,13675,50000,100000,500000 --out results/packing-comparison-three.csv
MPLCONFIGDIR=/tmp/packing-matplotlib python3 plot_comparison.py results/packing-comparison-three.csv
```

All three curves use measured encryption times and serialized bytes. BF
ElGamal at the largest sizes is expensive; the full default sweep takes longer.
The comparison supports 1..500,000 original items and ring dimensions through
N=1048576 (logN=20). Lattigo v6.2.0 declares `core/rlwe.MaxLogN = 20` and
rejects larger logN; this is a library limit, not a universal RLWE limit.
Below that capacity, the sweep retains the single-ciphertext policy. Larger
vectors are split into consecutive coefficient chunks. Under this Bloom sizing
formula, n=109,396 is the last original set size that fits one ciphertext;
n=109,397 requires multiple ciphertexts. At n=500,000, the
Bloom degree is 4,792,530 and there are 4,792,531 coefficients.
Ordinary root-polynomial CLI runs retain their
existing degree and ring-dimension limits. The extended figure reuses the
original 12 measurements and adds three-trial measurements at n=13,675,
n=50,000, n=100,000, and n=500,000. The last point is measured directly for all
three schemes, including ElGamal; it is not a linear extrapolation.
The 100,000-item extension is also saved separately in
`results/packing-comparison-100k.csv`; it can be reproduced with
`go run . --compare --trials 3 --sizes 100000 --out results/packing-comparison-100k.csv`.
The 500k measurements are saved in `results/packing-comparison-500k.csv`.
ElGamal reports progress within long trials; time spent printing is subtracted
from encryption and decryption timers. Progress polling overhead remains in
the measurements. All coefficients are still verified.
In the latency graph, RLWE squares show individual measured set sizes. Its
solid guide sums measured single-ring median times for the blocks needed at
each item count. For mixed plans, this is a cost estimate rather than a new
whole-vector measurement. Squares show measured whole-vector times, including
the complete sequential encryption pass over all ciphertexts. Timing noise
and deviations from the additive model remain visible in the markers.

### Packing after the single-ciphertext limit

```sh
go run . --packing-study --n 500000 --trials 3 --out results/packing-study-500k.json
go run . --compare --trials 3 --sizes 500000 --out results/packing-comparison-500k.csv
```

The study measures every uniform dimension N=2048..2^20 and a compact mixed-size
plan. Each three-trial median measures an entire coefficient vector; it is not
a sum of independently measured block medians. Decryption checks include all
blocks and padding. Ciphertext sizes are sums of actual serialized payloads.

The graph uses a byte-minimal plan after the ring limit: round total capacity
up to a multiple of 2048, then decompose it into the fewest allowed powers of
two. At 500k this is four N=1048576 blocks, followed by N=524288, 65536, 8192,
and 2048: eight ciphertexts, capacity 4,794,368, only 1,837 padded coefficients,
and 76,712,432 serialized bytes. A five-ciphertext plan at N=2^20 minimizes
the ciphertext count but uses 83,887,670 bytes because it pads the final block
to a full ring. The independently tested planner minimizes ciphertext bytes
within the supported dimensions; minimum count and minimum latency are
different objectives. The study reports the fastest measured candidate too.

Mixed dimensions require separate key contexts (five for the compact plan).
Setup and key bytes are excluded, as in the original benchmark; adding key
traffic could change the communication tradeoff. This only benchmarks encrypted
coefficient transport and reassembly, not evaluation across different rings.
The study JSON and generated `results/packing-study-500k.md` contain all plans,
counts, capacities, serialized sizes, and measured latencies.

Requires matplotlib for plotting. The new `comparison.go` reuses
`benchElGamal` and `benchLattice("rlwe", ...)`, including decryption checks
and actual serialization. It produces measurements for logarithmically spaced
set sizes and adjacent sizes around every single-ring boundary, up to 500,000
original items. The plotter writes `results/packing-latency.png`,
`results/packing-ciphertext-size.png`, and a text report of advantage transitions.
Both pictures contain `Exact (ElGamal)`, `BF (ElGamal)`, and `BF (RLWE)`;
their horizontal axis is the
original item count, not the expanded Bloom degree.

Exact sets use degree n and n+1 independently encrypted ElGamal coefficients.
Bloom sizing uses m=ceil(-n ln(0.01)/ln(2)^2), giving m=959 for n=100;
the requested Bloom polynomial has degree m and m+1 coefficients, encrypted as
m+1 separate ciphertexts for `BF (ElGamal)`, or packed into RLWE ciphertexts
under the policy described above for `BF (RLWE)`.
This is the standard optimal-hash sizing approximation; rounding the hash count
in an actual Bloom implementation may require slightly more bits for a strict
1% upper bound. An RLWE dimension increase can temporarily reverse a size
advantage, so the report lists all intervals rather than assuming one crossover.

This sweep measures encryption on reproducible **synthetic monic coefficient
vectors of the specified degrees**, not constructed root polynomials or a
working Bloom membership protocol. It isolates packing costs without the
existing quadratic polynomial construction dominating the sweep runtime.
The measured latency excludes setup, encoding, polynomial/Bloom construction,
serialization, verification, decryption, and networking. Ciphertext sizes include
serialized ciphertexts only. Latency transitions are brackets between measured
points, not exact thresholds; rerun on the target hardware for a decision.
Communication intervals use measured bytes per ring dimension and the checked
64-byte ElGamal coefficient size at every integer n in the swept range.
With this repository's serialization, RLWE stores two N-coefficient polynomials
as 64-bit words (16N+318 bytes per ciphertext). Total ring capacity must cover
m+1 coefficients, and m is approximately 9.585n, so its asymptotic payload lower bound is about 2.40
times ElGamal's 64(n+1) bytes even before power-of-two padding. Thus a
communication saving against the exact-set baseline is not expected under these parameters; the sweep checks
that prediction rather than presuming a crossover exists.

The existing field Z_65537 cannot represent more than 65537 distinct item or
position roots. This limitation also applies to the larger exact-set
curve. Larger-degree measurements remain valid packing cost experiments but
do not establish distinct-root set semantics. The existing parameter choices
also do not establish equal security between ElGamal and RLWE. The sweep stops
at 500,000 original items and does not extrapolate beyond it.

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
