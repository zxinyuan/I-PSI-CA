# RLWE packing at 500,000 original items

Bloom degree: 4,792,530; coefficients: 4,792,531.

Three-trial whole-vector encryption medians, verified by decrypting every block.
Ciphertext bytes exclude keys and external protocol framing.

| Plan | Ciphertexts | Key contexts | Capacity | Size (MiB) | Encryption (ms) |
|---|---:|---:|---:|---:|---:|
| uniform_logN_11 | 2,341 | 1 | 4,794,368 | 73.8662 | 612.559 |
| uniform_logN_12 | 1,171 | 1 | 4,796,416 | 73.5426 | 590.898 |
| uniform_logN_13 | 586 | 1 | 4,800,512 | 73.4277 | 599.220 |
| uniform_logN_14 | 293 | 1 | 4,800,512 | 73.3389 | 600.410 |
| uniform_logN_15 | 147 | 1 | 4,816,896 | 73.5446 | 616.917 |
| uniform_logN_16 | 74 | 1 | 4,849,664 | 74.0224 | 639.788 |
| uniform_logN_17 | 37 | 1 | 4,849,664 | 74.0112 | 657.814 |
| uniform_logN_18 | 19 | 1 | 4,980,736 | 76.0058 | 699.131 |
| uniform_logN_19 | 10 | 1 | 5,242,880 | 80.0030 | 738.331 |
| uniform_logN_20 | 5 | 1 | 5,242,880 | 80.0015 | 769.555 |
| compact_mixed | 8 | 5 | 4,794,368 | 73.1587 | 694.300 |

Compact plan: 1048576 + 1048576 + 1048576 + 1048576 + 524288 + 65536 + 8192 + 2048.

Fastest measured candidate: uniform_logN_12. This is a comparison of these candidates, not a proof of global latency optimality.
The compact plan minimizes serialized ciphertext bytes within N=2048..2^20 when the vector exceeds one maximum ring.
Mixed dimensions require separate key contexts; no cross-ciphertext polynomial evaluation is benchmarked.
