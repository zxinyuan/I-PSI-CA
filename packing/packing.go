package main

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

const minPackingLogN = 11

// For oversized vectors, compactPackingPlan minimizes serialized bytes over the
// repository's supported dimensions. Round capacity to 2048, then use the fewest
// power-of-two blocks.
// For <=500k items, removing all block headers could not offset even one extra
// 2048-coefficient block (32768 bytes), so extra padding cannot improve the size.
// Preserve the previous single-ciphertext policy below the maximum dimension.
func compactPackingPlan(coefficients, maxLogN int) []int {
	maxN := 1 << maxLogN
	if coefficients <= maxN {
		return []int{max(1<<minPackingLogN, 1<<bits.Len(uint(coefficients-1)))}
	}
	remaining := (coefficients + (1 << minPackingLogN) - 1) >> minPackingLogN << minPackingLogN
	var plan []int
	for remaining > 0 {
		N := min(maxN, 1<<(bits.Len(uint(remaining))-1))
		plan = append(plan, N)
		remaining -= N
	}
	return plan
}

func uniformPackingPlan(coefficients, logN int) []int {
	N := 1 << logN
	plan := make([]int, (coefficients+N-1)/N)
	for i := range plan {
		plan[i] = N
	}
	return plan
}

// benchRLWEPacked encrypts consecutive slices of one coefficient vector. All
// chunks share a key per N. Setup/encoding remain outside the timer, which
// measures each complete encryption pass (not a sum of per-block medians).
func benchRLWEPacked(coeffs []uint64, trials int, plan []int) (result, error) {
	if len(coeffs) == 0 || trials < 1 || len(plan) == 0 {
		return result{}, fmt.Errorf("nonempty coefficients/plan and positive trials required")
	}
	type context struct {
		keys *thresholdKeys
		enc  *rlwe.Encryptor
	}
	contexts := make(map[int]context)
	pts := make([]*rlwe.Plaintext, len(plan))
	starts := make([]int, len(plan))
	ends := make([]int, len(plan))
	offset, largestN := 0, 0
	for i, N := range plan {
		if N < 1<<minPackingLogN || N > 1<<rlwe.MaxLogN || N&(N-1) != 0 || offset >= len(coeffs) {
			return result{}, fmt.Errorf("invalid or unused packing block %d: N=%d", i, N)
		}
		largestN = max(largestN, N)
		ctx, ok := contexts[N]
		if !ok {
			bp, err := latticeParameters(bits.Len(uint(N)) - 1)
			if err != nil {
				return result{}, err
			}
			p, err := rawParameters(bp)
			if err != nil {
				return result{}, err
			}
			keys, err := collectiveKeys(p)
			if err != nil {
				return result{}, err
			}
			ctx = context{keys, rlwe.NewEncryptor(p, keys.public)}
			contexts[N] = ctx
		}
		starts[i], ends[i] = offset, min(offset+N, len(coeffs))
		pts[i] = encodeRaw(ctx.keys.params, coeffs[starts[i]:ends[i]])
		offset = ends[i]
	}
	if offset != len(coeffs) {
		return result{}, fmt.Errorf("packing capacity covers %d of %d coefficients", offset, len(coeffs))
	}
	var cts []*rlwe.Ciphertext
	samples := make([]time.Duration, trials)
	for trial := range samples {
		start := time.Now()
		cts = make([]*rlwe.Ciphertext, len(plan))
		for i, N := range plan {
			var err error
			cts[i], err = contexts[N].enc.EncryptNew(pts[i])
			if err != nil {
				return result{}, err
			}
		}
		samples[trial] = time.Since(start)
	}
	var decrypt time.Duration
	size := 0
	for i, N := range plan {
		ctx := contexts[N]
		start := time.Now()
		pt, err := ctx.keys.decrypt(cts[i])
		decrypt += time.Since(start)
		if err != nil {
			return result{}, err
		}
		decoded := decodeRaw(ctx.keys.params, pt)
		for j, value := range decoded {
			var want uint64
			if starts[i]+j < ends[i] {
				want = coeffs[starts[i]+j]
			}
			if value != want {
				return result{}, fmt.Errorf("block %d coefficient %d: got %d want %d", i, j, value, want)
			}
		}
		data, err := cts[i].MarshalBinary()
		if err != nil {
			return result{}, err
		}
		size += len(data)
	}
	return result{mode: "rlwe", roots: len(coeffs) - 1, N: largestN, logN: bits.Len(uint(largestN)) - 1,
		ciphertexts: len(plan), bytes: size, latency: median(samples), decrypt: decrypt}, nil
}

type packingMeasurement struct {
	Name        string  `json:"name"`
	Plan        []int   `json:"ring_dimensions"`
	Ciphertexts int     `json:"ciphertexts"`
	KeyContexts int     `json:"key_contexts"`
	Capacity    int     `json:"coefficient_capacity"`
	Bytes       int     `json:"ciphertext_bytes"`
	LatencyMS   float64 `json:"encryption_ms"`
	DecryptMS   float64 `json:"threshold_decrypt_ms"`
}

func runPackingStudy(n, trials int, seed int64, path string) error {
	if n < 1 || n > maxComparisonItems || trials < 1 {
		return fmt.Errorf("packing study requires n in [1,%d] and trials >=1", maxComparisonItems)
	}
	coeffs := comparisonCoefficients(bloomDegree(n), seed)
	var measurements []packingMeasurement
	for logN := minPackingLogN; logN <= maxComparisonLogN+1; logN++ {
		name := fmt.Sprintf("uniform_logN_%d", logN)
		var plan []int
		if logN <= maxComparisonLogN {
			plan = uniformPackingPlan(len(coeffs), logN)
		} else {
			name = "compact_mixed"
			plan = compactPackingPlan(len(coeffs), maxComparisonLogN)
		}
		fmt.Printf("items=%d plan=%s ciphertexts=%d phase=benchmark\n", n, name, len(plan))
		r, err := benchRLWEPacked(coeffs, trials, plan)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		capacity, unique := 0, map[int]bool{}
		for _, N := range plan {
			capacity += N
			unique[N] = true
		}
		measurement := packingMeasurement{name, plan, r.ciphertexts, len(unique), capacity, r.bytes,
			float64(r.latency) / float64(time.Millisecond), float64(r.decrypt) / float64(time.Millisecond)}
		measurements = append(measurements, measurement)
		fmt.Printf("plan=%s ciphertexts=%d capacity=%d bytes=%d latency_ms=%.3f verify=PASS\n", name, r.ciphertexts, capacity, r.bytes, measurement.LatencyMS)
	}
	data, err := json.MarshalIndent(struct {
		Items        int                  `json:"items"`
		Degree       int                  `json:"bloom_degree"`
		Coefficients int                  `json:"coefficients"`
		FPR          float64              `json:"bloom_fpr"`
		Trials       int                  `json:"trials"`
		Seed         int64                `json:"seed"`
		MaxLogN      int                  `json:"library_max_logN"`
		Results      []packingMeasurement `json:"results"`
	}{n, len(coeffs) - 1, len(coeffs), bloomFPR, trials, seed, rlwe.MaxLogN, measurements}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}
