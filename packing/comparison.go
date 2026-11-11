package main

// Encryption-only degree sweep. Reuses the verified encryption and serialization
// benchmarks; synthetic monic coefficient vectors avoid quadratic preprocessing.
import (
	"encoding/csv"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const bloomFPR = 0.01

// The encryption-only sweep can use larger rings without quadratic root
// construction. Ordinary --n runs retain their existing logN=17 limit.
const maxComparisonLogN = 20
const maxComparisonItems = 500000

// Standard optimal-hash Bloom sizing: ceil(-n ln(p) / ln(2)^2).
// The degree is m, as requested, so packing requires m+1 coefficients.
func bloomDegree(n int) int {
	return int(math.Ceil(-float64(n) * math.Log(bloomFPR) / (math.Ln2 * math.Ln2)))
}

func comparisonSizes() []int {
	maxItems := maxComparisonItems
	points := map[int]bool{1: true, 10: true, 100: true, maxItems: true}
	for x := 2.0; int(x) <= maxItems; x *= 1.6 {
		points[int(x)] = true
	}
	// Resolve each discontinuity on both sides instead of interpolating across it.
	for N := 2048; N <= 1<<maxComparisonLogN; N *= 2 {
		n := int(float64(N-1) * math.Ln2 * math.Ln2 / -math.Log(bloomFPR))
		for _, v := range []int{n - 1, n, n + 1, n + 2} {
			if v > 0 && v <= maxItems {
				points[v] = true
			}
		}
	}
	for capacity := 2 << maxComparisonLogN; capacity < bloomDegree(maxItems)+1; capacity += 1 << maxComparisonLogN {
		n := int(float64(capacity-1) * math.Ln2 * math.Ln2 / -math.Log(bloomFPR))
		for _, v := range []int{n - 1, n, n + 1, n + 2} {
			if v > 0 && v <= maxItems {
				points[v] = true
			}
		}
	}
	values := make([]int, 0, len(points))
	for n := range points {
		values = append(values, n)
	}
	sort.Ints(values)
	return values
}

func comparisonCoefficients(degree int, seed int64) []uint64 {
	rng := rand.New(rand.NewSource(seed))
	coeffs := make([]uint64, degree+1)
	for i := range coeffs {
		coeffs[i] = uint64(rng.Int63n(int64(plaintextModulus)))
	}
	coeffs[degree] = 1
	return coeffs
}

func comparePacking(path string, trials int, seed int64, sizes string) error {
	if trials < 1 {
		return fmt.Errorf("trials must be >= 1")
	}
	points := comparisonSizes()
	maxItems := points[len(points)-1]
	if sizes != "" {
		points = nil
		for _, value := range strings.Split(sizes, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 1 || n > maxItems {
				return fmt.Errorf("invalid comparison item count %q", value)
			}
			points = append(points, n)
		}
		sort.Ints(points)
		for i := 1; i < len(points); i++ {
			if points[i] == points[i-1] {
				return fmt.Errorf("duplicate comparison item count %d", points[i])
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	defer f.Close()
	if err := w.Write([]string{"items", "bloom_fpr", "bloom_degree", "rlwe_N", "exact_ms", "bloom_ms", "exact_bytes", "bloom_bytes", "trials", "seed", "coefficients", "bloom_elgamal_ms", "bloom_elgamal_bytes", "rlwe_plan", "rlwe_ciphertexts"}); err != nil {
		return err
	}
	for _, n := range points {
		m := bloomDegree(n)
		fmt.Printf("items=%d phase=exact_elgamal coeffs=%d\n", n, n+1)
		exact, err := benchElGamalWithProgress(comparisonCoefficients(n, seed), trials, func(status string) {
			fmt.Printf("items=%d phase=exact_elgamal %s\n", n, status)
		})
		if err != nil {
			return fmt.Errorf("exact n=%d: %w", n, err)
		}
		bloomCoeffs := comparisonCoefficients(m, seed)
		fmt.Printf("items=%d phase=bf_elgamal coeffs=%d\n", n, m+1)
		bloomElGamal, err := benchElGamalWithProgress(bloomCoeffs, trials, func(status string) {
			fmt.Printf("items=%d phase=bf_elgamal %s\n", n, status)
		})
		if err != nil {
			return fmt.Errorf("Bloom ElGamal n=%d: %w", n, err)
		}
		fmt.Printf("items=%d phase=bf_rlwe coeffs=%d\n", n, m+1)
		plan := compactPackingPlan(len(bloomCoeffs), maxComparisonLogN)
		var bloom result
		if len(plan) == 1 {
			bloom, err = benchLatticeWithLimit("rlwe", bloomCoeffs, trials, maxComparisonLogN)
		} else {
			bloom, err = benchRLWEPacked(bloomCoeffs, trials, plan)
		}
		if err != nil {
			return fmt.Errorf("Bloom n=%d: %w", n, err)
		}
		row := []string{strconv.Itoa(n), "0.01", strconv.Itoa(m), strconv.Itoa(bloom.N),
			fmt.Sprintf("%.6f", float64(exact.latency)/float64(time.Millisecond)),
			fmt.Sprintf("%.6f", float64(bloom.latency)/float64(time.Millisecond)),
			strconv.Itoa(exact.bytes), strconv.Itoa(bloom.bytes), strconv.Itoa(trials), strconv.FormatInt(seed, 10), "synthetic-monic",
			fmt.Sprintf("%.6f", float64(bloomElGamal.latency)/float64(time.Millisecond)), strconv.Itoa(bloomElGamal.bytes)}
		planText := make([]string, len(plan))
		for i, N := range plan {
			planText[i] = strconv.Itoa(N)
		}
		row = append(row, strings.Join(planText, ":"), strconv.Itoa(bloom.ciphertexts))
		if err := w.Write(row); err != nil {
			return err
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return err
		}
		fmt.Printf("items=%d bloom_degree=%d N=%d exact_ms=%s bf_elgamal_ms=%s bf_rlwe_ms=%s exact_bytes=%d bf_elgamal_bytes=%d bf_rlwe_bytes=%d verify=PASS\n", n, m, bloom.N, row[4], row[11], row[5], exact.bytes, bloomElGamal.bytes, bloom.bytes)
	}
	return f.Close()
}
