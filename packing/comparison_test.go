package main

import (
	"runtime"
	"testing"
)

func TestComparisonSizing(t *testing.T) {
	if m := bloomDegree(100); m != 959 {
		t.Fatalf("100 items: got degree %d, want 959", m)
	}
	points := comparisonSizes()
	seen := make(map[int]bool)
	for i, n := range points {
		if i > 0 && n <= points[i-1] {
			t.Fatal("sample sizes must be strictly increasing")
		}
		seen[n] = true
		plan := compactPackingPlan(bloomDegree(n)+1, maxComparisonLogN)
		capacity := 0
		for _, N := range plan {
			if N < 2048 || N > 1<<maxComparisonLogN || N&(N-1) != 0 {
				t.Fatalf("invalid Bloom packing block for n=%d: %d", n, N)
			}
			capacity += N
		}
		if capacity < bloomDegree(n)+1 {
			t.Fatalf("insufficient Bloom packing capacity for n=%d", n)
		}
	}
	// Every ring jump must have adjacent integer samples on both sides.
	for n := 2; n <= min(points[len(points)-1], 100000); n++ {
		a, _, _ := ringDimensionWithLimit(bloomDegree(n-1), maxComparisonLogN)
		b, _, _ := ringDimensionWithLimit(bloomDegree(n), maxComparisonLogN)
		if a != b && (!seen[n-1] || !seen[n]) {
			t.Fatalf("missing packing boundary samples %d, %d", n-1, n)
		}
	}
}

func TestExtendedComparisonRLWE(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	for _, tc := range []struct{ items, degree, N int }{{50000, 479253, 524288}, {100000, 958506, 1048576}} {
		degree := bloomDegree(tc.items)
		if degree != tc.degree {
			t.Fatalf("n=%d: unexpected degree: %d", tc.items, degree)
		}
		r, err := benchLatticeWithLimit("rlwe", comparisonCoefficients(degree, 1), 1, maxComparisonLogN)
		if err != nil {
			t.Fatal(err)
		}
		if r.N != tc.N || r.ciphertexts != 1 || r.bytes != 16*r.N+318 {
			t.Fatalf("n=%d: unexpected extended packing result: %+v", tc.items, r)
		}
	}
}
