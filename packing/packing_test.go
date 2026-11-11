package main

import (
	"runtime"
	"testing"
)

func TestCompactPacking(t *testing.T) {
	coefficients := bloomDegree(500000) + 1
	plan := compactPackingPlan(coefficients, maxComparisonLogN)
	capacity := 0
	for _, N := range plan {
		capacity += N
	}
	if coefficients != 4792531 || len(plan) != 8 || capacity != 4794368 {
		t.Fatalf("unexpected packing: coefficients=%d plan=%v capacity=%d", coefficients, plan, capacity)
	}
	// Independent unbounded-knapsack check: optimize actual bytes over all
	// capacities up to one extra maximum ring, rather than just checking the
	// greedy decomposition against itself.
	minimumUnits := (coefficients + 2047) / 2048
	limit := minimumUnits + (1<<maxComparisonLogN)/2048
	cost := make([]int, limit+1)
	for capacity := 1; capacity <= limit; capacity++ {
		cost[capacity] = int(^uint(0) >> 1)
		for units := 1; units <= 512 && units <= capacity; units *= 2 {
			candidate := cost[capacity-units] + 16*2048*units + 318
			if candidate < cost[capacity] {
				cost[capacity] = candidate
			}
		}
	}
	got := 16*capacity + 318*len(plan)
	for units := minimumUnits; units <= limit; units++ {
		if cost[units] < got {
			t.Fatalf("plan uses %d bytes but capacity %d permits %d", got, units*2048, cost[units])
		}
	}
}

func TestPackedRLWEChunkBoundaries(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	for _, length := range []int{4097, 8192, 8193} {
		coeffs := comparisonCoefficients(length-1, 1)
		plan := compactPackingPlan(length, 12)
		r, err := benchRLWEPacked(coeffs, 1, plan)
		if err != nil {
			t.Fatal(err)
		}
		capacity := 0
		for _, N := range plan {
			capacity += N
		}
		if r.ciphertexts != len(plan) || r.bytes != 16*capacity+318*len(plan) {
			t.Fatalf("unexpected aggregate result: %+v", r)
		}
	}
	if _, err := benchRLWEPacked(make([]uint64, 4097), 1, []int{4096}); err == nil {
		t.Fatal("accepted insufficient capacity")
	}
}
