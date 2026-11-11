package main

import (
	"fmt"
	"math/rand"
)

const plaintextModulus uint64 = 65537

// Keep an explicit tested limit; Lattigo itself supports up to logN=20.
const maxSupportedLogN = 17
const maxRoots = (1 << maxSupportedLogN) - 1

func rootsFromSeed(n int, seed int64) []uint64 {
	rng := rand.New(rand.NewSource(seed))
	roots := make([]uint64, n)
	for i := range roots {
		roots[i] = uint64(rng.Int63n(int64(plaintextModulus)))
	}
	return roots
}
func polynomialFromRoots(roots []uint64) []uint64 {
	p := []uint64{1}
	for _, r := range roots {
		next := make([]uint64, len(p)+1)
		for j, c := range p {
			next[j] = (next[j] + plaintextModulus - (r*c)%plaintextModulus) % plaintextModulus
			next[j+1] = (next[j+1] + c) % plaintextModulus
		}
		p = next
	}
	return p
}
func ringDimension(n int) (N, logN int, err error) {
	return ringDimensionWithLimit(n, maxSupportedLogN)
}

func ringDimensionWithLimit(n, maxLogN int) (N, logN int, err error) {
	limit := (1 << maxLogN) - 1
	if n < 1 || n > limit {
		return 0, 0, fmt.Errorf("roots must be in [1, %d] (supported logN: 11..%d)", limit, maxLogN)
	}
	N, logN = 2048, 11
	for N < n+1 {
		N *= 2
		logN++
	}
	return
}
