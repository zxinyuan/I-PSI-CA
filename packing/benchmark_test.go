package main

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestCorrectness(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	for _, n := range []int{1, 10, 100, 1000, 2000, 5000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			roots := rootsFromSeed(n, 1)
			coeffs := polynomialFromRoots(roots)
			if len(coeffs) != n+1 || coeffs[n] != 1 {
				t.Fatal("incorrect degree or leading coefficient")
			}
			for _, r := range roots {
				var value uint64
				for j := n; j >= 0; j-- {
					value = (value*r + coeffs[j]) % plaintextModulus
				}
				if value != 0 {
					t.Fatalf("root %d evaluates to %d", r, value)
				}
			}
			N, _, err := ringDimension(n)
			if err != nil || N < n+1 || N&(N-1) != 0 {
				t.Fatal("invalid packing dimension")
			}
			for _, mode := range []string{"elgamal", "rlwe", "bfv"} {
				t.Run(mode, func(t *testing.T) {
					var r result
					var err error
					if mode == "elgamal" {
						r, err = benchElGamal(coeffs, 1)
					} else {
						r, err = benchLattice(mode, coeffs, 1)
					}
					if err != nil {
						t.Fatal(err)
					}
					if r.bytes <= 0 {
						t.Fatal("empty serialization")
					}
					if mode != "elgamal" && r.N != N {
						t.Fatal("wrong ring dimension")
					}
				})
			}
		})
	}
}
func TestRingDimension(t *testing.T) {
	for _, tc := range []struct{ n, N, logN int }{{1, 2048, 11}, {2047, 2048, 11}, {2048, 4096, 12}, {5000, 8192, 13}, {12800, 16384, 14}, {65535, 65536, 16}, {65536, 131072, 17}, {95935, 131072, 17}, {131071, 131072, 17}} {
		N, l, err := ringDimension(tc.n)
		if err != nil || N != tc.N || l != tc.logN {
			t.Fatalf("n=%d: %d %d %v", tc.n, N, l, err)
		}
	}
	for _, n := range []int{-1, 0, 131072} {
		if _, _, err := ringDimension(n); err == nil {
			t.Fatalf("accepted %d", n)
		}
	}
}
func TestRawWraparound(t *testing.T) {
	bp, err := latticeParameters(11)
	if err != nil {
		t.Fatal(err)
	}
	p, err := rawParameters(bp)
	if err != nil {
		t.Fatal(err)
	}
	pt := encodeRaw(p, []uint64{0, 1, 32768, 32769, 65536})
	q := p.Q()[0]
	pt.Value.Coeffs[0][0] = q - 100
	got := decodeRaw(p, pt)
	for i, want := range []uint64{0, 1, 32768, 32769, 65536} {
		if got[i] != want {
			t.Fatalf("%d: got %d want %d", i, got[i], want)
		}
	}
}
func TestMedian(t *testing.T) {
	if median([]time.Duration{9, 1, 3}) != 3 || median([]time.Duration{9, 1, 3, 5}) != 4 {
		t.Fatal("incorrect median")
	}
}

// Exercise logN=17 without quadratic root construction in every test run.
func TestLargeLatticePacking(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	coeffs := make([]uint64, 95936)
	for i := range coeffs {
		coeffs[i] = uint64(i) % plaintextModulus
	}
	coeffs[len(coeffs)-1] = 1
	for _, mode := range []string{"rlwe", "bfv"} {
		t.Run(mode, func(t *testing.T) {
			r, err := benchLattice(mode, coeffs, 1)
			if err != nil {
				t.Fatal(err)
			}
			if r.N != 131072 || r.logN != 17 || r.ciphertexts != 1 || r.bytes == 0 {
				t.Fatalf("unexpected result: %+v", r)
			}
		})
	}
}
