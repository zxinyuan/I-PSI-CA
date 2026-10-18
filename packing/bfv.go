package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func encodeBFV(p bgv.Parameters, coeffs []uint64) (*rlwe.Plaintext, error) {
	pt := bgv.NewPlaintext(p, p.MaxLevel())
	pt.IsBatched = false
	return pt, bgv.NewEncoder(p).Encode(coeffs, pt)
}
func decodeBFV(p bgv.Parameters, pt *rlwe.Plaintext) ([]uint64, error) {
	pt.IsBatched = false
	out := make([]uint64, p.N())
	return out, bgv.NewEncoder(p).Decode(pt, out)
}
