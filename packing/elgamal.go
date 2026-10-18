package main

import (
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
	"time"
)

type curveCiphertext struct{ R, S kyber.Point }

func benchElGamal(coeffs []uint64, trials int) (result, error) {
	suite := suites.MustFind("Ed25519")
	stream := suite.RandomStream()
	x1 := suite.Scalar().Pick(stream)
	x2 := suite.Scalar().Pick(stream)
	X := suite.Point().Add(suite.Point().Mul(x1, nil), suite.Point().Mul(x2, nil))
	messages := make([]kyber.Point, len(coeffs))
	for i, c := range coeffs {
		messages[i] = suite.Point().Mul(suite.Scalar().SetInt64(int64(c)), nil)
	}
	samples := make([]time.Duration, trials)
	var cts []curveCiphertext
	for trial := range samples {
		start := time.Now()
		cts = make([]curveCiphertext, len(coeffs))
		for i := range coeffs {
			r := suite.Scalar().Pick(stream)
			cts[i] = curveCiphertext{suite.Point().Mul(r, nil), suite.Point().Add(messages[i], suite.Point().Mul(r, X))}
		}
		samples[trial] = time.Since(start)
	}
	recovered := make([]kyber.Point, len(cts))
	start := time.Now()
	for i, ct := range cts {
		d1 := suite.Point().Mul(x1, ct.R)
		d2 := suite.Point().Mul(x2, ct.R)
		recovered[i] = suite.Point().Sub(suite.Point().Sub(ct.S, d1), d2)
	}
	decrypt := time.Since(start)
	size := 0
	for i, ct := range cts {
		if !recovered[i].Equal(messages[i]) {
			return result{}, fmt.Errorf("coefficient %d verification failed", i)
		}
		r, err := ct.R.MarshalBinary()
		if err != nil {
			return result{}, err
		}
		s, err := ct.S.MarshalBinary()
		if err != nil {
			return result{}, err
		}
		size += len(r) + len(s)
	}
	return result{mode: "elgamal", roots: len(coeffs) - 1, ciphertexts: len(cts), bytes: size, latency: median(samples), decrypt: decrypt}, nil
}
