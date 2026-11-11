package main

import (
	"fmt"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
	"time"
)

type curveCiphertext struct{ R, S kyber.Point }

func benchElGamal(coeffs []uint64, trials int) (result, error) {
	return benchElGamalWithProgress(coeffs, trials, nil)
}

// Progress printing time is subtracted from measured intervals. The encryption
// and complete coefficient verification work are identical to benchElGamal.
func benchElGamalWithProgress(coeffs []uint64, trials int, progress func(string)) (result, error) {
	lastProgress := time.Now()
	report := func(stage string, completed int) time.Duration {
		if progress == nil || completed%16384 != 0 || time.Since(lastProgress) < 40*time.Second {
			return 0
		}
		start := time.Now()
		progress(fmt.Sprintf("stage=%s completed=%d/%d", stage, completed, len(coeffs)))
		lastProgress = time.Now()
		return time.Since(start)
	}
	suite := suites.MustFind("Ed25519")
	stream := suite.RandomStream()
	x1 := suite.Scalar().Pick(stream)
	x2 := suite.Scalar().Pick(stream)
	X := suite.Point().Add(suite.Point().Mul(x1, nil), suite.Point().Mul(x2, nil))
	messages := make([]kyber.Point, len(coeffs))
	for i, c := range coeffs {
		messages[i] = suite.Point().Mul(suite.Scalar().SetInt64(int64(c)), nil)
		report("encoding", i+1)
	}
	samples := make([]time.Duration, trials)
	var cts []curveCiphertext
	for trial := range samples {
		stage := fmt.Sprintf("encrypt_trial_%d", trial+1)
		var printing time.Duration
		start := time.Now()
		cts = make([]curveCiphertext, len(coeffs))
		for i := range coeffs {
			r := suite.Scalar().Pick(stream)
			cts[i] = curveCiphertext{suite.Point().Mul(r, nil), suite.Point().Add(messages[i], suite.Point().Mul(r, X))}
			printing += report(stage, i+1)
		}
		samples[trial] = time.Since(start) - printing
		if progress != nil {
			progress(fmt.Sprintf("trial=%d/%d latency_ms=%.3f", trial+1, trials, float64(samples[trial])/float64(time.Millisecond)))
		}
	}
	if progress != nil {
		progress("threshold_decrypt_and_verify")
	}
	recovered := make([]kyber.Point, len(cts))
	var printing time.Duration
	start := time.Now()
	for i, ct := range cts {
		d1 := suite.Point().Mul(x1, ct.R)
		d2 := suite.Point().Mul(x2, ct.R)
		recovered[i] = suite.Point().Sub(suite.Point().Sub(ct.S, d1), d2)
		printing += report("threshold_decrypt", i+1)
	}
	decrypt := time.Since(start) - printing
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
		report("verify_and_serialize", i+1)
	}
	return result{mode: "elgamal", roots: len(coeffs) - 1, ciphertexts: len(cts), bytes: size, latency: median(samples), decrypt: decrypt}, nil
}
