package main

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// Lattigo 6.2 implements BFV in bgv; schemes/bfv contains documentation only.
// Encryption-only BFV and BGV use this same encoder and encryptor. The BFV
// scale-invariant evaluator is unnecessary because no evaluation is performed.
func latticeParameters(logN int) (bgv.Parameters, error) {
	return bgv.NewParametersFromLiteral(bgv.ParametersLiteral{LogN: logN, LogQ: []int{50}, PlaintextModulus: plaintextModulus})
}
func rawParameters(p bgv.Parameters) (rlwe.Parameters, error) {
	return rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{LogN: p.LogN(), Q: p.Q(), Xs: p.Xs(), Xe: p.Xe(), NTTFlag: true})
}
