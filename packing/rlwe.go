package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"time"
)

type thresholdKeys struct {
	params         rlwe.Parameters
	sk1, sk2, zero *rlwe.SecretKey
	public         *rlwe.PublicKey
	protocol       multiparty.KeySwitchProtocol
}

func collectiveKeys(p rlwe.Parameters) (*thresholdKeys, error) {
	kg := rlwe.NewKeyGenerator(p)
	k := &thresholdKeys{params: p, sk1: kg.GenSecretKeyNew(), sk2: kg.GenSecretKeyNew(), zero: rlwe.NewSecretKey(p), public: rlwe.NewPublicKey(p)}
	ckg := multiparty.NewPublicKeyGenProtocol(p)
	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, err
	}
	crp := ckg.SampleCRP(prng)
	a, b := ckg.AllocateShare(), ckg.AllocateShare()
	ckg.GenShare(k.sk1, crp, &a)
	ckg.GenShare(k.sk2, crp, &b)
	ckg.AggregateShares(a, b, &a)
	ckg.GenPublicKey(a, crp, k.public)
	k.protocol, err = multiparty.NewKeySwitchProtocol(p, ring.DiscreteGaussian{Sigma: 3.2, Bound: 19.2})
	return k, err
}
func (k *thresholdKeys) decrypt(ct *rlwe.Ciphertext) (*rlwe.Plaintext, error) {
	a, b := k.protocol.AllocateShare(ct.Level()), k.protocol.AllocateShare(ct.Level())
	k.protocol.GenShare(k.sk1, k.zero, ct, &a)
	k.protocol.GenShare(k.sk2, k.zero, ct, &b)
	if err := k.protocol.AggregateShares(a, b, &a); err != nil {
		return nil, err
	}
	out := rlwe.NewCiphertext(k.params, 1, ct.Level())
	k.protocol.KeySwitch(ct, a, out)
	return rlwe.NewDecryptor(k.params, k.zero).DecryptNew(out), nil
}
func encodeRaw(p rlwe.Parameters, coeffs []uint64) *rlwe.Plaintext {
	pt := rlwe.NewPlaintext(p, p.MaxLevel())
	pt.IsNTT = false
	delta := p.Q()[0] / plaintextModulus
	for i, c := range coeffs {
		pt.Value.Coeffs[0][i] = delta * c
	}
	return pt
}
func decodeRaw(p rlwe.Parameters, pt *rlwe.Plaintext) []uint64 {
	if pt.IsNTT {
		p.RingQ().AtLevel(pt.Level()).INTT(pt.Value, pt.Value)
		pt.IsNTT = false
	}
	q := p.Q()[0]
	delta := q / plaintextModulus
	out := make([]uint64, p.N())
	for i, v := range pt.Value.Coeffs[0] {
		v %= q
		// Use centered representatives so negative noise near zero wraps correctly.
		if v > q/2 {
			out[i] = (plaintextModulus - ((q-v+delta/2)/delta)%plaintextModulus) % plaintextModulus
		} else {
			out[i] = ((v + delta/2) / delta) % plaintextModulus
		}
	}
	return out
}
func benchLattice(mode string, coeffs []uint64, trials int) (result, error) {
	return benchLatticeWithLimit(mode, coeffs, trials, maxSupportedLogN)
}

func benchLatticeWithLimit(mode string, coeffs []uint64, trials, maxLogN int) (result, error) {
	N, logN, err := ringDimensionWithLimit(len(coeffs)-1, maxLogN)
	if err != nil {
		return result{}, err
	}
	bp, err := latticeParameters(logN)
	if err != nil {
		return result{}, err
	}
	p := bp.Parameters
	if mode == "rlwe" {
		p, err = rawParameters(bp)
		if err != nil {
			return result{}, err
		}
	}
	keys, err := collectiveKeys(p)
	if err != nil {
		return result{}, err
	}
	var pt *rlwe.Plaintext
	if mode == "rlwe" {
		pt = encodeRaw(p, coeffs)
	} else {
		pt, err = encodeBFV(bp, coeffs)
		if err != nil {
			return result{}, err
		}
	}
	encryptor := rlwe.NewEncryptor(p, keys.public)
	samples := make([]time.Duration, trials)
	var ct *rlwe.Ciphertext
	for trial := range samples {
		start := time.Now()
		ct, err = encryptor.EncryptNew(pt)
		samples[trial] = time.Since(start)
		if err != nil {
			return result{}, err
		}
	}
	start := time.Now()
	decodedPT, err := keys.decrypt(ct)
	decrypt := time.Since(start)
	if err != nil {
		return result{}, err
	}
	var decoded []uint64
	if mode == "rlwe" {
		decoded = decodeRaw(p, decodedPT)
	} else {
		decoded, err = decodeBFV(bp, decodedPT)
		if err != nil {
			return result{}, err
		}
	}
	for i := 0; i < N; i++ {
		var want uint64
		if i < len(coeffs) {
			want = coeffs[i]
		}
		if decoded[i] != want {
			return result{}, fmt.Errorf("coefficient %d: got %d, want %d", i, decoded[i], want)
		}
	}
	data, err := ct.MarshalBinary()
	if err != nil {
		return result{}, err
	}
	return result{mode: mode, roots: len(coeffs) - 1, N: N, logN: logN, ciphertexts: 1, bytes: len(data), latency: median(samples), decrypt: decrypt}, nil
}
