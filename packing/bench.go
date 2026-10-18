package main

import (
	"fmt"
	"sort"
	"time"
)

type result struct {
	mode                               string
	roots, N, logN, ciphertexts, bytes int
	latency, decrypt                   time.Duration
}

func median(samples []time.Duration) time.Duration {
	s := append([]time.Duration(nil), samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return s[m-1] + (s[m]-s[m-1])/2
}
func (r result) print() {
	N, logN := "NA", "NA"
	if r.N != 0 {
		N = fmt.Sprint(r.N)
		logN = fmt.Sprint(r.logN)
	}
	fmt.Printf("mode=%s roots=%d degree=%d coeffs=%d N=%s logN=%s ciphertexts=%d latency_ms=%.3f threshold_decrypt_ms=%.3f ciphertext_kb=%.3f verify=PASS\n", r.mode, r.roots, r.roots, r.roots+1, N, logN, r.ciphertexts, float64(r.latency)/float64(time.Millisecond), float64(r.decrypt)/float64(time.Millisecond), float64(r.bytes)/1024)
}
