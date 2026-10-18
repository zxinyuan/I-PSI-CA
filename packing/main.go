package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

func run() error {
	n := flag.Int("n", 0, "number of roots (1..131071)")
	mode := flag.String("mode", "", "elgamal | rlwe | bfv | all")
	trials := flag.Int("trials", 5, "encryption timing trials")
	seed := flag.Int64("seed", 1, "deterministic root seed")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if _, _, err := ringDimension(*n); err != nil {
		return err
	}
	if *trials < 1 {
		return fmt.Errorf("trials must be >= 1")
	}
	modes := []string{*mode}
	switch *mode {
	case "all":
		modes = []string{"elgamal", "rlwe", "bfv"}
	case "elgamal", "rlwe", "bfv":
	default:
		return fmt.Errorf("mode must be elgamal, rlwe, bfv, or all")
	}
	coeffs := polynomialFromRoots(rootsFromSeed(*n, *seed))
	for _, m := range modes {
		var r result
		var err error
		if m == "elgamal" {
			r, err = benchElGamal(coeffs, *trials)
		} else {
			r, err = benchLattice(m, coeffs, *trials)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", m, err)
		}
		r.print()
	}
	return nil
}
func main() {
	runtime.GOMAXPROCS(1)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
