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
	compare := flag.Bool("compare", false, "compare Exact (ElGamal), BF (ElGamal), BF (RLWE); write CSV to --out")
	packingStudy := flag.Bool("packing-study", false, "measure RLWE packing plans for --n items; write JSON to --out")
	out := flag.String("out", "results/packing-comparison-three.csv", "comparison CSV path")
	sizes := flag.String("sizes", "", "optional comma-separated item counts for --compare")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *packingStudy {
		if *compare || *mode != "" || *sizes != "" {
			return fmt.Errorf("--packing-study cannot be combined with --compare, --mode or --sizes")
		}
		path := *out
		if path == "results/packing-comparison-three.csv" {
			path = "results/packing-study.json"
		}
		return runPackingStudy(*n, *trials, *seed, path)
	}
	if *sizes != "" && !*compare {
		return fmt.Errorf("--sizes requires --compare")
	}
	if *compare {
		if *n != 0 || *mode != "" {
			return fmt.Errorf("--compare cannot be combined with --n or --mode")
		}
		return comparePacking(*out, *trials, *seed, *sizes)
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
