// Command rulelint loads every rule under a directory through the real DeusWatch
// Sigma engine (the same LoadDir/LoadAggDir the worker uses) and reports counts and
// any parse errors. Exit code is non-zero if any file fails to parse, so it can gate
// CI and the rule generator.
//
//	go run ./tools/rulelint [rules/sigma]
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"deuswatch/internal/detect/sigma"
)

func main() {
	dir := "rules/sigma"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	// Per-file validation so a single bad rule names itself (LoadDir aborts on the
	// first error otherwise).
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml", filepath.Join("*", "*.yml"), filepath.Join("*", "*.yaml")} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		files = append(files, m...)
	}

	var bad int
	single, agg := 0, 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("READ  %s: %v\n", f, err)
			bad++
			continue
		}
		kind, err := sigma.Classify(data)
		if err != nil {
			fmt.Printf("PARSE %s: %v\n", f, err)
			bad++
			continue
		}
		switch kind {
		case sigma.KindAggregation:
			agg++
		default:
			single++
		}
	}

	// Also exercise the loaders the worker actually calls (they must not error).
	if _, err := sigma.LoadDir(dir); err != nil {
		fmt.Printf("LoadDir: %v\n", err)
		bad++
	}
	if _, err := sigma.LoadAggDir(dir); err != nil {
		fmt.Printf("LoadAggDir: %v\n", err)
		bad++
	}

	fmt.Printf("\n%s: %d files, %d single-event, %d aggregation, %d errors\n",
		dir, len(files), single, agg, bad)
	if bad > 0 {
		os.Exit(1)
	}
}
