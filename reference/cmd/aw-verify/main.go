// Command aw-verify recomputes a ledger's hash chain from genesis and reports any
// tampering, localized to the first offending record (AW-Spec v0.2 §8.3). It needs
// no trust in the broker that wrote the ledger: verify-over-trust.
//
// Usage: aw-verify -ledger /path/to/ledger.log
//
// Exit code 0 = chain intact; 1 = tampering detected; 2 = usage/IO error.
//
// Licensed under the Apache License 2.0.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aiegis/agentwarden/internal/ledger"
)

func main() {
	path := flag.String("ledger", "", "path to the ledger file")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "usage: aw-verify -ledger /path/to/ledger.log")
		os.Exit(2)
	}
	res, err := ledger.Verify(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify error: %v\n", err)
		os.Exit(2)
	}
	if res.OK {
		fmt.Printf("OK: ledger chain intact (%d records)\n", res.Count)
		os.Exit(0)
	}
	fmt.Printf("TAMPER DETECTED at seq %d: %s\n", res.BadSeq, res.Detail)
	os.Exit(1)
}
