// Package leaktest verifies that a test suite leaves no permanently stuck
// goroutines behind. It reads the runtime/pprof "goroutineleak" profile
// instead of depending on a third-party leak checker.
package leaktest

import (
	"bytes"
	"fmt"
	"os"
	"runtime/pprof"
)

// Exit checks the goroutineleak profile after a test suite has finished and
// overrides code with 1 when goroutines leaked. Wire it into TestMain with
// m.Run()'s result, so the check runs once with every server torn down:
//
//	func TestMain(m *testing.M) {
//		os.Exit(leaktest.Exit(m.Run()))
//	}
func Exit(code int) int {
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		return code
	}

	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 1); err != nil {
		fmt.Fprintf(os.Stderr, "leaktest: write goroutineleak profile: %v\n", err)
		return 1
	}
	if p.Count() > 0 {
		fmt.Fprintf(os.Stderr, "leaktest: leaked goroutines:\n%s\n", buf.String())
		return 1
	}
	return code
}
