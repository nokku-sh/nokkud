// Package leaktest verifies that tests leave no permanently stuck
// goroutines behind. It reads the runtime/pprof "goroutineleak" profile
// instead of depending on a third-party leak checker. The profile is
// experimental on Go 1.26 (GOEXPERIMENT=goroutineleakprofile) and generally
// available from Go 1.27; while it is unavailable, VerifyNone is a no-op.
package leaktest

import (
	"bytes"
	"runtime/pprof"
	"testing"
)

// VerifyNone fails the test when the goroutineleak profile reports leaked
// goroutines. The profile only reports goroutines that are provably stuck
// forever, computed by the garbage collector as a reachability proof, so
// the check cannot produce false positives. It mirrors goleak.VerifyNone.
func VerifyNone(t *testing.T) {
	t.Helper()

	p := pprof.Lookup("goroutineleak")
	if p == nil {
		return
	}

	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 1); err != nil {
		t.Fatalf("write goroutineleak profile: %v", err)
	}
	if p.Count() > 0 {
		t.Fatalf("leaked goroutines:\n%s", buf.String())
	}
}
