package client

import (
	"os"
	"testing"

	"github.com/nokku-sh/nokkud/internal/leaktest"
)

// TestMain checks the goroutine leak profile once after every test has torn
// down, so a leak in any test fails the suite.
func TestMain(m *testing.M) {
	os.Exit(leaktest.Exit(m.Run()))
}
