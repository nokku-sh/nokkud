//go:build windows

package sshd

import "os"

func signalByName(name string) (os.Signal, bool) {
	sig, ok := map[string]os.Signal{
		"INT":  os.Interrupt,
		"KILL": os.Kill,
		"TERM": os.Kill,
	}[name]
	return sig, ok
}

// processSignal always reports a normal exit, since Windows has no POSIX
// signals and sessions always report exit-status.
func processSignal(_ *os.ProcessState) (string, int, bool) {
	return "", 0, false
}
