//go:build windows

package sshd

import "os"

// signalByName maps an SSH signal name (RFC 4254) to an OS signal.
func signalByName(name string) (os.Signal, bool) {
	sig, ok := map[string]os.Signal{
		"INT":  os.Interrupt,
		"KILL": os.Kill,
		"TERM": os.Kill,
	}[name]
	return sig, ok
}

// processSignal always reports a normal exit: Windows has no POSIX signals,
// so sessions always report exit-status.
func processSignal(_ *os.ProcessState) (string, int, bool) {
	return "", 0, false
}
