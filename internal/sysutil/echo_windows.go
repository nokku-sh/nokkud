//go:build windows

package sysutil

// EchoEnabled always reports true on Windows: ConPTY input echo is managed
// by the terminal and cannot be queried the same way, so input recording
// is left unfiltered there.
func EchoEnabled(_ uintptr) bool {
	return true
}
