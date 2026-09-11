//go:build windows

package sysutil

// EchoEnabled always reports true on Windows: ConPTY echo is managed by the
// terminal and cannot be queried, so input recording is left unfiltered.
func EchoEnabled(_ uintptr) bool {
	return true
}
