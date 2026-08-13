//go:build !windows

package sshd

import (
	"os"
	"syscall"
)

// sshSignals maps SSH signal names (RFC 4254) to OS signals.
var sshSignals = map[string]os.Signal{
	"ABRT": syscall.SIGABRT,
	"ALRM": syscall.SIGALRM,
	"FPE":  syscall.SIGFPE,
	"HUP":  syscall.SIGHUP,
	"ILL":  syscall.SIGILL,
	"INT":  syscall.SIGINT,
	"KILL": syscall.SIGKILL,
	"PIPE": syscall.SIGPIPE,
	"QUIT": syscall.SIGQUIT,
	"SEGV": syscall.SIGSEGV,
	"TERM": syscall.SIGTERM,
	"USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2,
}

// signalByName maps an SSH signal name (RFC 4254) to an OS signal.
func signalByName(name string) (os.Signal, bool) {
	sig, ok := sshSignals[name]
	return sig, ok
}

// processSignal extracts the terminating signal of a finished process and
// its conventional shell exit code (128+n). ok is false when the process
// exited on its own, so the caller reports the regular exit-status instead.
// A signal outside the RFC 4254 name table is reported with an empty name.
// The caller then sends exit-status with the 128+n code.
func processSignal(st *os.ProcessState) (name string, code int, ok bool) {
	if st == nil {
		return "", 0, false
	}
	ws, ok := st.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return "", 0, false
	}
	sig := ws.Signal()
	code = 128 + int(sig)
	for n, s := range sshSignals {
		if s == sig {
			return n, code, true
		}
	}
	return "", code, true
}
