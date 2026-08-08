package sysutil

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SystemUsers returns up to 20 local usernames that could plausibly log in
// over SSH (root and human accounts with a real shell). The backend uses the
// list to offer principal mappings for this target.
func SystemUsers() []string {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd", "netbsd":
		return linuxUsers()
	case "darwin":
		return darwinUsers()
	case "windows":
		return windowsUsers()
	default:
		return nil
	}
}

func linuxUsers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "getent", "passwd")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("list system users", "error", err)
		return nil
	}

	var users []string
	for line := range bytes.SplitSeq(output, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if len(users) >= 20 {
			break
		}

		parts := strings.Split(string(line), ":")
		if len(parts) != 7 {
			continue
		}

		username := parts[0]
		uidStr := parts[2]
		shell := parts[6]

		var uid int
		uid, err = strconv.Atoi(uidStr)
		if err != nil {
			continue
		}

		if isValidSSHUser(uid, shell) {
			users = append(users, username)
		}
	}
	return users
}

func windowsUsers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "net", "user")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var users []string
	lines := strings.Split(string(output), "\n")
	inUserList := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "User accounts for") {
			inUserList = true
			continue
		}
		if strings.Contains(line, "The command completed") {
			break
		}
		if inUserList && line != "" && !strings.Contains(line, "---") {
			for userField := range strings.FieldsSeq(line) {
				if userField != "" && len(users) < 20 {
					users = append(users, userField)
				}
			}
		}

		if len(users) >= 20 {
			break
		}
	}
	return users
}

func darwinUsers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "dscl", ".", "-list", "/Users", "UniqueID")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("list system users", "error", err)
		return nil
	}

	var users []string
	for line := range strings.SplitSeq(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		user := fields[0]
		uid, _ := strconv.Atoi(fields[1])

		if !strings.HasPrefix(user, "_") && (uid == 0 || uid >= 501) {
			users = append(users, user)
		}
	}
	return users
}

func isValidSSHUser(uid int, shell string) bool {
	isHumanOrRoot := uid == 0 || uid >= 1000
	hasValidShell := !strings.HasSuffix(shell, "nologin") &&
		!strings.HasSuffix(shell, "false") &&
		!strings.HasSuffix(shell, "sync")

	return isHumanOrRoot && hasValidShell
}
