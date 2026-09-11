package sysutil

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxReportedUsers caps how many local usernames the daemon reports. The list
// is sorted before truncating, so only the tail can ever change between syncs.
const maxReportedUsers = 200

// SystemUsers returns local usernames that could plausibly log in over SSH
// (root and human accounts with a real shell), capped at maxReportedUsers.
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

		parts := strings.Split(string(line), ":")
		if len(parts) != 7 {
			continue
		}

		uid, parseErr := strconv.Atoi(parts[2])
		if parseErr != nil {
			continue
		}

		if isValidSSHUser(uid, parts[6]) {
			users = append(users, parts[0])
		}
	}
	return capUsers(users)
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
				if userField != "" {
					users = append(users, userField)
				}
			}
		}
	}
	return capUsers(users)
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
	return capUsers(users)
}

// capUsers sorts and truncates so the backend always sees a stable head.
func capUsers(users []string) []string {
	sort.Strings(users)
	if len(users) > maxReportedUsers {
		return users[:maxReportedUsers]
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
