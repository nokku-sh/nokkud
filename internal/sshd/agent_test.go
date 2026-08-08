package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

// TestServerAgentForwarding verifies ssh -A: a session sees SSH_AUTH_SOCK and
// can reach the client's agent through it.
func TestServerAgentForwarding(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{AllowAgentForwarding: true})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Client side: serve auth-agent@openssh.com channels from an in-memory
	// agent that holds one key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	agentKey := agent.AddedKey{PrivateKey: priv}
	if err = keyring.Add(agentKey); err != nil {
		t.Fatalf("add key to agent: %v", err)
	}
	if err = agent.ForwardToAgent(client, keyring); err != nil {
		t.Fatalf("forward to agent: %v", err)
	}

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	if err = agent.RequestAgentForwarding(sess); err != nil {
		t.Fatalf("request agent forwarding: %v", err)
	}

	// The session must see SSH_AUTH_SOCK set.
	out, err := sess.Output("echo $SSH_AUTH_SOCK")
	if err != nil {
		t.Fatalf("echo SSH_AUTH_SOCK: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("SSH_AUTH_SOCK not set in session")
	}
	t.Logf("SSH_AUTH_SOCK=%s", out)
}

// TestServerAgentForwardingKeyList exercises the full agent protocol: the
// session opens the socket and lists keys from the client's agent.
func TestServerAgentForwardingKeyList(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{AllowAgentForwarding: true})
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	agentKey := agent.AddedKey{PrivateKey: priv}
	if err = keyring.Add(agentKey); err != nil {
		t.Fatalf("add key to agent: %v", err)
	}
	if err = agent.ForwardToAgent(client, keyring); err != nil {
		t.Fatalf("forward to agent: %v", err)
	}

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	if err = agent.RequestAgentForwarding(sess); err != nil {
		t.Fatalf("request agent forwarding: %v", err)
	}

	// Run a helper (this test binary, re-entered) that connects to the agent
	// socket and prints the key count. The helper-activation flag is passed via
	// the shell environment, not an env request: the daemon's env whitelist
	// (correctly) refuses GO_* variables from clients.
	helper := "GO_WANT_AGENT_HELPER_PROCESS=1 " + helperProcessCommand(t, "agent")
	out, err := sess.Output(helper)
	if err != nil {
		t.Fatalf("agent helper: %v\n%s", err, out)
	}
	if want := "keys=1\n"; string(out) != want {
		t.Fatalf("agent helper output = %q, want %q", out, want)
	}
}

// helperProcessCommand returns a shell command that re-enters the test binary
// as the named helper.
func helperProcessCommand(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("%s -test.run=TestAgentHelperProcess -- %s", sshdTestBinary(t), name)
}

// sshdTestBinary returns the path of the running test binary so it can be
// re-entered as a subprocess.
func sshdTestBinary(t *testing.T) string {
	t.Helper()
	bin := os.Args[0]
	if filepath.Base(bin) != "sshd.test" {
		t.Fatalf("expected test binary named sshd.test, got %q", bin)
	}
	return bin
}

// TestAgentHelperProcess re-enters the test binary as an agent client: it
// connects to $SSH_AUTH_SOCK, lists the agent keys, and prints their count.
func TestAgentHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_AGENT_HELPER_PROCESS") != "1" {
		return
	}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		fmt.Fprintln(os.Stderr, "SSH_AUTH_SOCK not set")
		os.Exit(2)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent dial:", err)
		os.Exit(1)
	}
	ag := agent.NewClient(conn)
	keys, err := ag.List()
	_ = conn.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent list:", err)
		os.Exit(1)
	}
	fmt.Printf("keys=%d\n", len(keys))
	os.Exit(0)
}

// TestServerAgentForwardingDisabled verifies agent forwarding is rejected when
// AllowAgentForwarding is off.
func TestServerAgentForwardingDisabled(t *testing.T) {
	ca := newTestCA(t)
	addr, closeFn := startTestServer(t, ca)
	defer closeFn()

	client, err := dial(t, addr, currentUser(t), userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()
	if err = agent.RequestAgentForwarding(sess); err == nil {
		t.Fatal("agent forwarding unexpectedly allowed")
	}
}

// TestServerAgentForwardingInterop drives ssh -A with the real OpenSSH client:
// SSH_AUTH_SOCK is exposed and a real ssh-add sees the agent.
func TestServerAgentForwardingInterop(t *testing.T) {
	if !isTestBinary() {
		t.Skip("requires the test binary on PATH")
	}
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}
	if _, err = exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add not installed")
	}

	ca := newTestCA(t)
	addr, closeFn := startTestServerOpts(t, ca, Options{AllowAgentForwarding: true})
	defer closeFn()
	host, port := hostPort(t, addr)
	user := currentUser(t)

	client, err := dial(t, addr, user, userCert(t, ca, testPrincipal))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Client side serves the agent for this connection.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err = keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("add key: %v", err)
	}
	if err = agent.ForwardToAgent(client, keyring); err != nil {
		t.Fatalf("forward to agent: %v", err)
	}

	// The real ssh client opens the session with -A and runs ssh-add -L.
	// It forwards its own agent, so a dedicated one is started and loaded
	// with a key: CI runners have no agent and would silently disable -A.
	sock, stopAgent := testAgent(t)
	defer stopAgent()
	agentEnv := append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	out, err := exec.Command(
		"ssh-keygen", "-t", "ed25519", "-f", keyFile, "-N", "", "-q",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	add := exec.Command("ssh-add", keyFile)
	add.Env = agentEnv
	out, err = add.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, out)
	}

	identity := userCertFile(t, ca)
	cmd := exec.Command(
		sshBin,
		"-A",
		"-p", port,
		"-i", identity,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		fmt.Sprintf("%s@%s", user, host),
		"ssh-add -L",
	)
	cmd.Env = agentEnv
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -A ssh-add -L: %v\n%s", err, out)
	}
	if len(out) == 0 {
		t.Fatal("ssh-add -L produced no output (agent not reachable)")
	}
	t.Logf("agent key: %s", out)
}
