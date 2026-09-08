package sshd

import (
	"context"
	"io"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvValueLastWins(t *testing.T) {
	t.Parallel()
	sess := &session{env: []string{
		"NOKKU_SESSION_ID=first",
		"TERM=xterm",
		"NOKKU_SESSION_ID=second",
	}}
	is := assert.New(t)

	v, ok := sess.envValue("NOKKU_SESSION_ID")
	is.True(ok)
	is.Equal("second", v)

	v, ok = sess.envValue("TERM")
	is.True(ok)
	is.Equal("xterm", v)

	_, ok = sess.envValue("MISSING")
	is.False(ok)
}

func TestRecorderSessionIDFromEnv(t *testing.T) {
	t.Setenv("NOKKUD_DATA_DIR", t.TempDir())

	tests := []struct {
		name string
		env  string
		want string
	}{
		{
			name: "canonical uuid is promoted",
			env:  "01999650-9b7a-7d5e-9f2a-3f1e8f6f1a01",
			want: "01999650-9b7a-7d5e-9f2a-3f1e8f6f1a01",
		},
		{
			name: "free-form value is refused",
			env:  "other-session",
			want: "sshd-generated",
		},
		{
			name: "uppercase is not canonical",
			env:  "01999650-9B7A-7D5E-9F2A-3F1E8F6F1A01",
			want: "sshd-generated",
		},
		{
			name: "wrong length is refused",
			env:  "01999650-9b7a-7d5e-9f2a-3f1e8f6f1a0",
			want: "sshd-generated",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			captured := make(chan string, 1)
			srv := &Server{}
			srv.tun.Store(&Tunables{Record: true})
			srv.recordingSinkFactory = func(_ context.Context, sessionID, _ string) io.WriteCloser {
				captured <- sessionID
				return nopSink{}
			}
			sess := &session{
				server:    srv,
				sessionID: "sshd-generated",
				env:       []string{"NOKKU_SESSION_ID=" + tt.env},
				ctx:       t.Context(),
				sysUser:   &user.User{Username: "tester"},
			}

			sess.startRecorder(80, 24)
			require.Equal(t, tt.want, <-captured)
			if sess.rec != nil {
				sess.rec.Close()
			}
		})
	}
}

type nopSink struct{}

func (nopSink) Write(p []byte) (int, error) { return len(p), nil }

func (nopSink) Close() error { return nil }
