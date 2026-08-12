package client

import "testing"

func TestSSHPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr string
		want string
	}{
		{addr: "", want: ""},
		{addr: ":4022", want: "4022"},
		{addr: "0.0.0.0:4022", want: "4022"},
		{addr: "[::]:4022", want: "4022"},
		{addr: "127.0.0.1:4022", want: "4022"},
		{addr: "4022", want: "4022"},
		{addr: "0", want: ""},
		{addr: "65535", want: "65535"},
		{addr: "65536", want: ""},
		{addr: "-1", want: ""},
		{addr: "not-a-port", want: ""},
		{addr: "127.0.0.1:not-a-port", want: ""},
		{addr: "127.0.0.1:0", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := sshPort(tt.addr); got != tt.want {
				t.Errorf("sshPort(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestValidPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		port string
		want string
	}{
		{port: "4022", want: "4022"},
		{port: "00080", want: "00080"},
		{port: "0", want: ""},
		{port: "65536", want: ""},
		{port: "", want: ""},
		{port: " 22", want: ""},
		{port: "22 ", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.port, func(t *testing.T) {
			if got := validPort(tt.port); got != tt.want {
				t.Errorf("validPort(%q) = %q, want %q", tt.port, got, tt.want)
			}
		})
	}
}
