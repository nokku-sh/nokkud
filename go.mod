module github.com/nokku-sh/nokkud

go 1.26.6

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260709200747-435963d16310.1
	connectrpc.com/connect v1.20.0
	github.com/aymanbagabas/go-pty v0.2.3
	github.com/cenkalti/backoff/v7 v7.0.0
	github.com/google/go-tpm v0.9.8
	github.com/mizuchilabs/kata v0.1.3
	github.com/pkg/sftp v1.13.11
	github.com/urfave/cli-altsrc/v3 v3.1.0
	github.com/urfave/cli/v3 v3.11.0
	golang.org/x/crypto v0.55.0
	golang.org/x/sys v0.47.0
	golang.org/x/time v0.15.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260817212433-ac3dfec99bb1
	google.golang.org/protobuf v1.36.12
)

require github.com/go-jose/go-jose/v4 v4.1.4 // indirect

require (
	github.com/creack/pty v1.1.24 // indirect
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mizuchilabs/kagi v0.0.0
	github.com/u-root/u-root v0.16.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mizuchilabs/kagi => /home/roxas/Projects/kagi
