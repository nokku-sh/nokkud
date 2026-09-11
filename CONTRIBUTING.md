# Contributing

Thanks for your interest in `nokkud`! It's a small Go daemon, so getting
started is quick.

## Prerequisites

- Go 1.x (see `go.mod`)
- [Task](https://taskfile.dev)
- [`buf`](https://buf.build) and
  [`protoc-gen-connect-go`](https://connectrpc.com/docs/go/getting-started)
  (protobuf generation)
- [`golangci-lint`](https://golangci-lint.run)
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [GoReleaser](https://goreleaser.com) (snapshots/releases only)

## Building

```bash
task build
```

This builds the `nokkud` binary and installs it to `/usr/local/bin` (static,
`CGO_ENABLED=0`). The move needs root, so the task calls `sudo`.

## Regenerating generated code

```bash
task gen
```

This runs `buf generate` against the sibling `../protos/nokku` checkout, so
clone [nokku-sh/protos](https://github.com/nokku-sh/protos) next to this repo
first. The generated Go lives in `internal/gen/` and is committed.

## Code style

Follow the conventions already in the codebase. Before opening a PR, run:

```bash
task lint
```

which runs `go mod tidy`, `go fmt`, `go vet`, `govulncheck`, the test suite, and
`golangci-lint run --fix` (the config enables golines formatting).

## Tests

```bash
go test ./...
```

or via the lint task above. Please add tests for new behavior and keep the
existing suite green.

## Releases

Releases are cut via GoReleaser on version tags. To preview a local build
without publishing:

```bash
task snapshot
```

## Submitting changes

1. Fork the repo and create a branch off `main`.
2. Make focused changes and run `task lint`.
3. Open a pull request describing what and why.

Keep changes small and scoped. If a change alters behavior, update the README
accordingly. Release notes are generated from conventional commit messages with
git-cliff, so prefix commits with `feat:`, `fix:`, and so on.
