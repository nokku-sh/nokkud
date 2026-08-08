# Contributing

Thanks for your interest in `nokkud`! It's a small Go daemon, so getting
started is quick.

## Prerequisites

- Go 1.x (see `go.mod`)
- [Task](https://taskfile.dev)
- [`buf`](https://buf.build) (protobuf generation)
- [`golangci-lint`](https://golangci-lint.run)
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- `golines`
- [GoReleaser](https://goreleaser.com) (snapshots/releases only)

## Building

```bash
task build
```

This produces the `nokkud` binary in the repo root (static, `CGO_ENABLED=0`).

## Regenerating generated code

```bash
task gen
```

This runs `buf generate` from the `.proto` sources used by the repo.

## Code style

Follow the conventions already in the codebase. Before opening a PR, run:

```bash
task lint
```

which runs `go fmt`, `go vet`, `golines`, `govulncheck`, the test suite, and
`golangci-lint`.

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

Keep changes small and scoped. If a change alters behavior, update the
README and CHANGELOG accordingly.
