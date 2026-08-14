# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-08-14

### Features

- tpm: Add TPM-backed signer key
- sshd: Back host identity with TPM-resident key
- client: Sync daemon state from heartbeat version
- sshd: Add graceful shutdown draining connections

### Bug Fixes

- install: Handle missing CA bundle and verify package install
- hostcerts: Reject non-host certificate types
- recorder: Sanitize session id in filenames
- util: Cap sanitized label length
- hostcerts: Renew immediately when no cert is valid
- sshd: Stop client-alive goroutine on disconnect
- sshd: Drain stdout before reaping child process
- client: Reconnect in background with quiet retries
- client: Drain pty sessions on shutdown
- config: Use string source for ssh_addr flag
- config: Use ConfigFile pointer for ssh_addr sourcing

### Performance Improvements

- recorder: Flush compressed data on a bounded interval

### Refactoring

- client: Accept config in constructor
- client: Use scoped error variables in streams
- sshd: Tidy channel handlers and session cap
- util: Drop gid parameter from atomic write helpers
- config: Drop persisted ca id from enrollment state
- util: Drop unused FileExists helper
- audit: Write events on a background goroutine
- state: Make cache fields private

### Testing

- sshd: Fuzz signal and env handling
- hostcerts: Add shared CA helpers and cert tests
- sshd: Scope accept errors in forward tests
- state: Cover cache and config behavior
- client: Cover ssh port parsing
- sysutil: Cover user lookup and shell resolution
- leaktest: Check for leaked goroutines in tests

### Documentation

- Adjust punctuation
- sshd: Tighten channel and session comments
- tpm: Clarify software key wrap comment
- sysutil: Reword session env comments
- Rewrite code comments as complete sentences

### Miscellaneous

- fuzz: Add task to run all fuzz targets
- Run tests with race detector
- sshd: Reformat client-alive logging and session handler
- gen: Regenerate sso and user protos
- Enable goroutineleak profile in tests

## [0.1.0] - 2026-08-08

### Features

- install: Add cloudsmith package install with github fallback

### Bug Fixes

- ci: Normalize version comparison in release tagger

### Documentation

- readme: Add package repo and hosting sections


