# Changelog

## 0.1.0

Initial public draft release.

Includes:

- manifest schema and validation
- structured shell execution (`shell.program`, `shell.args`, `shell.env`, `shell.cwd`, `shell.stdin`) instead of raw `command` strings
- standalone compile target
- `openclaw-scheduler` compile target with POSIX shell rendering for `payload_message`
- scheduler inspection with field masks and sanitization
- stdio JSON-RPC
- publication docs for spec, protocol, conformance, capabilities, versioning, and adoption
- schema deduplication with shared field definitions

Breaking changes from pre-release git snapshots:

- `command` field removed from tasks and `on_failure`; use `shell.program` and `shell.args` instead
- shell targets now reject `payload_kind` values other than `shellCommand`
- shell targets reject `prompt`; non-shell targets reject `shell`
