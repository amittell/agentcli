# Security Policy

## Reporting

Report security issues privately using [GitHub Security Advisories](https://github.com/amittell/agentcli/security/advisories/new) instead of opening a public issue.

Include:

- affected version
- reproduction steps
- impact
- suggested mitigation if known

## Scope

Security-sensitive areas include:

- manifest input validation
- file output handling
- runtime inspection surfaces
- protocol parsing
- sanitization behavior

## Expectations

This project aims to be safe for agent-facing usage, which means:

- rejecting unsafe control characters where practical
- refusing unsafe write paths
- preserving machine-readable error behavior

Please report bypasses or unsafe edge cases.
