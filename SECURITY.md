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
- approval binding, signing, scope, expiry, and single-use consumption
- authorization proof trust material and manifest binding
- identity provider resolution and credential materialization
- sandbox, allowed-path, and network enforcement
- evidence payload binding and later verification
- file output handling
- runtime inspection surfaces
- protocol parsing
- sanitization behavior

`agentcli` is a governed control plane and local shell executor. It is not a durable scheduler or an operating-system security boundary. `openclaw-scheduler` owns durable dispatch, retries, delivery, and persistent runtime state.

## Fail-Closed Boundaries

- `exec --dry-run` is static and side-effect free with respect to approval records, proof commands, identity and authorization providers, network endpoints, sandbox probes, credential materialization, signing, evidence, post-execution verification, and audit files.
- A manual approval binds the canonical manifest and complete effective execution configuration. Approver scope and task timeout cap the grant. Unexpected unsigned records, invalid signatures, and any bound configuration drift are rejected.
- Every authorization proof method other than `none` requires cryptographic verification and a canonical manifest binding. Missing trust material is an error, even if `verify.required` is false.
- Evidence is a versioned, canonical envelope. Verification checks the execution and manifest binding so an envelope cannot be transplanted to another audit record.
- Requested sandbox or network restrictions are enforced or execution is refused. There is no permissive fallback when the host lacks an enforcement adapter.
- Child processes inherit only a small operational allowlist such as PATH, HOME, temporary-directory, locale, shell, user, timezone, terminal, and Windows equivalents. All other ambient variables are stripped unless explicitly declared by the task or materialized by its identity provider.
- Credentials must not be placed in `shell.args` or prompts. Arguments can appear in process listings and prompts can be stored in durable runtime records. Use identity-provider env, file, or stdin materialization.
- Durable scheduler compilation rejects inline `shell.env` and `shell.stdin`. Secrets must be resolved at dispatch through an identity provider instead of being persisted in a job record.
- Output, registry, audit, approval, temporary credential, and allowed-signer files use restrictive paths and permissions. Symlinked or otherwise unsafe destinations are refused.

## Runtime Capability Trust

When a scheduler reports capabilities, its live values are authoritative. Static target declarations are conservative fallback values only. Root approval gates, approver scopes, structured output, and scheduler handoff v3 fields require explicit runtime support. An operator who controls the scheduler binary, provider path, environment, or capability response controls that runtime trust boundary.

For production isolation, run local shell execution inside a container or another operating-system boundary that can enforce the manifest's filesystem and network contract. Do not treat a manifest declaration by itself as isolation.

## Expectations

This project aims to be safe for agent-facing usage, which means:

- rejecting unsafe control characters where practical
- refusing unsafe write paths
- keeping raw secrets, stdin, stdout, and stderr out of canonical approval and evidence bindings
- preserving only audit-safe identity and command metadata in durable artifacts
- preserving machine-readable error behavior

Please report bypasses or unsafe edge cases.
