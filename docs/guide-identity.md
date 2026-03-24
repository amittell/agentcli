# Identity Setup Guide

## Overview

Identity profiles tell agentcli *who* a task runs as and *what credentials* it carries.
When agentcli executes a v0.2 manifest, it resolves the task's identity profile, acquires
credentials from the configured provider, materializes those credentials into the
subprocess environment, and records a redacted audit trail.

**When you need identity profiles:**

- Your tool needs an API token, OAuth access token, or service credential at runtime.
- You need audit records that attribute executions to a specific principal.
- You need trust-level enforcement on tasks (e.g. production tasks require supervised trust).
- You need verifiable execution evidence signed against a declared identity.

**When you do not need identity profiles:**

- The task has no authentication requirements and you do not need principal attribution.
  Use `"provider": "none"` or omit the identity block entirely.

## Choosing a Provider

| Situation | Provider | Auth mode |
|---|---|---|
| Bearer token already in an environment variable | `env-bearer` | `service` |
| Bearer token stored in a file on disk | `file-bearer` | `service` |
| Service-to-service OAuth (client credentials grant) | `oidc-client-credentials` | `service` |
| Exchange one token for another (RFC 8693) | `oidc-token-exchange` | `exchange` |
| Running on an Azure VM, App Service, or Container Instance | `azure-managed-identity` | `service` |
| Running on AWS EC2, Lambda, ECS, or EKS | `aws-sts-assume-role` | `service` |
| Running on GCP Compute Engine, Cloud Run, or GKE | `gcp-workload-identity` | `service` |
| Running in a SPIFFE-enabled Kubernetes cluster | `spiffe-jwt-svid` | `service` |
| Running as an Entra Agent ID in Microsoft Entra | `entra-agent-id` | `service` |
| No credentials needed | `none` | `none` |

List available providers at any time:

```bash
agentcli identity providers
```

## Quick Setup: env-bearer

The most common case. You have a bearer token in an environment variable and want agentcli
to pass it to the tool process.

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "api-service",
      "provider": "env-bearer",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/api-service",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "scopes": ["read", "write"],
        "required": true,
        "provider_config": {
          "token_env": "MY_API_TOKEN"
        }
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "TOOL_ACCESS_TOKEN" },
            "required": true,
            "redact": true
          }
        ],
        "handoff": "none",
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "deploy",
      "name": "Deploy Workflow",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "call-api",
          "name": "Call API",
          "shell": {
            "program": "curl",
            "args": ["-H", "Authorization: Bearer $TOOL_ACCESS_TOKEN", "https://api.example.com/deploy"]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "api-service" }
        }
      ]
    }
  ]
}
```

### Run it

```bash
export MY_API_TOKEN="your-token-here"
agentcli exec manifest.json call-api
```

The flow:

1. agentcli reads `MY_API_TOKEN` from the environment.
2. The presentation binding copies the token value into `TOOL_ACCESS_TOKEN` in the subprocess environment.
3. The `curl` command receives the token via its environment.
4. After execution, credentials are cleaned up and an audit record is written.

### Dry run

Preview what agentcli will do without executing the command:

```bash
agentcli exec manifest.json call-api --dry-run
```

Add `--identity-debug` to see the resolved (redacted) identity session:

```bash
agentcli exec manifest.json call-api --dry-run --identity-debug
```

### Making auth optional

Set `"required": false` in the auth block. If the environment variable is not set, agentcli
produces an empty credential session instead of failing:

```json
"auth": {
  "mode": "service",
  "required": false,
  "provider_config": {
    "token_env": "MY_API_TOKEN"
  }
}
```

## Quick Setup: oidc-client-credentials

Use this when you need to obtain a fresh access token from an OAuth 2.0 / OIDC token endpoint
using the client credentials grant (RFC 6749 Section 4.4).

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "oidc-service",
      "provider": "oidc-client-credentials",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/oidc-worker",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "scopes": ["api.read", "api.write"],
        "audience": "https://api.example.com",
        "required": true,
        "provider_config": {
          "token_endpoint": "https://auth.example.com/oauth/token",
          "client_id": "my-client-id",
          "client_secret": {
            "value_from": { "env": "OIDC_CLIENT_SECRET" }
          }
        }
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "ACCESS_TOKEN" },
            "required": true,
            "redact": true
          }
        ],
        "handoff": "none",
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "sync",
      "name": "Data Sync",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "sync-data",
          "name": "Sync Data",
          "shell": {
            "program": "python3",
            "args": ["sync.py"]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "oidc-service" }
        }
      ]
    }
  ]
}
```

### Run it

```bash
export OIDC_CLIENT_SECRET="your-client-secret"
agentcli exec manifest.json sync-data
```

The flow:

1. agentcli reads the client secret from `OIDC_CLIENT_SECRET` via the `value_from` indirection.
2. It performs a POST to the token endpoint with `grant_type=client_credentials`, `client_id`, `client_secret`, `scope`, and `audience`.
3. The returned access token is placed into the `ACCESS_TOKEN` env var for the subprocess.
4. If the token endpoint returns `expires_in`, the session records the expiration time.

### Client secret sources

The client secret supports three resolution methods:

**Inline string** (not recommended for production):

```json
"client_secret": "literal-secret-value"
```

**Environment variable (recommended):**

```json
"client_secret": {
  "value_from": { "env": "OIDC_CLIENT_SECRET" }
}
```

**File on disk:**

```json
"client_secret": {
  "value_from": { "file": "/run/secrets/oidc-client-secret" }
}
```

You can also place the secret in `auth.inputs` instead of `provider_config`:

```json
"auth": {
  "inputs": {
    "client_secret": {
      "value_from": { "env": "OIDC_CLIENT_SECRET" }
    }
  },
  "provider_config": {
    "token_endpoint": "https://auth.example.com/oauth/token",
    "client_id": "my-client-id"
  }
}
```

### Required fields

| Field | Location | Required |
|---|---|---|
| `token_endpoint` | `auth.provider_config.token_endpoint` | Yes |
| `client_id` | `auth.provider_config.client_id` | Yes |
| `client_secret` | `auth.provider_config.client_secret` or `auth.inputs.client_secret` | Yes |
| `scopes` | `auth.scopes` | No |
| `audience` | `auth.audience` | No |
| `resource` | `auth.resource` | No |

The token endpoint must use `https://` unless you explicitly pass `allowInsecure` in the
resolution context.

## Quick Setup: file-bearer

Use this when a bearer token is stored in a file, for example a Kubernetes service account
token at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "k8s-service",
      "provider": "file-bearer",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/k8s-worker",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "required": true,
        "provider_config": {
          "token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
        }
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "K8S_TOKEN" },
            "required": true,
            "redact": true
          }
        ],
        "handoff": "none",
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "k8s-ops",
      "name": "Kubernetes Operations",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "list-pods",
          "name": "List Pods",
          "shell": {
            "program": "kubectl",
            "args": ["get", "pods"]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "k8s-service" }
        }
      ]
    }
  ]
}
```

### Run it

```bash
agentcli exec manifest.json list-pods
```

### Indirect file path via environment variable

Instead of hardcoding the file path, resolve it from an environment variable:

```json
"auth": {
  "mode": "service",
  "required": true,
  "inputs": {
    "token_file": {
      "value_from": { "env": "TOKEN_FILE_PATH" }
    }
  }
}
```

```bash
export TOKEN_FILE_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
agentcli exec manifest.json list-pods
```

### Security note

The file-bearer provider checks file permissions at resolution time. If the token file is
world-readable, a warning is included in `provider_assertions.permission_warning` and
appears in the audit record. Restrict token files to mode `0600`.

## Trust Levels

Trust levels declare how much autonomy a task's identity is granted. There are four levels,
from least to most privileged:

| Level | Meaning |
|---|---|
| `untrusted` | No trust. Suitable for sandboxed or throwaway operations. |
| `restricted` | Limited trust. May read but not modify sensitive resources. |
| `supervised` | Standard operating trust. Human oversight assumed. Default if not specified. |
| `autonomous` | Full autonomy. The task can act independently without human oversight. |

### Setting the trust level

Set the trust level on the identity profile:

```json
"trust": {
  "level": "supervised"
}
```

### Requiring a trust level on a contract

Set `required_trust_level` and `trust_enforcement` on the workflow or task contract:

```json
"contract": {
  "sandbox": "permissive",
  "network": "unrestricted",
  "audit": "always",
  "required_trust_level": "supervised",
  "trust_enforcement": "strict"
}
```

### Enforcement modes

| Mode | Behavior when trust is below required level |
|---|---|
| `none` | Recorded in audit but execution proceeds. No warning. |
| `advisory` | A warning is emitted and recorded. Execution proceeds. |
| `strict` | Execution fails with error code `trust_level_insufficient`. |

### Example: require supervised trust for production tasks

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "prod-agent",
      "provider": "env-bearer",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/prod-deployer"
      },
      "auth": {
        "mode": "service",
        "required": true,
        "provider_config": { "token_env": "DEPLOY_TOKEN" }
      },
      "trust": { "level": "supervised" }
    }
  ],
  "workflows": [
    {
      "id": "prod-deploy",
      "name": "Production Deploy",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always",
        "required_trust_level": "supervised",
        "trust_enforcement": "strict"
      },
      "tasks": [
        {
          "id": "deploy",
          "name": "Deploy",
          "shell": { "program": "deploy.sh", "args": [] },
          "target": { "session_target": "shell" },
          "identity": { "ref": "prod-agent" }
        }
      ]
    }
  ]
}
```

If a task references an identity with `"level": "restricted"` and the contract enforces
`"trust_enforcement": "strict"` with `"required_trust_level": "supervised"`, execution
will fail:

```
Error: Trust level "restricted" is below required "supervised"
```

## Credential Presentation

Presentation bindings control how resolved credentials are delivered to the subprocess.

### Environment variable binding (most common)

The binding reads a value from the credential session using a dot-path and writes it to
a named environment variable in the subprocess:

```json
"presentation": {
  "bindings": [
    {
      "source": "credentials.access_token.value",
      "target": { "kind": "env", "name": "AZURE_ACCESS_TOKEN" },
      "required": true,
      "redact": true
    }
  ]
}
```

After resolution, the subprocess will have `AZURE_ACCESS_TOKEN` set to the token value.

### File binding

For tools that read credentials from a file path, use a file target. agentcli writes the
credential to a temporary file with mode `0600` and cleans it up after execution:

```json
"presentation": {
  "bindings": [
    {
      "source": "credentials.access_token.value",
      "target": { "kind": "file", "prefix": "my-cred" },
      "format": "raw"
    }
  ]
}
```

The temporary file is created under the system temp directory. Use `--presentation-debug`
to see the materialization summary including temp file counts:

```bash
agentcli exec manifest.json my-task --dry-run --presentation-debug
```

### Multiple bindings

You can bind multiple values from the same session. For example, bind both the token and
the token type:

```json
"bindings": [
  {
    "source": "credentials.access_token.value",
    "target": { "kind": "env", "name": "API_TOKEN" }
  },
  {
    "source": "credentials.access_token.audience",
    "target": { "kind": "env", "name": "API_AUDIENCE" }
  }
]
```

### Source paths

The `source` field is a dot-delimited path into the credential session object. Common paths:

| Path | Value |
|---|---|
| `credentials.access_token.value` | The raw token string |
| `credentials.access_token.audience` | The audience claim |
| `credentials.access_token.scopes` | Array of granted scopes |
| `credentials.access_token.expires_at` | ISO 8601 expiration timestamp |
| `subject.principal` | The resolved principal |
| `provider_assertions.token_endpoint` | The token endpoint used (OIDC providers) |

### Format options

The `format` field on a binding controls how the value is serialized before writing:

| Format | Behavior |
|---|---|
| `raw` | String conversion (default) |
| `json` | JSON-encoded |
| `base64` | Base64-encoded |

### Cleanup

Presentation supports a `cleanup` field that controls when temporary files are deleted:

```json
"presentation": {
  "cleanup": "always",
  "bindings": [...]
}
```

Cleanup runs after execution completes, including on dry runs where materialization occurred.

## Evidence and Attestation

Evidence profiles produce cryptographically signed records that bind an execution to a
declared identity, command, and result. This is separate from the signing-based attestation
in v0.1 manifests.

### Configure an evidence profile

Define an evidence profile at the top level of the manifest:

```json
"evidence_profiles": [
  {
    "id": "ssh-evidence",
    "provider": "ssh",
    "payload": {
      "bind": ["execution_id", "declared_identity", "contract", "command", "result"],
      "format": "canonical-json"
    },
    "verify": { "required": false }
  }
]
```

The `bind` array controls which execution fields are included in the signed payload.
Available bind targets: `execution_id`, `declared_identity`, `resolved_identity`,
`authorization_proof`, `authorization`, `contract`, `command`, `result`.

### Reference the evidence profile from a task

```json
"tasks": [
  {
    "id": "secured-task",
    "name": "Secured Task",
    "shell": { "program": "echo", "args": ["hello"] },
    "target": { "session_target": "shell" },
    "identity": { "ref": "my-identity" },
    "evidence": { "ref": "ssh-evidence" }
  }
]
```

### Run with evidence

```bash
agentcli exec manifest.json secured-task
```

The evidence provider signs the payload using your SSH key (discovered automatically from
`~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, or `~/.ssh/id_rsa`, or set explicitly via
`AGENTCLI_SIGNING_KEY`).

To require evidence and fail if signing is not possible:

```bash
agentcli exec manifest.json secured-task --require-evidence
```

### Verify after execution

Use the execution ID from the result to verify:

```bash
agentcli verify <execution-id>
```

Provide an explicit allowed signers file if needed:

```bash
agentcli verify <execution-id> --allowed-signers ~/.ssh/allowed_signers
```

The verify command reads the audit log, finds the record with the matching execution ID,
and checks the attestation signature against the recorded principal.

### Full example with identity and evidence

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "build-agent",
      "provider": "env-bearer",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/build-agent"
      },
      "auth": {
        "mode": "service",
        "required": true,
        "provider_config": { "token_env": "BUILD_TOKEN" }
      },
      "trust": { "level": "supervised" },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "CI_TOKEN" },
            "redact": true
          }
        ],
        "cleanup": "always"
      }
    }
  ],
  "evidence_profiles": [
    {
      "id": "ssh-evidence",
      "provider": "ssh",
      "payload": {
        "bind": ["execution_id", "declared_identity", "contract", "command", "result"],
        "format": "canonical-json"
      },
      "verify": { "required": false }
    }
  ],
  "workflows": [
    {
      "id": "ci",
      "name": "CI Pipeline",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "build",
          "name": "Build",
          "shell": { "program": "make", "args": ["build"] },
          "target": { "session_target": "shell" },
          "identity": { "ref": "build-agent" },
          "evidence": { "ref": "ssh-evidence" }
        }
      ]
    }
  ]
}
```

```bash
export BUILD_TOKEN="ghp_xxxxxxxxxxxx"
agentcli exec manifest.json build
```

## Audit Records

Every v0.2 execution with `"audit": "always"` writes an append-only audit record. Records
are stored as newline-delimited JSON in `~/.agentcli/audit.ndjson` (or the path set by
`AGENTCLI_HOME`).

### Reading audit records

```bash
agentcli audit
agentcli audit --limit 5
```

### What an audit record contains

A v0.2 audit record includes:

```json
{
  "execution_id": "a1b2c3d4e5f6...",
  "timestamp": "2026-03-22T10:30:00.000Z",
  "source": {
    "workflow_id": "deploy",
    "task_id": "call-api"
  },
  "declared_identity": {
    "provider": "env-bearer",
    "subject": {
      "principal": "agent://myorg/api-service",
      "kind": "service",
      "issuer": null
    },
    "trust_level": "supervised"
  },
  "resolved_identity": {
    "provider": "env-bearer",
    "subject": { "principal": "agent://myorg/api-service" },
    "trust": { "declared_level": "supervised", "effective_level": "supervised" },
    "credentials": {
      "access_token": {
        "kind": "bearer",
        "value": "[REDACTED]",
        "audience": null,
        "scopes": ["read", "write"],
        "expires_at": null
      }
    },
    "credential_summary": {
      "credential_types": ["bearer"],
      "expires_at": null
    }
  },
  "principal_used": "agent://myorg/api-service",
  "trust": {
    "declared_level": "supervised",
    "effective_level": "supervised"
  },
  "contract": {
    "sandbox": "permissive",
    "network": "unrestricted",
    "audit": "always"
  },
  "command": {
    "program": "curl",
    "args": ["-H", "Authorization: Bearer $TOOL_ACCESS_TOKEN", "https://api.example.com/deploy"],
    "cwd": "/home/user/project",
    "env_keys": ["TOOL_ACCESS_TOKEN"],
    "stdin_present": false
  },
  "hashes": {
    "command": "sha256:...",
    "result": "sha256:..."
  },
  "result": {
    "exit_code": 0,
    "signal": null,
    "timed_out": false,
    "duration_ms": 1234,
    "stdout_bytes": 42,
    "stderr_bytes": 0,
    "output_hash": "sha256:...",
    "structured_present": false
  },
  "warnings": [],
  "dry_run": false
}
```

### What is redacted

All credential values in `resolved_identity.credentials` are replaced with `[REDACTED]`.
The audit record never contains raw tokens, secrets, or access credentials. The
`credential_summary` field provides a safe overview of what credential types were present
and when they expire.

Stdout and stderr content is not stored in the audit record. Only byte counts and a
SHA-256 hash of the combined output are recorded.

## Troubleshooting

### "Identity provider not found"

The provider name in the identity profile does not match a registered provider. Check
the spelling and run `agentcli identity providers` to see all available providers.

```bash
agentcli identity providers
```

### "Bearer token not found: environment variable ... is not set or is empty"

The `token_env` environment variable is not set in the current shell. Export it before
running:

```bash
export MY_API_TOKEN="your-token"
agentcli exec manifest.json my-task
```

### "Token file not found" / "Token file is empty"

The file path in `provider_config.token_file` does not exist or the file contains only
whitespace. Verify the file exists and contains a token:

```bash
ls -la /path/to/token/file
cat /path/to/token/file | wc -c
```

### "Trust level ... is below required ..."

The task's identity trust level is lower than the contract's `required_trust_level` and
`trust_enforcement` is `strict`. Either raise the trust level on the identity profile or
lower the contract requirement:

```json
"trust": { "level": "supervised" }
```

### "Client secret could not be resolved"

The OIDC client credentials provider could not find the client secret. Check that:

- The `value_from.env` variable is exported in your shell.
- The `value_from.file` path exists and is readable.
- The secret is defined in either `auth.provider_config.client_secret` or `auth.inputs.client_secret`.

### "Token endpoint returned HTTP 4xx/5xx"

The OAuth token endpoint rejected the request. Common causes:

- Wrong `client_id` or `client_secret`.
- The `audience` or `scopes` are not configured on the OAuth server.
- The token endpoint URL is incorrect.

Test the token endpoint directly:

```bash
curl -X POST https://auth.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=my-client-id" \
  -d "client_secret=$OIDC_CLIENT_SECRET" \
  -d "scope=api.read api.write"
```

### "Authorization proof verification failed"

The authorization proof (JWT, detached signature, or certificate) did not pass verification.
Check that the proof value is current and matches the expected claims. Use `--dry-run` to
inspect the proof verification result without executing:

```bash
agentcli exec manifest.json my-task --dry-run
```

### "Authorization denied"

An external authorization provider rejected the request. Check the authorization policy
configuration and ensure the principal has the required permissions.

### Debug flags

Use these flags to get more detail during troubleshooting:

| Flag | What it shows |
|---|---|
| `--dry-run` | Full execution plan without running the command |
| `--identity-debug` | Redacted identity session and credential summary |
| `--presentation-debug` | Materialization summary (env keys, temp file counts) |

Example:

```bash
agentcli exec manifest.json my-task --dry-run --identity-debug --presentation-debug
```

### Validating identity resolution without execution

Resolve and display the identity session for a task without executing it:

```bash
agentcli identity resolve manifest.json my-task
```

Validate the delegation chain:

```bash
agentcli identity validate-delegation manifest.json my-task
```
