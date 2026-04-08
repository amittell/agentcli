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
            "program": "sh",
            "args": ["-lc", "curl -H \"Authorization: Bearer $TOOL_ACCESS_TOKEN\" https://api.example.com/deploy"]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "api-service" }
        }
      ]
    }
  ]
}
```

This example uses `sh -lc` intentionally. Structured `shell.args` are passed literally by `agentcli`, so shell variable expansion only happens when you opt into an explicit shell wrapper. For tools that can read credentials directly from the environment, prefer invoking them without `sh -lc`.

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

## Quick Setup: oidc-token-exchange

Use this when you have an existing token (from another identity provider, CI system, or
upstream service) and need to exchange it for a new token with different scope, audience,
or type. Implements OAuth 2.0 Token Exchange (RFC 8693).

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "exchange-service",
      "provider": "oidc-token-exchange",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/mesh-worker",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "exchange",
        "scopes": ["api.read"],
        "audience": "https://downstream.example.com",
        "required": true,
        "provider_config": {
          "token_endpoint": "https://auth.example.com/oauth/token",
          "subject_token_env": "UPSTREAM_TOKEN"
        }
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "EXCHANGED_TOKEN" },
            "required": true,
            "redact": true
          }
        ],
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "mesh-call",
      "name": "Service Mesh Call",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "call-downstream",
          "name": "Call Downstream Service",
          "shell": {
            "program": "sh",
            "args": ["-lc", "curl -H \"Authorization: Bearer $EXCHANGED_TOKEN\" https://downstream.example.com/api"]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "exchange-service" }
        }
      ]
    }
  ]
}
```

### Required fields

| Field | Location | Required |
|---|---|---|
| `token_endpoint` | `auth.provider_config.token_endpoint` | Yes |
| `subject_token_env` | `auth.provider_config.subject_token_env` | Yes (or use `auth.inputs.subject_token.value_from`) |
| `client_id` | `auth.provider_config.client_id` | No |
| `client_secret` | `auth.provider_config.client_secret` or `auth.inputs.client_secret` | No |
| `subject_token_type` | `auth.provider_config.subject_token_type` | No (defaults to `urn:ietf:params:oauth:token-type:access_token`) |
| `scopes` | `auth.scopes` | No |
| `audience` | `auth.audience` | No |

### Run it

```bash
export UPSTREAM_TOKEN="eyJhbGciOi..."
agentcli exec manifest.json call-downstream
```

Preview without executing:

```bash
agentcli exec manifest.json call-downstream --dry-run --identity-debug
```

### When to use this provider

Use `oidc-token-exchange` for service mesh token exchange, cross-tenant delegation, or
scope reduction. The token endpoint must support the RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange`
grant type. The provider also supports downscope handoff for passing a reduced-privilege
token to downstream tasks.

## Quick Setup: azure-managed-identity

Use this when running on Azure VMs, App Service, or Container Instances with managed
identity enabled. The provider acquires tokens from the Azure Instance Metadata Service
(IMDS) at `169.254.169.254`.

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "azure-service",
      "provider": "azure-managed-identity",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/azure-worker",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "required": true,
        "provider_config": {
          "resource": "https://management.azure.com/"
        }
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "AZURE_ACCESS_TOKEN" },
            "required": true,
            "redact": true
          }
        ],
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "azure-ops",
      "name": "Azure Operations",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "list-resources",
          "name": "List Resources",
          "shell": {
            "program": "sh",
            "args": ["-lc", "curl -H \"Authorization: Bearer $AZURE_ACCESS_TOKEN\" \"https://management.azure.com/subscriptions?api-version=2022-12-01\""]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "azure-service" }
        }
      ]
    }
  ]
}
```

### Required fields

| Field | Location | Required |
|---|---|---|
| `resource` | `auth.provider_config.resource` | Yes (e.g. `https://management.azure.com/`, `https://vault.azure.net/`, `https://graph.microsoft.com/`) |
| `client_id` | `auth.provider_config.client_id` | No (required for user-assigned managed identities) |

### Run it

```bash
agentcli exec manifest.json list-resources
```

Preview the identity resolution:

```bash
agentcli identity resolve manifest.json list-resources
```

### When to use this provider

This provider only works inside Azure environments where managed identity is enabled.
Outside Azure, the IMDS endpoint at `169.254.169.254` is not reachable and the provider
fails with: `Azure IMDS endpoint not reachable. This provider requires an Azure environment
with managed identity enabled.` For user-assigned managed identities, set `client_id` to
the managed identity's client ID. For system-assigned identities, omit `client_id`.

## Quick Setup: aws-sts-assume-role

Use this to assume an IAM role via AWS Security Token Service. The provider implements
AWS Signature Version 4 signing with no external dependencies.

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "aws-service",
      "provider": "aws-sts-assume-role",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/aws-deployer",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "required": true,
        "provider_config": {
          "role_arn": "arn:aws:iam::123456789012:role/AgentDeployRole"
        }
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_key_id.value",
            "target": { "kind": "env", "name": "AWS_ACCESS_KEY_ID" },
            "required": true,
            "redact": true
          },
          {
            "source": "credentials.secret_access_key.value",
            "target": { "kind": "env", "name": "AWS_SECRET_ACCESS_KEY" },
            "required": true,
            "redact": true
          },
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "AWS_SESSION_TOKEN" },
            "required": true,
            "redact": true
          }
        ],
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "aws-deploy",
      "name": "AWS Deploy",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "list-buckets",
          "name": "List S3 Buckets",
          "shell": {
            "program": "aws",
            "args": ["s3", "ls"]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "aws-service" }
        }
      ]
    }
  ]
}
```

### Required fields

| Field | Location | Required |
|---|---|---|
| `role_arn` | `auth.provider_config.role_arn` | Yes |
| `region` | `auth.provider_config.region` | No (defaults to `AWS_DEFAULT_REGION`, `AWS_REGION`, or `us-east-1`) |
| `session_name` | `auth.provider_config.session_name` | No (defaults to `agentcli-session`) |
| `duration_seconds` | `auth.provider_config.duration_seconds` | No (defaults to `3600`) |
| `external_id` | `auth.provider_config.external_id` | No |

Requires `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the environment. If you are
chaining from an existing session, `AWS_SESSION_TOKEN` is also accepted.

### Run it

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="wJalr..."
agentcli exec manifest.json list-buckets
```

Preview the assumed role session:

```bash
agentcli exec manifest.json list-buckets --dry-run --identity-debug
```

### When to use this provider

Use `aws-sts-assume-role` for cross-account access, limited-privilege role assumption,
or when you need temporary credentials scoped to a specific role. The provider includes
full AWS Signature V4 signing and does not require the AWS SDK. The three credential
values (access key, secret key, session token) are materialized into the subprocess
environment via separate presentation bindings, matching the standard AWS credential
environment variables.

## Quick Setup: gcp-workload-identity

Use this when running on GCP Compute Engine, Cloud Run, or GKE with a service account
attached. The provider acquires tokens from the GCP metadata server at
`metadata.google.internal`.

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "gcp-service",
      "provider": "gcp-workload-identity",
      "subject": {
        "kind": "service",
        "principal": "agent://myorg/gcp-worker",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        "required": true
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "GCP_ACCESS_TOKEN" },
            "required": true,
            "redact": true
          }
        ],
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "gcp-ops",
      "name": "GCP Operations",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "list-instances",
          "name": "List Compute Instances",
          "shell": {
            "program": "sh",
            "args": ["-lc", "curl -H \"Authorization: Bearer $GCP_ACCESS_TOKEN\" \"https://compute.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances\""]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "gcp-service" }
        }
      ]
    }
  ]
}
```

### Required fields

| Field | Location | Required |
|---|---|---|
| `scopes` | `auth.scopes` or `auth.provider_config.scopes` | Yes (non-empty array, e.g. `["https://www.googleapis.com/auth/cloud-platform"]`) |
| `service_account_email` | `auth.provider_config.service_account_email` | No (for impersonating a specific service account) |

### Run it

```bash
agentcli exec manifest.json list-instances
```

Resolve identity without executing:

```bash
agentcli identity resolve manifest.json list-instances
```

### When to use this provider

This provider only works inside GCP environments where the metadata server is reachable.
Outside GCP, the provider fails with: `GCP metadata server not reachable. This provider
requires a GCP environment with workload identity enabled.` When `service_account_email`
is specified, the metadata server returns a token for that specific service account
(impersonation). Otherwise it uses the default service account attached to the instance.

## Quick Setup: spiffe-jwt-svid

Use this in SPIFFE-enabled Kubernetes clusters running SPIRE or Istio. The provider
acquires JWT-SVIDs (SPIFFE Verifiable Identity Documents) from a file on disk or the
SPIFFE Workload API.

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "spiffe-service",
      "provider": "spiffe-jwt-svid",
      "subject": {
        "kind": "service",
        "principal": "spiffe://example.org/my-agent",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "audience": "spiffe://example.org/downstream",
        "required": true,
        "provider_config": {
          "svid_file": "/var/run/secrets/spiffe/svid.jwt"
        }
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "SPIFFE_JWT_SVID" },
            "required": true,
            "redact": true
          }
        ],
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "mesh-ops",
      "name": "Service Mesh Operations",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "call-peer",
          "name": "Call Peer Service",
          "shell": {
            "program": "sh",
            "args": ["-lc", "curl -H \"Authorization: Bearer $SPIFFE_JWT_SVID\" https://peer.example.svc.cluster.local/api"]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "spiffe-service" }
        }
      ]
    }
  ]
}
```

### Required fields

| Field | Location | Required |
|---|---|---|
| `audience` | `auth.audience` or `auth.provider_config.audience` | Yes |
| `svid_file` | `auth.provider_config.svid_file` | No (path to a file containing the JWT-SVID, e.g. Kubernetes projected volume) |
| `workload_api_socket` | `auth.provider_config.workload_api_socket` | No (defaults to `SPIFFE_ENDPOINT_SOCKET` env var; supports `http://` or `https://` endpoints) |

The provider tries `svid_file` first, then falls back to the Workload API socket. For
Unix domain sockets (the standard SPIRE agent configuration), use the file-based approach
since standard Node `fetch()` does not support UDS connections.

### Run it

```bash
agentcli exec manifest.json call-peer
```

Preview identity resolution:

```bash
agentcli exec manifest.json call-peer --dry-run --identity-debug
```

### When to use this provider

Use `spiffe-jwt-svid` in Kubernetes clusters with SPIRE agent or Istio that project
JWT-SVIDs into pod volumes. The `svid_file` approach works with Kubernetes projected
service account tokens and SPIRE agent projected volumes. The HTTP-based Workload API
approach works with SPIRE agents or Envoy SDS sidecars configured with TCP listeners.
The provider parses JWT claims (sub, aud, exp, iss) from the SVID for audit purposes
but does not verify the signature, as that is the responsibility of the consuming service's
SPIFFE trust bundle verifier.

## Quick Setup: entra-agent-id

Use this for enterprise agent identities registered in the Microsoft Entra Agent Registry.
This is distinct from `azure-managed-identity`: Entra Agent ID uses JWT bearer client
assertions and supports agent-specific Conditional Access policies and lifecycle governance.

### Manifest

```json
{
  "version": "0.2",
  "identity_profiles": [
    {
      "id": "entra-agent",
      "provider": "entra-agent-id",
      "subject": {
        "kind": "service",
        "principal": "agent://entra/contoso/my-agent",
        "delegation_mode": "none"
      },
      "auth": {
        "mode": "service",
        "scopes": ["https://graph.microsoft.com/.default"],
        "required": true,
        "provider_config": {
          "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
          "blueprint_app_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
          "agent_identity_id": "c3d4e5f6-a7b8-9012-cdef-123456789012"
        }
      },
      "trust": {
        "level": "supervised"
      },
      "presentation": {
        "bindings": [
          {
            "source": "credentials.access_token.value",
            "target": { "kind": "env", "name": "ENTRA_ACCESS_TOKEN" },
            "required": true,
            "redact": true
          }
        ],
        "cleanup": "always"
      }
    }
  ],
  "workflows": [
    {
      "id": "entra-ops",
      "name": "Entra Operations",
      "contract": {
        "sandbox": "permissive",
        "network": "unrestricted",
        "audit": "always"
      },
      "tasks": [
        {
          "id": "query-graph",
          "name": "Query Microsoft Graph",
          "shell": {
            "program": "sh",
            "args": ["-lc", "curl -H \"Authorization: Bearer $ENTRA_ACCESS_TOKEN\" https://graph.microsoft.com/v1.0/me"]
          },
          "target": { "session_target": "shell" },
          "identity": { "ref": "entra-agent" }
        }
      ]
    }
  ]
}
```

### Required fields

| Field | Location | Required |
|---|---|---|
| `tenant_id` | `auth.provider_config.tenant_id` | Yes (Entra tenant GUID) |
| `blueprint_app_id` | `auth.provider_config.blueprint_app_id` | Yes (blueprint application GUID, used as `client_id`) |
| `agent_identity_id` | `auth.provider_config.agent_identity_id` | Yes (agent identity GUID) |
| `authority` | `auth.provider_config.authority` | No (defaults to `https://login.microsoftonline.com/{tenant_id}`) |

The client assertion (a platform-issued JWT) is resolved in this order:

1. `AGENTCLI_ENTRA_CLIENT_ASSERTION` environment variable
2. `auth.inputs.client_assertion.value_from` (env, file, or command indirection)
3. `auth.provider_config.client_assertion` (inline string or `value_from`)
4. IMDS fallback (acquires a managed identity token for the blueprint app)

### Run it

```bash
export AGENTCLI_ENTRA_CLIENT_ASSERTION="eyJhbGciOi..."
agentcli exec manifest.json query-graph
```

Preview the resolved identity session:

```bash
agentcli exec manifest.json query-graph --dry-run --identity-debug
```

### When to use this provider

Use `entra-agent-id` when your agent is registered in the Microsoft Entra Agent Registry
and needs to authenticate using agent-specific credentials. The provider uses client
credentials flow with a JWT bearer assertion (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`),
which is distinct from the IMDS-based flow used by `azure-managed-identity`. On Azure
infrastructure, the provider can fall back to IMDS to acquire the client assertion
automatically. Outside Azure, you must provide the assertion via environment variable,
file, or command source.

## Dynamic Credential Acquisition

The `value_from` pattern supports four sources for resolving sensitive values without
embedding them in the manifest:

| Source | Usage | Example |
|---|---|---|
| `env` | Read from an environment variable | `{ "env": "MY_SECRET" }` |
| `file` | Read from a file on disk | `{ "file": "/run/secrets/token" }` |
| `literal` | Inline value (use sparingly) | `{ "literal": "static-value" }` |
| `command` | Run a shell command and capture stdout | `{ "command": "vault kv get -field=token secret/app" }` |

The `command` source runs the specified string through the platform shell with a
30-second timeout. On Unix-like hosts this uses `sh -c`; on Windows it uses
`cmd.exe /d /s /c`. It captures stdout, trims whitespace, resolves relative
paths from the current working directory, and returns the result. If the command
fails (non-zero exit), the value resolves to null.

### When to use `command`

Use `command` when credentials are managed by an external tool that exposes them
via CLI:

```json
"inputs": {
  "client_secret": {
    "value_from": {
      "command": "vault kv get -field=api_key secret/myapp"
    }
  }
}
```

Common patterns:

| Tool | Command |
|---|---|
| HashiCorp Vault | `vault kv get -field=token secret/path` |
| 1Password CLI | `op item get "API Key" --fields credential` |
| AWS SSM | `aws ssm get-parameter --name /app/secret --with-decryption --query Parameter.Value --output text` |
| Stripe Projects | `stripe projects env --pull --format env 2>/dev/null \| grep STRIPE_API_KEY \| cut -d= -f2` |
| macOS Keychain | `security find-generic-password -a account -s service -w` |
| Doppler | `doppler secrets get API_KEY --plain` |

### Security considerations

- The command inherits the current environment, so tools that use env-based auth
  (like `VAULT_TOKEN` for Vault) will work transparently.
- The command runs with the same permissions as the `agentcli` process.
- Stdout is captured and trimmed. Stderr is discarded.
- The 30-second timeout prevents hanging on interactive prompts.
- Command values are NOT persisted in audit records. Only the fact that a command
  source was used is recorded.

### Example: Stripe Projects credential sync

[stripe-projects.json](../examples/stripe-projects.json) demonstrates using
`stripe projects env --pull` as a credential source alongside direct `STRIPE_API_KEY`
binding. The workflow syncs project credentials, checks project status, and runs
database migrations with strict trust enforcement and failure triage.

```bash
stripe projects env --pull          # populate local .env
agentcli validate examples/stripe-projects.json
agentcli exec examples/stripe-projects.json check-project-status --signer none
```

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

## Sandbox and Network Contract Modes

The trust settings above answer "is this identity trusted enough to run this task?"

The `contract` block also answers "what execution boundary is this task supposed to run inside?"

### Sandbox modes

| Mode | Meaning |
|---|---|
| `none` | No sandboxing intent is declared. |
| `permissive` | The task may run locally without strong isolation, but the manifest still records boundary intent. |
| `strict` | The task is intended to run in a stronger sandbox. |

### Network modes

| Mode | Meaning |
|---|---|
| `unrestricted` | Normal network access is allowed. |
| `restricted` | Network access should be narrowed by the runtime or environment. |
| `none` | The task should run without network access. |

### What local `agentcli exec` enforces today

Local `agentcli exec` fully enforces some contract checks, and records others as advisory intent:

- `allowed_paths`: enforced
- `required_trust_level` + `trust_enforcement`: enforced
- `audit`: enforced
- `sandbox`: enforced on macOS when `sandbox-exec` is available; advisory on other OSes
- `network`: enforced on macOS when `sandbox-exec` is available for `restricted` and `none`; advisory on other OSes

That is why you may see warnings such as:

```text
contract.sandbox is "strict" but no supported local sandbox runner is available; execution proceeds without OS-level sandbox enforcement
```

or:

```text
contract.network is "none" but no supported local sandbox runner is available; execution proceeds without OS-level network enforcement
```

These warnings do not mean the manifest is invalid. They mean the declaration is valid, but the local machine does not currently have a supported sandbox backend for that boundary.

Use this rule of thumb:

- local testing: `permissive` / `unrestricted` is usually fine
- macOS local enforcement: use `strict`, `restricted`, or `none` and let `sandbox-exec` enforce the boundary
- other OSes: keep the contract declaration, but rely on a backend or environment that can enforce it until an OS-specific adapter is available
- if you want no warning during local runs on an unsupported machine, use `sandbox: "none"` and `network: "unrestricted"`

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
    "program": "sh",
    "args": ["-lc", "curl -H \"Authorization: Bearer $TOOL_ACCESS_TOKEN\" https://api.example.com/deploy"],
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

## Stripe Identity Step-Up For Sensitive Commands

Use Stripe Identity as an additional verification signal, not as the task's primary runtime credential.

Recommended pattern:

1. Put the normal CLI or service credential in an `identity_profile`.
2. Put org, delegation, run, and non-secret verification references in `identity.subject.attributes`.
3. Require a short-lived signed JWT in `authorization_proof` for sensitive tasks.
4. Use `jwks_uri` or `public_key` so `verify.required: true` enforces signature-backed verification.
5. If you use OPA, request the `actor` and `step_up` sections so policy can see the actor chain and verification summary without reading raw tokens.

The dedicated example manifest is:

- [`stripe-identity-step-up.json`](../examples/stripe-identity-step-up.json)
- [`stripe-identity-step-up.rego`](../examples/stripe-identity-step-up.rego)
- [`guide-testing-stripe-identity-step-up.md`](guide-testing-stripe-identity-step-up.md)

That example shows:

- normal runtime auth via `identity_profiles`
- a sensitive task gated by `authorization_proof`
- OPA authorization using the `actor` and `step_up` request sections
- actor metadata flowing from `identity.subject.attributes`
- evidence payload binding with `actor_context` and `authorization_proof`

## Example Manifests

The `examples/` directory contains complete, runnable manifests for common use cases:

| Example | Use case |
|---|---|
| `identity-v2.json` | Basic v0.2 identity with `none` and `env-bearer` providers |
| `oidc-service-auth.json` | OIDC client credentials with token materialization |
| `trust-enforcement.json` | Graduated trust levels with strict and advisory enforcement |
| `authorization-proof.json` | JWT-based manifest authorization proof with signature-backed verification |
| `stripe-identity-step-up.json` | Step-up proof for sensitive commands plus actor-context audit metadata |
| `cloud-workload.json` | Azure managed identity for cloud workloads |

Run any example locally:

```bash
agentcli validate examples/trust-enforcement.json
agentcli exec examples/trust-enforcement.json collect-data --dry-run --signer none
agentcli identity resolve examples/cloud-workload.json fetch-prices
```
