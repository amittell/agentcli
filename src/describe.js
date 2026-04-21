import { listTargets } from './targets.js';
import { MANIFEST_VERSION } from './schema.js';

export const COMMAND_DESCRIPTIONS = [
  {
    command: 'version',
    summary: 'Return package version and manifest spec version.'
  },
  {
    command: 'schema',
    summary: 'Emit machine-readable schema fragments for manifests, tasks, targets, and RPC payloads.'
  },
  {
    command: 'describe',
    summary: 'Emit narrative metadata for commands, targets, workflow objects, and RPC methods.'
  },
  {
    command: 'validate',
    summary: 'Validate a manifest from a file path, stdin, or raw JSON string.'
  },
  {
    command: 'compile',
    summary: 'Compile a manifest into a target-specific artifact, optionally writing it to disk safely under the current working directory.'
  },
  {
    command: 'convert',
    summary: 'Convert a v0.1 manifest to v0.2 with safe defaults for new identity, authorization, and evidence surfaces.'
  },
  {
    command: 'apply',
    summary: 'Upsert a manifest into an OpenClaw Scheduler runtime. Supports --adopt-by name for migrating existing jobs.'
  },
  {
    command: 'inspect',
    summary: 'Read scheduler runtime state with field masks, sanitization, and NDJSON output.'
  },
  {
    command: 'targets',
    summary: 'List available compilation targets with capabilities and feature support.'
  },
  {
    command: 'paths',
    summary: 'Show resolved agentcli home directory paths. Respects AGENTCLI_HOME and --home flag.'
  },
  {
    command: 'init',
    summary: 'Scaffold a new agentcli manifest in the current directory. Use --tool to wrap a specific CLI program.'
  },
  {
    command: 'exec',
    summary: 'Execute a shell-target task from a manifest with identity verification, contract enforcement, signing provider attestation, and audit logging. Use --signer to select a signing provider (ssh, none).'
  },
  {
    command: 'run',
    summary: 'Execute a shell-only workflow DAG locally from one or more scheduled roots. Trigger edges, conditions, and on_failure handlers are evaluated in-process.'
  },
  {
    command: 'identity',
    summary: 'Inspect identity providers, schemas, effective task identity, and delegation validation state.'
  },
  {
    command: 'authorization-proof',
    summary: 'List authorization proof methods, inspect verifier metadata, and verify a task’s configured proof.'
  },
  {
    command: 'authorization',
    summary: 'Inspect authorization providers and evaluate authorization for a task.'
  },
  {
    command: 'evidence',
    summary: 'Inspect evidence providers and provider metadata.'
  },
  {
    command: 'audit',
    summary: 'Read the local execution audit log.'
  },
  {
    command: 'approve',
    summary: 'Grant a local, single-use, ssh-signed approval record for a task whose approval.policy is "manual". Required before agentcli exec will run the task. Concurrent execs serialize on an fs-lockfile so at most one consumer wins per grant.'
  },
  {
    command: 'approvals',
    summary: 'List or revoke local approval records stored in ~/.agentcli/state/approvals.ndjson. Subcommands: list, revoke.'
  },
  {
    command: 'signing',
    summary: 'List available signing providers used for execution attestations.'
  },
  {
    command: 'verify',
    summary: 'Cryptographically verify an execution audit record. Dispatches to the signing provider that produced the attestation (e.g. ssh-signature dispatches to the ssh provider).'
  },
  {
    command: 'whoami',
    summary: 'Resolve and print the effective task identity, trust, and contract view without executing the task.'
  },
  {
    command: 'skill-path',
    summary: 'Print the resolved path to the bundled SKILL.md for agent auto-discovery.'
  },
  {
    command: 'registry',
    summary: 'Manage reusable manifest templates in ~/.agentcli/registry/. Subcommands: list, add, show, remove.'
  },
  {
    command: 'import',
    summary: 'Import a manifest from a tool directory. Looks for agentcli.json or package.json "agentcli" field and adds to registry.'
  },
  {
    command: 'merge',
    summary: 'Combine workflows from multiple manifests into one. Rejects duplicate workflow ids.'
  },
  {
    command: 'serve',
    summary: 'Run a line-delimited JSON-RPC server over stdio for agent integrations.'
  }
];

export const RPC_METHODS = [
  { method: 'agentcli.ping', summary: 'Health check for JSON-RPC clients.' },
  { method: 'agentcli.version', summary: 'Return package and manifest spec version.' },
  { method: 'agentcli.schema', summary: 'Return a schema fragment by name.' },
  { method: 'agentcli.describe', summary: 'Return descriptive metadata by topic.' },
  { method: 'agentcli.validate', summary: 'Validate a manifest object.' },
  { method: 'agentcli.compile', summary: 'Compile a manifest object to a named target.' },
  { method: 'agentcli.apply', summary: 'Apply a manifest to an OpenClaw Scheduler runtime.' },
  { method: 'agentcli.inspect', summary: 'Inspect a scheduler database when available.' },
  { method: 'agentcli.convert', summary: 'Convert a v0.1 manifest object to v0.2.' },
  { method: 'agentcli.identity.providers', summary: 'List registered identity providers.' },
  { method: 'agentcli.identity.schema', summary: 'Return metadata for a named identity provider.' },
  { method: 'agentcli.identity.resolve', summary: 'Resolve the effective identity for a task.' },
  { method: 'agentcli.identity.validateDelegation', summary: 'Validate a task identity delegation chain.' },
  { method: 'agentcli.authorizationProof.methods', summary: 'List registered authorization proof verifier methods.' },
  { method: 'agentcli.authorizationProof.schema', summary: 'Return metadata for a named authorization proof verifier.' },
  { method: 'agentcli.authorization.providers', summary: 'List registered authorization providers.' },
  { method: 'agentcli.authorization.schema', summary: 'Return metadata for a named authorization provider.' },
  { method: 'agentcli.authorization.evaluate', summary: 'Evaluate authorization for a task.' },
  { method: 'agentcli.evidence.providers', summary: 'List registered evidence providers.' },
  { method: 'agentcli.evidence.schema', summary: 'Return metadata for a named evidence provider.' }
];

export const RPC_NOTIFICATIONS = [
  {
    method: 'agentcli.ready',
    summary: 'Server startup notification emitted before request processing begins.',
    params: {
      ok: true,
      manifest_version: MANIFEST_VERSION
    }
  }
];

const DESCRIPTIONS = {
  manifest: {
    name: 'manifest',
    summary: 'Top-level workflow document. A manifest is portable across backends and stays machine-readable end to end.',
    notes: [
      'Use raw JSON files or stdin instead of bespoke flags.',
      'Each task must define exactly one invocation mode: schedule or trigger.'
    ]
  },
  workflow: {
    name: 'workflow',
    summary: 'Named collection of tasks with task-local ids and trigger edges.'
  },
  task: {
    name: 'task',
    summary: 'Unit of work. The target controls how the task is executed, while schedule or trigger controls when it runs.',
    notes: [
      'Approval policy can express manual review intent without forcing every backend to expose the same gate semantics.',
      'Trigger conditions support contains: and regex: prefixes.',
      'Shell targets use structured execution fields like shell.program and shell.args instead of raw command strings.',
      'Tasks can carry model policy, plan/read-only intent, output hints, and resource budgets without hard-binding to one runtime.'
    ]
  },
  targets: {
    name: 'targets',
    summary: 'Available compilation targets.',
    items: listTargets()
  },
  commands: {
    name: 'commands',
    summary: 'CLI commands exposed by agentcli.',
    items: COMMAND_DESCRIPTIONS
  },
  rpc: {
    name: 'rpc',
    summary: 'Line-delimited JSON-RPC methods served over stdio.',
    methods: RPC_METHODS,
    notifications: RPC_NOTIFICATIONS
  }
};

export function describeTarget(name = 'commands') {
  const description = DESCRIPTIONS[name];
  if (!description) {
    throw Object.assign(
      new Error(`Unknown description target: ${name}`),
      { code: 'invalid_argument' }
    );
  }
  return description;
}
