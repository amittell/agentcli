import { listTargets } from './targets.js';

export const COMMAND_DESCRIPTIONS = [
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
    summary: 'Initialize the agentcli home directory with a starter manifest. Supports --force to overwrite.'
  },
  {
    command: 'serve',
    summary: 'Run a line-delimited JSON-RPC server over stdio for agent integrations.'
  }
];

export const RPC_METHODS = [
  { method: 'agentcli.ping', summary: 'Health check for JSON-RPC clients.' },
  { method: 'agentcli.schema', summary: 'Return a schema fragment by name.' },
  { method: 'agentcli.describe', summary: 'Return descriptive metadata by topic.' },
  { method: 'agentcli.validate', summary: 'Validate a manifest object.' },
  { method: 'agentcli.compile', summary: 'Compile a manifest object to a named target.' },
  { method: 'agentcli.apply', summary: 'Apply a manifest to an OpenClaw Scheduler runtime.' },
  { method: 'agentcli.inspect', summary: 'Inspect a scheduler database when available.' }
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
    items: RPC_METHODS
  }
};

export function describeTarget(name = 'commands') {
  const description = DESCRIPTIONS[name];
  if (!description) {
    throw new Error(`Unknown description target: ${name}`);
  }
  return description;
}
