import { MANIFEST_SCHEMA } from './schema.js';
import { loadJsonInput, writeJsonOutput } from './io.js';
import { validateManifest } from './validate.js';
import { describeTarget } from './describe.js';
import { getTarget, listTargets } from './targets.js';
import { inspectSchedulerState, listInspectableEntities } from './inspect.js';
import { parseFieldMask } from './fields.js';
import { serveJsonRpc } from './jsonrpc.js';
import { applyManifestToScheduler } from './apply.js';
import { ensureAgentcliHome, getAgentcliPaths } from './home.js';

function usage() {
  return `
agentcli <command> [args]

Commands:
  schema [manifest|workflow|task|schedulerJob|standalonePlan|rpcRequest|rpcResponse]
  describe [manifest|workflow|task|targets|commands|rpc]
  targets
  paths
  init [--home path] [--force]
  validate <path-or-json|->
  compile <path-or-json|-> [--target standalone|openclaw-scheduler] [--write path] [--explain]
  apply <path-or-json|-> [--db path] [--scheduler-prefix path|--scheduler-bin path] [--dry-run] [--explain]
  inspect <jobs|runs|queue|approvals> [--db path] [--fields a,b,c] [--limit n] [--sanitize basic] [--ndjson]
  serve [--db path]

Flags:
  --json      Force JSON output
  --ndjson    Emit item streams as newline-delimited JSON

Environment:
  AGENTCLI_HOME=~/.agentcli
  AGENTCLI_OUTPUT=json|ndjson
  AGENTCLI_TARGET=standalone|openclaw-scheduler
  AGENTCLI_SCHEDULER_DB=/path/to/scheduler.sqlite
  AGENTCLI_SCHEDULER_PREFIX=/path/to/npm-prefix
  AGENTCLI_SCHEDULER_BIN=/path/to/openclaw-scheduler
`;
}

function parseArgs(argv) {
  const positionals = [];
  const flags = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }

    const [key, inlineValue] = arg.slice(2).split('=', 2);
    if (inlineValue !== undefined) {
      flags[key] = inlineValue;
      continue;
    }

    const next = argv[index + 1];
    if (next && !next.startsWith('--')) {
      flags[key] = next;
      index += 1;
    } else {
      flags[key] = true;
    }
  }

  return { positionals, flags };
}

function pickSchema(name) {
  const aliases = {
    'scheduler-job': 'schedulerJob',
    'standalone-plan': 'standalonePlan',
    'rpc-request': 'rpcRequest',
    'rpc-response': 'rpcResponse'
  };
  const schema = MANIFEST_SCHEMA[aliases[name] || name || 'manifest'];
  if (!schema) {
    throw new Error(`Unknown schema target: ${name}`);
  }
  return schema;
}

function formatOutput(payload, { mode = 'json' } = {}) {
  if (mode === 'ndjson') {
    const items = payload?.items || (Array.isArray(payload) ? payload : []);
    if (Array.isArray(items) && (payload?.items || Array.isArray(payload))) {
      return items.map(item => JSON.stringify(item)).join('\n');
    }
    return JSON.stringify(payload, null, 2);
  }

  if (typeof payload === 'string') {
    return payload;
  }

  return JSON.stringify(payload, null, 2);
}

export async function runCli(
  argv,
  {
    cwd = process.cwd(),
    env = process.env,
    stdin = process.stdin,
    stdout = process.stdout
  } = {}
) {
  const { positionals, flags } = parseArgs(argv);
  const command = positionals[0];
  const outputMode = flags.ndjson
    ? 'ndjson'
    : flags.json || env.AGENTCLI_OUTPUT === 'json'
      ? 'json'
      : env.AGENTCLI_OUTPUT === 'ndjson'
        ? 'ndjson'
        : 'json';
  const defaultTarget = env.AGENTCLI_TARGET || 'standalone';
  const defaultDbPath = env.AGENTCLI_SCHEDULER_DB || null;
  const defaultSchedulerPrefix = env.AGENTCLI_SCHEDULER_PREFIX || '';
  const defaultSchedulerBin = env.AGENTCLI_SCHEDULER_BIN || '';
  const derivedEnv = flags.home ? { ...env, AGENTCLI_HOME: flags.home } : env;

  switch (command) {
    case 'schema':
      return formatOutput({ ok: true, schema: pickSchema(positionals[1]) }, { mode: outputMode });
    case 'describe':
      return formatOutput({ ok: true, description: describeTarget(positionals[1]) }, { mode: outputMode });
    case 'targets':
      return formatOutput({ ok: true, targets: listTargets() }, { mode: outputMode });
    case 'paths':
      return formatOutput({ ok: true, paths: getAgentcliPaths({ env: derivedEnv }) }, { mode: outputMode });
    case 'init':
      return formatOutput(ensureAgentcliHome({
        env: derivedEnv,
        force: Boolean(flags.force)
      }), { mode: outputMode });
    case 'validate': {
      const manifest = loadJsonInput(positionals[1], { cwd, env: derivedEnv });
      return formatOutput(validateManifest(manifest), { mode: outputMode });
    }
    case 'compile': {
      const manifest = loadJsonInput(positionals[1], { cwd, env: derivedEnv });
      const target = getTarget(flags.target || defaultTarget);
      const compiled = target.compile(manifest, { includeExplain: Boolean(flags.explain) });
      const payload = {
        ok: true,
        target: target.name,
        output: compiled
      };

      if (flags.write) {
        payload.written_to = writeJsonOutput(flags.write, compiled, { cwd });
      }

      return formatOutput(payload, { mode: outputMode });
    }
    case 'apply': {
      const manifest = loadJsonInput(positionals[1], { cwd, env: derivedEnv });
      const payload = applyManifestToScheduler(manifest, {
        dryRun: Boolean(flags['dry-run']),
        includeExplain: Boolean(flags.explain),
        dbPath: flags.db || defaultDbPath,
        schedulerPrefix: flags['scheduler-prefix'] || defaultSchedulerPrefix,
        schedulerBin: flags['scheduler-bin'] || defaultSchedulerBin,
        cwd,
        env: derivedEnv
      });
      return formatOutput(payload, { mode: outputMode });
    }
    case 'inspect': {
      const entity = positionals[1] || 'jobs';
      if (!listInspectableEntities().includes(entity)) {
        throw new Error(`Unsupported inspect entity: ${entity}`);
      }
      const payload = inspectSchedulerState({
        dbPath: flags.db || defaultDbPath,
        entity,
        limit: flags.limit,
        fields: parseFieldMask(flags.fields),
        sanitize: flags.sanitize || 'none'
      });
      return formatOutput(payload, { mode: outputMode });
    }
    case 'serve': {
      await serveJsonRpc({
        input: stdin,
        output: stdout,
        defaults: {
          dbPath: flags.db || defaultDbPath,
          target: defaultTarget
        }
      });
      return '';
    }
    case 'help':
    case undefined:
      return formatOutput({ ok: true, usage: usage().trim() }, { mode: outputMode });
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}
