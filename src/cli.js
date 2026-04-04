import { createRequire } from 'node:module';
import { MANIFEST_SCHEMA, MANIFEST_VERSION } from './schema.js';
import { loadJsonInput, writeJsonOutput } from './io.js';
import { validateManifest } from './validate.js';
import { describeTarget } from './describe.js';
import { getTarget, listTargets } from './targets.js';
import { inspectSchedulerState, listInspectableEntities } from './inspect.js';
import { parseFieldMask } from './fields.js';
import { serveJsonRpc } from './jsonrpc.js';
import { applyManifestToScheduler, createSchedulerCliRunner } from './apply.js';
import {
  querySchedulerCapabilities,
  resolveEffectiveFeatures,
  validateManifestCapabilities,
} from './capabilities.js';
import { executeTask } from './exec.js';
import { runWorkflow } from './run.js';
import { readAuditLog } from './audit.js';
import { resolveProviderForMethod } from './signing/index.js';
import './signing/ssh.js';
import { resolveAllowedSigners, generateAllowedSigners } from './signing/ssh.js';
import { ensureAgentcliHome, getAgentcliPaths } from './home.js';
import { createManifestScaffold, writeManifest } from './init.js';
import { listRegistry, addToRegistry, showRegistryEntry, removeFromRegistry } from './registry.js';
import { importManifest } from './import.js';
import { mergeManifests } from './merge.js';

const require = createRequire(import.meta.url);
const { version: PACKAGE_VERSION } = require('../package.json');

function usage() {
  return `
agentcli <command> [args]

Commands:
  version
  init [--tool program] [--output path] [--workflow-id id] [--task-id id]
  schema [manifest|workflow|task|schedulerJob|standalonePlan|rpcRequest|rpcResponse|scheduler-job|standalone-plan|rpc-request|rpc-response]
  describe [manifest|workflow|task|targets|commands|rpc]
  targets
  paths
  validate <path-or-json|->
  compile <path-or-json|-> [--target standalone|openclaw-scheduler] [--write path] [--explain]
  apply <path-or-json|-> [--db path] [--scheduler-prefix path|--scheduler-bin path] [--dry-run] [--explain] [--adopt-by id|name] [--check-capabilities]
  exec <path-or-json|-> <task-id> [--workflow id] [--dry-run] [--timeout ms]
       [--signer ssh|none] [--signing-key path] [--evidence-provider name]
       [--instance-id id] [--require-evidence] [--require-authorization]
       [--identity-debug] [--presentation-debug]
       [--db path] [--scheduler-prefix path|--scheduler-bin path]
  run <path-or-json|-> [--workflow id] [--root task-id|--all-roots] [--dry-run] [--timeout ms]
       [--signer ssh|none] [--signing-key path] [--evidence-provider name]
       [--instance-id id] [--require-evidence] [--require-authorization]
       [--identity-debug] [--presentation-debug]
  inspect <jobs|runs|queue|approvals> [--db path] [--fields a,b,c] [--limit n] [--sanitize basic] [--ndjson]
  audit [--limit n]
  verify <execution-id> [--allowed-signers path]
  signing providers
  registry list
  registry add <path> [--name name]
  registry show <name>
  registry remove <name>
  import <directory> [--name name]
  merge <manifest1> <manifest2> [--output path]
  convert <path-or-json|-> [--output path]  Convert v0.1 manifest to v0.2
  identity providers
  identity schema <provider>
  identity resolve <manifest> <task-id> [--workflow id]
  identity validate-delegation <manifest> <task-id> [--workflow id]
  authorization-proof methods
  authorization-proof schema <method>
  authorization-proof verify <manifest> <task-id> [--workflow id]
  authorization providers
  authorization schema <provider>
  authorization evaluate <manifest> <task-id> [--workflow id]
  evidence providers
  evidence schema <provider>
  whoami <manifest> <task-id> [--workflow id]
  skill-path
  serve [--db path]

Flags:
  --version, -v  Show package and manifest spec version
  --json         Force JSON output
  --pretty       Colorize JSON output for human readability
  --ndjson       Emit item streams as newline-delimited JSON
  --adopt-by     Strategy for matching existing jobs: id (default) or name.
                 Use --adopt-by name when migrating existing scheduler jobs
                 to agentcli management (one-time migration).

Environment:
  AGENTCLI_HOME=~/.agentcli
  AGENTCLI_OUTPUT=json|ndjson
  AGENTCLI_TARGET=standalone|openclaw-scheduler
  AGENTCLI_SIGNER=ssh|none (default: ssh)
  AGENTCLI_SIGNING_KEY=/path/to/ssh-private-key
  AGENTCLI_SCHEDULER_DB=/path/to/scheduler.sqlite
  AGENTCLI_SCHEDULER_PREFIX=/path/to/npm-prefix
  AGENTCLI_SCHEDULER_BIN=/path/to/openclaw-scheduler
`;
}

function parseArgs(argv) {
  const positionals = [];
  const flags = Object.create(null);

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') {
      positionals.push(...argv.slice(index + 1));
      break;
    }
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
    throw Object.assign(
      new Error(`Unknown schema target: ${name}`),
      { code: 'invalid_argument' }
    );
  }
  return schema;
}

function colorizeJson(json) {
  return json.replace(
    /("(?:[^"\\]|\\.)*")(\s*:)?|(\b(?:true|false|null)\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match, str, colon, bool, num) => {
      if (str && colon) return `\x1b[36m${str}\x1b[0m${colon}`;
      if (str) return `\x1b[32m${str}\x1b[0m`;
      if (bool) return `\x1b[33m${bool}\x1b[0m`;
      if (num) return `\x1b[35m${num}\x1b[0m`;
      return match;
    }
  );
}

function formatOutput(payload, { mode = 'json', pretty = false } = {}) {
  if (mode === 'ndjson') {
    const items = payload?.items || (Array.isArray(payload) ? payload : null);
    if (items) {
      return items.map(item => JSON.stringify(item)).join('\n');
    }
    return JSON.stringify(payload);
  }

  if (typeof payload === 'string') {
    return payload;
  }

  const json = JSON.stringify(payload, null, 2);
  return pretty ? colorizeJson(json) : json;
}

function cliError(message, code = 'invalid_argument', extra = {}) {
  throw Object.assign(new Error(message), { code, ...extra });
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
  const envOutput = env.AGENTCLI_OUTPUT || '';
  if (envOutput && envOutput !== 'json' && envOutput !== 'ndjson') {
    throw Object.assign(
      new Error(`Unknown AGENTCLI_OUTPUT value: ${envOutput}. Accepted values: json, ndjson`),
      { code: 'invalid_argument' }
    );
  }
  const explicitJson = Boolean(flags.json || flags.ndjson || envOutput);
  const outputMode = flags.ndjson ? 'ndjson'
    : flags.json ? 'json'
    : envOutput === 'ndjson' ? 'ndjson'
    : 'json';
  const pretty = Boolean(flags.pretty);
  const defaultTarget = env.AGENTCLI_TARGET || 'standalone';
  const defaultDbPath = env.AGENTCLI_SCHEDULER_DB || null;
  const defaultSchedulerPrefix = env.AGENTCLI_SCHEDULER_PREFIX || '';
  const defaultSchedulerBin = env.AGENTCLI_SCHEDULER_BIN || '';
  const derivedEnv = flags.home ? { ...env, AGENTCLI_HOME: flags.home } : env;

  if (flags.version || command === 'version' || command === '-v') {
    return formatOutput({
      ok: true,
      package_version: PACKAGE_VERSION,
      manifest_version: MANIFEST_VERSION
    }, { mode: outputMode, pretty });
  }

  switch (command) {
    case 'schema':
      return formatOutput({ ok: true, schema: pickSchema(positionals[1]) }, { mode: outputMode, pretty });
    case 'describe':
      return formatOutput({ ok: true, description: describeTarget(positionals[1]) }, { mode: outputMode, pretty });
    case 'targets':
      return formatOutput({ ok: true, targets: listTargets() }, { mode: outputMode, pretty });
    case 'paths':
      return formatOutput({ ok: true, paths: getAgentcliPaths({ env: derivedEnv }) }, { mode: outputMode, pretty });
    case 'skill-path': {
      const paths = getAgentcliPaths({ env: derivedEnv });
      const bundledSkillPath = new URL('../skills/manifest-authoring/SKILL.md', import.meta.url).pathname;
      return formatOutput({ ok: true, skill_path: bundledSkillPath, home_skill_path: paths.skill_path }, { mode: outputMode, pretty });
    }
    case 'init': {
      const { manifest, warnings: initWarnings } = createManifestScaffold({
        tool: flags.tool || undefined,
        workflowId: flags['workflow-id'] || undefined,
        taskId: flags['task-id'] || undefined,
      });
      const writtenTo = writeManifest(manifest, {
        output: flags.output || undefined,
        cwd,
      });
      ensureAgentcliHome({ env: derivedEnv });
      return formatOutput({
        ok: true,
        written_to: writtenTo,
        manifest,
        warnings: initWarnings,
      }, { mode: outputMode, pretty });
    }
    case 'validate': {
      const manifest = await loadJsonInput(positionals[1], { cwd, env: derivedEnv, stdin });
      return formatOutput(validateManifest(manifest), { mode: outputMode, pretty });
    }
    case 'compile': {
      const manifest = await loadJsonInput(positionals[1], { cwd, env: derivedEnv, stdin });
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

      return formatOutput(payload, { mode: outputMode, pretty });
    }
    case 'apply': {
      const manifest = await loadJsonInput(positionals[1], { cwd, env: derivedEnv, stdin });

      if (flags['check-capabilities']) {
        const runner = createSchedulerCliRunner({
          schedulerPrefix: flags['scheduler-prefix'] || defaultSchedulerPrefix,
          schedulerBin: flags['scheduler-bin'] || defaultSchedulerBin,
          dbPath: flags.db || defaultDbPath,
          cwd,
          env: derivedEnv,
        });
        const caps = querySchedulerCapabilities(runner);
        const effective = resolveEffectiveFeatures('openclaw-scheduler', caps);
        const compiled = getTarget('openclaw-scheduler').compile(manifest);
        const { errors: compatibilityErrors, warnings: compatibilityWarnings } = validateManifestCapabilities(compiled, effective);
        return formatOutput({
          ok: true,
          capabilities: caps,
          effective: effective,
          compatibility: {
            ok: compatibilityErrors.length === 0,
            errors: compatibilityErrors,
            warnings: compatibilityWarnings,
          },
        }, { mode: outputMode, pretty });
      }

      const adoptBy = flags['adopt-by'] || 'id';
      if (adoptBy !== 'id' && adoptBy !== 'name') {
        throw Object.assign(
          new Error(`Invalid --adopt-by value: ${adoptBy}. Accepted values: id, name`),
          { code: 'invalid_argument' }
        );
      }
      const payload = await applyManifestToScheduler(manifest, {
        dryRun: Boolean(flags['dry-run']),
        includeExplain: Boolean(flags.explain),
        adoptBy,
        dbPath: flags.db || defaultDbPath,
        schedulerPrefix: flags['scheduler-prefix'] || defaultSchedulerPrefix,
        schedulerBin: flags['scheduler-bin'] || defaultSchedulerBin,
        cwd,
        env: derivedEnv
      });
      return formatOutput(payload, { mode: outputMode, pretty });
    }
    case 'inspect': {
      const entity = positionals[1] || 'jobs';
      if (!listInspectableEntities().includes(entity)) {
        throw Object.assign(
          new Error(`Unsupported inspect entity: ${entity}`),
          { code: 'invalid_argument' }
        );
      }
      const sanitize = flags.sanitize || 'none';
      if (sanitize !== 'none' && sanitize !== 'basic') {
        throw Object.assign(
          new Error(`Unsupported sanitize mode: ${sanitize}. Accepted values: none, basic`),
          { code: 'invalid_argument' }
        );
      }
      const rawLimit = flags.limit;
      if (rawLimit != null && (typeof rawLimit !== 'string' || !/^[1-9][0-9]*$/.test(rawLimit))) {
        throw Object.assign(
          new Error(`Invalid --limit value: ${rawLimit}. Must be a positive integer.`),
          { code: 'invalid_argument' }
        );
      }
      const payload = await inspectSchedulerState({
        dbPath: flags.db || defaultDbPath,
        entity,
        limit: rawLimit,
        fields: parseFieldMask(flags.fields),
        sanitize
      });
      return formatOutput(payload, { mode: outputMode, pretty });
    }
    case 'exec': {
      const manifest = await loadJsonInput(positionals[1], { cwd, env: derivedEnv, stdin });
      const taskId = positionals[2];
      if (!taskId) {
        throw Object.assign(
          new Error('Usage: agentcli exec <manifest> <task-id> [--workflow id] [--dry-run] [--timeout ms]'),
          { code: 'invalid_argument' }
        );
      }
      const rawTimeout = flags.timeout;
      if (rawTimeout != null && (typeof rawTimeout !== 'string' || !/^[1-9][0-9]*$/.test(rawTimeout))) {
        throw Object.assign(
          new Error(`Invalid --timeout value: ${rawTimeout}. Must be a positive integer (milliseconds).`),
          { code: 'invalid_argument' }
        );
      }
      const payload = await executeTask(manifest, {
        workflowId: flags.workflow || undefined,
        taskId,
        dryRun: Boolean(flags['dry-run']),
        timeoutMs: rawTimeout ? Number(rawTimeout) : undefined,
        signer: flags.signer || undefined,
        signingKey: flags['signing-key'] || undefined,
        evidenceProvider: flags['evidence-provider'] || undefined,
        instanceId: flags['instance-id'] || undefined,
        requireEvidence: flags['require-evidence'] ? true : undefined,
        requireAuthorization: flags['require-authorization'] ? true : undefined,
        identityDebug: flags['identity-debug'] ? true : undefined,
        presentationDebug: flags['presentation-debug'] ? true : undefined,
        schedulerPrefix: flags['scheduler-prefix'] || defaultSchedulerPrefix,
        schedulerBin: flags['scheduler-bin'] || defaultSchedulerBin,
        dbPath: flags.db || defaultDbPath,
        cwd,
        env: derivedEnv,
      });
      return formatOutput(payload, { mode: outputMode, pretty });
    }
    case 'run': {
      if (!positionals[1]) {
        throw Object.assign(
          new Error('Usage: agentcli run <manifest> [--workflow id] [--root task-id|--all-roots] [--dry-run] [--timeout ms]'),
          { code: 'invalid_argument' }
        );
      }
      const manifest = await loadJsonInput(positionals[1], { cwd, env: derivedEnv, stdin });
      const rawTimeout = flags.timeout;
      if (rawTimeout != null && (typeof rawTimeout !== 'string' || !/^[1-9][0-9]*$/.test(rawTimeout))) {
        throw Object.assign(
          new Error(`Invalid --timeout value: ${rawTimeout}. Must be a positive integer (milliseconds).`),
          { code: 'invalid_argument' }
        );
      }
      const payload = await runWorkflow(manifest, {
        workflowId: flags.workflow || undefined,
        rootTaskId: flags.root || undefined,
        allRoots: Boolean(flags['all-roots']),
        dryRun: Boolean(flags['dry-run']),
        timeoutMs: rawTimeout ? Number(rawTimeout) : undefined,
        signer: flags.signer || undefined,
        signingKey: flags['signing-key'] || undefined,
        evidenceProvider: flags['evidence-provider'] || undefined,
        instanceId: flags['instance-id'] || undefined,
        requireEvidence: flags['require-evidence'] ? true : undefined,
        requireAuthorization: flags['require-authorization'] ? true : undefined,
        identityDebug: flags['identity-debug'] ? true : undefined,
        presentationDebug: flags['presentation-debug'] ? true : undefined,
        cwd,
        env: derivedEnv,
      });
      return formatOutput(payload, { mode: outputMode, pretty });
    }
    case 'audit': {
      const paths = getAgentcliPaths({ env: derivedEnv });
      const rawLimit = flags.limit;
      if (rawLimit != null && (typeof rawLimit !== 'string' || !/^[1-9][0-9]*$/.test(rawLimit))) {
        throw Object.assign(
          new Error(`Invalid --limit value: ${rawLimit}. Must be a positive integer.`),
          { code: 'invalid_argument' }
        );
      }
      const records = readAuditLog({
        auditPath: paths.audit,
        limit: rawLimit ? Number(rawLimit) : undefined,
      });
      return formatOutput({ ok: true, count: records.length, records }, { mode: outputMode, pretty });
    }
    case 'verify': {
      const executionId = positionals[1];
      if (!executionId) {
        throw Object.assign(
          new Error('Usage: agentcli verify <execution-id> [--allowed-signers path]'),
          { code: 'invalid_argument' }
        );
      }
      const paths = getAgentcliPaths({ env: derivedEnv });
      const records = readAuditLog({ auditPath: paths.audit });
      const record = records.find(r => r.execution_id === executionId);
      if (!record) {
        throw Object.assign(
          new Error(`Execution not found in audit log: ${executionId}`),
          { code: 'invalid_argument' }
        );
      }
      if (!record.attestation) {
        return formatOutput({
          ok: true,
          execution_id: executionId,
          verified: false,
          reason: record.attestation_note || 'no attestation present on this execution',
        }, { mode: outputMode, pretty });
      }
      const principal = record.principal_used || record.identity?.principal;
      if (!principal) {
        return formatOutput({
          ok: true,
          execution_id: executionId,
          verified: false,
          reason: 'no principal recorded for this execution',
        }, { mode: outputMode, pretty });
      }

      const method = record.attestation.method;
      const provider = resolveProviderForMethod(method);
      if (!provider) {
        return formatOutput({
          ok: true,
          execution_id: executionId,
          verified: false,
          reason: `no provider registered for attestation method "${method}"`,
        }, { mode: outputMode, pretty });
      }

      // SSH-specific: resolve allowed_signers file, auto-generate if missing
      let verifyOptions = { principal };
      if (method === 'ssh-signature') {
        let allowedSignersPath = flags['allowed-signers']
          || resolveAllowedSigners({ env: derivedEnv, statePath: paths.allowed_signers });
        if (!allowedSignersPath) {
          allowedSignersPath = generateAllowedSigners({
            principal,
            outputPath: paths.allowed_signers,
          });
          if (!allowedSignersPath) {
            return formatOutput({
              ok: true,
              execution_id: executionId,
              verified: false,
              reason: 'no allowed_signers file and no SSH public keys found to generate one',
            }, { mode: outputMode, pretty });
          }
        }
        verifyOptions.allowedSignersPath = allowedSignersPath;
      }

      const verifyResult = provider.verify(record.attestation, verifyOptions);
      return formatOutput({
        ok: true,
        execution_id: executionId,
        verified: verifyResult.verified,
        principal,
        method,
        key_fingerprint: record.attestation.key_fingerprint || null,
        ...(verifyResult.reason ? { reason: verifyResult.reason } : {}),
      }, { mode: outputMode, pretty });
    }
    case 'signing': {
      const subcommand = positionals[1];
      if (subcommand === 'providers') {
        const { listProviders, getProvider } = await import('./signing/index.js');
        return formatOutput({
          ok: true,
          providers: listProviders().map(name => {
            const provider = getProvider(name);
            return {
              name,
              methods: provider?.methods || [],
            };
          }),
        }, { mode: outputMode, pretty });
      }
      return cliError('Unknown signing subcommand. Available: providers');
    }
    case 'registry': {
      const subcommand = positionals[1];
      switch (subcommand) {
        case 'list':
          return formatOutput({
            ok: true,
            entries: listRegistry({ env: derivedEnv }),
          }, { mode: outputMode, pretty });
        case 'add': {
          const addPath = positionals[2];
          if (!addPath) {
            throw Object.assign(
              new Error('Usage: agentcli registry add <path> [--name name]'),
              { code: 'invalid_argument' }
            );
          }
          const addResult = addToRegistry(addPath, {
            name: flags.name || undefined,
            env: derivedEnv,
            cwd,
          });
          return formatOutput({ ok: true, ...addResult }, { mode: outputMode, pretty });
        }
        case 'show': {
          const showName = positionals[2];
          if (!showName) {
            throw Object.assign(
              new Error('Usage: agentcli registry show <name>'),
              { code: 'invalid_argument' }
            );
          }
          const manifest = showRegistryEntry(showName, { env: derivedEnv });
          return formatOutput({ ok: true, name: showName, manifest }, { mode: outputMode, pretty });
        }
        case 'remove': {
          const removeName = positionals[2];
          if (!removeName) {
            throw Object.assign(
              new Error('Usage: agentcli registry remove <name>'),
              { code: 'invalid_argument' }
            );
          }
          return formatOutput({
            ok: true,
            ...removeFromRegistry(removeName, { env: derivedEnv }),
          }, { mode: outputMode, pretty });
        }
        default:
          throw Object.assign(
            new Error(`Unknown registry subcommand: ${subcommand}. Available: list, add, show, remove`),
            { code: 'invalid_argument' }
          );
      }
    }
    case 'import': {
      const importPath = positionals[1];
      if (!importPath) {
        throw Object.assign(
          new Error('Usage: agentcli import <directory> [--name name]'),
          { code: 'invalid_argument' }
        );
      }
      const importResult = importManifest(importPath, {
        name: flags.name || undefined,
        env: derivedEnv,
        cwd,
      });
      return formatOutput({ ok: true, ...importResult }, { mode: outputMode, pretty });
    }
    case 'merge': {
      const mergePaths = positionals.slice(1);
      if (mergePaths.length < 2) {
        throw Object.assign(
          new Error('Usage: agentcli merge <manifest1> <manifest2> [--output path]'),
          { code: 'invalid_argument' }
        );
      }
      const manifests = [];
      for (const mp of mergePaths) {
        manifests.push(await loadJsonInput(mp, { cwd, env: derivedEnv, stdin }));
      }
      const merged = mergeManifests(manifests);
      const mergePayload = { ok: true, manifest: merged };
      if (flags.output) {
        const writtenTo = writeJsonOutput(flags.output, merged, { cwd });
        mergePayload.written_to = writtenTo;
      }
      return formatOutput(mergePayload, { mode: outputMode, pretty });
    }
    case 'convert': {
      const manifest = await loadJsonInput(positionals[1], { cwd, env: derivedEnv, stdin });
      const { convertManifestV1toV2 } = await import('./convert.js');
      try {
        const converted = convertManifestV1toV2(manifest);
        const writeTarget = flags.output || flags.write;
        if (writeTarget) {
          const writtenTo = writeJsonOutput(writeTarget, converted, { cwd });
          return formatOutput({ ok: true, output: writtenTo, version: '0.2' }, { mode: outputMode, pretty });
        }
        return formatOutput(converted, { mode: outputMode, pretty });
      } catch (err) {
        return cliError(err.message, err.code || 'invalid_argument', err.validation ? { validation: err.validation } : {});
      }
    }
    case 'identity': {
      const subcommand = positionals[1];
      if (subcommand === 'providers') {
        const { listProviders, listProviderCapabilities } = await import('./identity/index.js');
        await import('./identity/none.js');
        await import('./identity/env-bearer.js');
        await import('./identity/file-bearer.js');
        await import('./identity/oidc-client-credentials.js');
        await import('./identity/oidc-token-exchange.js');
        await import('./identity/azure-managed-identity.js');
        await import('./identity/aws-sts-assume-role.js');
        await import('./identity/gcp-workload-identity.js');
        await import('./identity/spiffe-jwt-svid.js');
        await import('./identity/entra-agent-id.js');
        return formatOutput({ ok: true, providers: listProviders().map(name => ({ name, capabilities: listProviderCapabilities().get(name) || null })) }, { mode: outputMode, pretty });
      }
      if (subcommand === 'schema') {
        const providerName = positionals[2];
        if (!providerName) cliError('Usage: agentcli identity schema <provider>');
        const { getProvider } = await import('./identity/index.js');
        await import('./identity/none.js');
        await import('./identity/env-bearer.js');
        await import('./identity/file-bearer.js');
        await import('./identity/oidc-client-credentials.js');
        await import('./identity/oidc-token-exchange.js');
        await import('./identity/azure-managed-identity.js');
        await import('./identity/aws-sts-assume-role.js');
        await import('./identity/gcp-workload-identity.js');
        await import('./identity/spiffe-jwt-svid.js');
        await import('./identity/entra-agent-id.js');
        const provider = getProvider(providerName);
        if (!provider) cliError(`Unknown identity provider: ${providerName}`);
        return formatOutput({ ok: true, provider: providerName, capabilities: provider.capabilities }, { mode: outputMode, pretty });
      }
      if (subcommand === 'resolve') {
        const manifest = await loadJsonInput(positionals[2], { cwd, env: derivedEnv, stdin });
        const taskId = positionals[3];
        const workflowId = flags.workflow || null;
        if (!taskId) cliError('Usage: agentcli identity resolve <manifest> <task-id> [--workflow id]');
        const result = await executeTask(manifest, { workflowId, taskId, dryRun: true, identityDebug: true, cwd, env: derivedEnv });
        return formatOutput({ ok: true, declared_identity: result.declared_identity || result.identity, resolved_identity: result.resolved_identity || null, principal_used: result.principal_used }, { mode: outputMode, pretty });
      }
      if (subcommand === 'validate-delegation') {
        const manifest = await loadJsonInput(positionals[2], { cwd, env: derivedEnv, stdin });
        const taskId = positionals[3];
        const workflowId = flags.workflow || null;
        if (!taskId) cliError('Usage: agentcli identity validate-delegation <manifest> <task-id> [--workflow id]');
        const result = await executeTask(manifest, { workflowId, taskId, dryRun: true, identityDebug: true, cwd, env: derivedEnv });
        return formatOutput({ ok: true, delegation: result.resolved_identity?.delegation_validation || null }, { mode: outputMode, pretty });
      }
      return cliError('Unknown identity subcommand. Available: providers, schema, resolve, validate-delegation');
    }
    case 'authorization-proof': {
      const subcommand = positionals[1];
      if (subcommand === 'methods') {
        const { listVerifiers } = await import('./authorization-proof/index.js');
        await import('./authorization-proof/none.js');
        await import('./authorization-proof/jwt.js');
        await import('./authorization-proof/detached-signature.js');
        await import('./authorization-proof/certificate.js');
        return formatOutput({ ok: true, methods: listVerifiers() }, { mode: outputMode, pretty });
      }
      if (subcommand === 'schema') {
        const method = positionals[2];
        if (!method) cliError('Usage: agentcli authorization-proof schema <method>');
        const { getVerifier } = await import('./authorization-proof/index.js');
        await import('./authorization-proof/none.js');
        await import('./authorization-proof/jwt.js');
        await import('./authorization-proof/detached-signature.js');
        await import('./authorization-proof/certificate.js');
        const verifier = getVerifier(method);
        if (!verifier) cliError(`Unknown verifier method: ${method}`);
        return formatOutput({ ok: true, method, verifier: verifier.name }, { mode: outputMode, pretty });
      }
      if (subcommand === 'verify') {
        const manifest = await loadJsonInput(positionals[2], { cwd, env: derivedEnv, stdin });
        const taskId = positionals[3];
        const workflowId = flags.workflow || null;
        if (!taskId) cliError('Usage: agentcli authorization-proof verify <manifest> <task-id> [--workflow id]');
        const result = await executeTask(manifest, { workflowId, taskId, dryRun: true, cwd, env: derivedEnv });
        return formatOutput({ ok: true, authorization_proof: result.authorization_proof || null }, { mode: outputMode, pretty });
      }
      return cliError('Unknown authorization-proof subcommand. Available: methods, schema, verify');
    }
    case 'authorization': {
      const subcommand = positionals[1];
      if (subcommand === 'providers') {
        const { listAuthorizationProviders } = await import('./authorization/index.js');
        await import('./authorization/none.js');
        await import('./authorization/opa.js');
        return formatOutput({ ok: true, providers: listAuthorizationProviders() }, { mode: outputMode, pretty });
      }
      if (subcommand === 'schema') {
        const providerName = positionals[2];
        if (!providerName) cliError('Usage: agentcli authorization schema <provider>');
        const { getAuthorizationProvider } = await import('./authorization/index.js');
        await import('./authorization/none.js');
        await import('./authorization/opa.js');
        const provider = getAuthorizationProvider(providerName);
        if (!provider) cliError(`Unknown authorization provider: ${providerName}`);
        return formatOutput({ ok: true, provider: providerName, capabilities: provider.capabilities }, { mode: outputMode, pretty });
      }
      if (subcommand === 'evaluate') {
        const manifest = await loadJsonInput(positionals[2], { cwd, env: derivedEnv, stdin });
        const taskId = positionals[3];
        const workflowId = flags.workflow || null;
        if (!taskId) cliError('Usage: agentcli authorization evaluate <manifest> <task-id> [--workflow id]');
        const result = await executeTask(manifest, { workflowId, taskId, dryRun: true, requireAuthorization: true, cwd, env: derivedEnv });
        return formatOutput({ ok: true, authorization: result.authorization || null }, { mode: outputMode, pretty });
      }
      return cliError('Unknown authorization subcommand. Available: providers, schema, evaluate');
    }
    case 'evidence': {
      const subcommand = positionals[1];
      if (subcommand === 'providers') {
        const { listEvidenceProviders } = await import('./evidence/index.js');
        await import('./evidence/none.js');
        await import('./evidence/ssh.js');
        return formatOutput({ ok: true, providers: listEvidenceProviders() }, { mode: outputMode, pretty });
      }
      if (subcommand === 'schema') {
        const providerName = positionals[2];
        if (!providerName) cliError('Usage: agentcli evidence schema <provider>');
        const { getEvidenceProvider } = await import('./evidence/index.js');
        await import('./evidence/none.js');
        await import('./evidence/ssh.js');
        const provider = getEvidenceProvider(providerName);
        if (!provider) cliError(`Unknown evidence provider: ${providerName}`);
        return formatOutput({ ok: true, provider: providerName, methods: provider.methods || [] }, { mode: outputMode, pretty });
      }
      return cliError('Unknown evidence subcommand. Available: providers, schema');
    }
    case 'whoami': {
      const manifest = await loadJsonInput(positionals[1], { cwd, env: derivedEnv, stdin });
      const taskId = positionals[2];
      const workflowId = flags.workflow || null;
      if (!taskId) cliError('Usage: agentcli whoami <manifest> <task-id> [--workflow id]');
      const result = await executeTask(manifest, { workflowId, taskId, dryRun: true, identityDebug: true, cwd, env: derivedEnv });
      return formatOutput({ ok: true, principal_used: result.principal_used, declared_identity: result.declared_identity || result.identity, resolved_identity: result.resolved_identity || null, trust: result.trust || null }, { mode: outputMode, pretty });
    }
    case 'serve': {
      await serveJsonRpc({
        input: stdin,
        output: stdout,
        defaults: {
          dbPath: flags.db || defaultDbPath,
          target: defaultTarget,
          schedulerPrefix: defaultSchedulerPrefix,
          schedulerBin: defaultSchedulerBin
        }
      });
      return '';
    }
    case 'help':
    case '-h':
    case undefined:
      if (explicitJson) {
        return formatOutput({ ok: true, usage: usage().trim() }, { mode: outputMode, pretty });
      }
      return usage().trim();
    default:
      throw Object.assign(
        new Error(`Unknown command: ${command}`),
        { code: 'unknown_command' }
      );
  }
}
