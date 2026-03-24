import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PassThrough } from 'node:stream';
import { DatabaseSync } from 'node:sqlite';
import {
  compileManifestToStandalone as compileStandaloneFromIndex,
  describeTarget,
  expandManifestShorthands,
  inspectSchedulerState as inspectFromIndex,
  MANIFEST_VERSION,
  resolveManifestCandidate,
  sanitizeForAgent,
  serveJsonRpc
} from '../src/index.js';
import { validateManifest } from '../src/validate.js';
import { compileManifestToScheduler } from '../src/compiler/openclaw-scheduler.js';
import { compileManifestToStandalone } from '../src/compiler/standalone.js';
import { applyManifestToScheduler, resolveSchedulerInvocation } from '../src/apply.js';
import { runCli } from '../src/cli.js';
import { inspectSchedulerState } from '../src/inspect.js';
import { handleJsonRpcRequest } from '../src/jsonrpc.js';
import { ensureAgentcliHome } from '../src/home.js';
import { stableId, resolveIdentityV2 } from '../src/compiler/shared.js';
import { applyFieldMask, parseFieldMask } from '../src/fields.js';
import { resolveSafeOutputPath } from '../src/io.js';
import { buildOnFailureTask } from '../src/shorthand.js';
import { executeTask } from '../src/exec.js';
import { readAuditLog } from '../src/audit.js';
import { buildAttestationPayload, commandHash } from '../src/attestation.js';
import {
  registerProvider,
  getProvider,
  listProviders,
  resolveProvider,
  resolveProviderForMethod,
} from '../src/signing/index.js';
import {
  resolveSigningKey,
  signPayload,
  verifySignature,
  generateAllowedSigners,
} from '../src/signing/ssh.js';

function readExample(name) {
  return JSON.parse(readFileSync(new URL(`../examples/${name}`, import.meta.url), 'utf8'));
}

function encodeBase64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function unsignedJwt(payload) {
  return `${encodeBase64UrlJson({ alg: 'none', typ: 'JWT' })}.${encodeBase64UrlJson(payload)}.`;
}

const exampleManifest = readExample('hello-world.json');
const shellManifest = readExample('shell-workflow.json');
const publicBotHealthManifest = readExample('public-bot-health.json');
const publicFailureTriageManifest = readExample('public-shell-failure-triage.json');
const publicReportPublishManifest = readExample('public-report-publish.json');

test('all example manifests validate and compile', () => {
  for (const name of readdirSync(join(process.cwd(), 'examples')).filter(file => file.endsWith('.json')).sort()) {
    const manifest = readExample(name);
    const result = validateManifest(manifest);
    assert.equal(result.ok, true, `${name} should validate`);

    const schedulerCompiled = compileManifestToScheduler(manifest);
    const standaloneCompiled = compileManifestToStandalone(manifest);
    assert.ok(Array.isArray(schedulerCompiled.jobs), `${name} should compile to scheduler jobs`);
    assert.ok(Array.isArray(standaloneCompiled.workflows), `${name} should compile to standalone workflows`);
  }
});

test('example manifest validates', () => {
  const result = validateManifest(exampleManifest);
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);
});

test('invalid identifiers fail validation', () => {
  const bad = {
    version: '0.1',
    workflows: [
      {
        id: 'bad workflow',
        name: 'Bad',
        tasks: [
          {
            id: 't1',
            name: 'Task',
            prompt: 'hello',
            target: { session_target: 'isolated' },
            schedule: { cron: '0 1 * * *' }
          }
        ]
      }
    ]
  };

  const result = validateManifest(bad);
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /must match/);
});

test('invalid trigger conditions fail validation', () => {
  const bad = structuredClone(exampleManifest);
  bad.workflows[0].tasks[1].trigger.condition = 'equals:ALERT';

  const result = validateManifest(bad);
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /must start with contains: or regex:/);
});

test('self-referential triggers fail validation explicitly', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'self-trigger-flow',
        name: 'Self Trigger Flow',
        tasks: [
          {
            id: 'loop',
            name: 'Loop',
            prompt: 'Check the current task state.',
            target: { session_target: 'isolated' },
            trigger: { parent: 'loop', on: 'failure' },
            delivery: { mode: 'announce' }
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => error.path.endsWith('.trigger.parent') && /must not reference its own task id/.test(error.message)));
});

test('invalid enabled type fails validation', () => {
  const bad = structuredClone(exampleManifest);
  bad.workflows[0].tasks[0].enabled = 'false';

  const result = validateManifest(bad);
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /must be a boolean/);
});

test('missing target.session_target fails validation explicitly', () => {
  const bad = {
    version: '0.1',
    workflows: [
      {
        id: 'missing-session-target',
        name: 'Missing Session Target',
        tasks: [
          {
            id: 't1',
            name: 'Task',
            prompt: 'hello',
            target: {},
            schedule: { cron: '0 1 * * *' }
          }
        ]
      }
    ]
  };

  const result = validateManifest(bad);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => error.path.endsWith('.target.session_target') && /required/.test(error.message)));
});

test('invalid on_failure type fails validation', () => {
  const bad = structuredClone(publicFailureTriageManifest);
  bad.workflows[0].tasks[0].on_failure = 'diagnose it';

  const result = validateManifest(bad);
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /must be an object/);
});

test('on_failure without explicit id validates and compiles with synthesized id', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'auto-id-flow',
        name: 'Auto ID Flow',
        tasks: [
          {
            id: 'root-task',
            name: 'Root Task',
            shell: { program: 'scripts/check.sh' },
            target: { session_target: 'shell' },
            schedule: { cron: '0 * * * *' },
            delivery: { mode: 'none' },
            on_failure: {
              prompt: 'Diagnose the failure and suggest a fix.',
              delivery: { mode: 'announce' }
            }
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);

  const compiled = compileManifestToScheduler(manifest);
  assert.equal(compiled.jobs.length, 2);
  const handler = compiled.jobs.find(job => job.source.task_id === 'root-task.failure');
  assert.ok(handler);
  assert.equal(handler.parent_id, compiled.jobs[0].id);
});

test('on_failure with explicit id that collides with another task fails validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'collide-flow',
        name: 'Collide Flow',
        tasks: [
          {
            id: 'root-task',
            name: 'Root Task',
            shell: { program: 'scripts/check.sh' },
            target: { session_target: 'shell' },
            schedule: { cron: '0 * * * *' },
            delivery: { mode: 'none' },
            on_failure: {
              id: 'root-task',
              prompt: 'Diagnose the failure.',
              delivery: { mode: 'announce' }
            }
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => /unique after shorthand expansion/.test(e.message)));
});

test('compile emits scheduler jobs with parent linkage and explain notes', () => {
  const compiled = compileManifestToScheduler(exampleManifest, { includeExplain: true });
  assert.equal(compiled.target, 'openclaw-scheduler');
  assert.equal(compiled.jobs.length, 2);
  const root = compiled.jobs.find(job => job.source.task_id === 'collect');
  const child = compiled.jobs.find(job => job.source.task_id === 'alert-followup');
  assert.ok(root);
  assert.ok(child);
  assert.equal(child.parent_id, root.id);
  assert.equal(child.trigger_condition, 'contains:ALERT');
  assert.equal(child.approval_required, 1);
  assert.match(compiled.explain[1].notes[0], /sentinel cron/);
});

test('compile emits standalone workflow plan', () => {
  const compiled = compileManifestToStandalone(exampleManifest, { includeExplain: true });
  assert.equal(compiled.target, 'standalone');
  assert.equal(compiled.workflows.length, 1);
  assert.equal(compiled.workflows[0].tasks[0].invocation.mode, 'schedule');
  assert.equal(compiled.workflows[0].tasks[1].invocation.mode, 'trigger');
  assert.equal(compiled.workflows[0].edges.length, 1);
  assert.match(compiled.explain[1].notes[0], /Retains trigger semantics directly/);
});

test('shell workflow validates and carries policy-based approval intent', () => {
  const result = validateManifest(shellManifest);
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);

  const compiled = compileManifestToScheduler(shellManifest);
  const root = compiled.jobs.find(job => job.source.task_id === 'check-space');
  const followup = compiled.jobs.find(job => job.source.task_id === 'escalate-low-space');
  assert.ok(root);
  assert.ok(followup);
  assert.equal(root.payload_kind, 'shellCommand');
  assert.equal(root.payload_message, '\'df\' \'-h\'');
  assert.equal(followup.approval_required, 1);
  assert.equal(followup.approval_auto, 'reject');
  assert.equal(followup.trigger_condition, 'regex:(9[0-9]%|100%)');
});

test('structured shell execution is preserved in standalone plans and rendered for scheduler jobs', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'structured-shell',
        name: 'Structured Shell',
        tasks: [
          {
            id: 'query-logs',
            name: 'Query Logs',
            shell: {
              program: 'python3',
              args: ['scripts/query_logs.py', '--namespace', 'agent x'],
              env: {
                START_NS: '1700000000000000000',
                KUBECONFIG: '/tmp/kube config'
              },
              cwd: '/tmp/work dir',
              stdin: 'line one\nline two'
            },
            target: { session_target: 'shell' },
            schedule: { cron: '*/15 * * * *' },
            delivery: { mode: 'none' }
          }
        ]
      }
    ]
  };

  const validation = validateManifest(manifest);
  assert.equal(validation.ok, true);

  const schedulerCompiled = compileManifestToScheduler(manifest);
  assert.equal(schedulerCompiled.jobs[0].payload_message, 'cd \'/tmp/work dir\' && printf %s \'line one\nline two\' | KUBECONFIG=\'/tmp/kube config\' START_NS=\'1700000000000000000\' \'python3\' \'scripts/query_logs.py\' \'--namespace\' \'agent x\'');

  const standaloneCompiled = compileManifestToStandalone(manifest);
  assert.deepEqual(standaloneCompiled.workflows[0].tasks[0].execution.payload, {
    program: 'python3',
    args: ['scripts/query_logs.py', '--namespace', 'agent x'],
    env: {
      START_NS: '1700000000000000000',
      KUBECONFIG: '/tmp/kube config'
    },
    cwd: '/tmp/work dir',
    stdin: 'line one\nline two'
  });
});

test('shell.stdin accepts empty strings', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'empty-stdin',
        name: 'Empty Stdin',
        tasks: [
          {
            id: 'pipe-empty',
            name: 'Pipe Empty',
            shell: {
              program: 'cat',
              stdin: ''
            },
            target: { session_target: 'shell' },
            schedule: { cron: '0 * * * *' },
            delivery: { mode: 'none' }
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);
});

test('public bot health example validates and compiles chained diagnosis flow', () => {
  const result = validateManifest(publicBotHealthManifest);
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);

  const compiled = compileManifestToScheduler(publicBotHealthManifest, { includeExplain: true });
  assert.equal(compiled.jobs.length, 2);
  const root = compiled.jobs.find(job => job.source.task_id === 'check-bot-health');
  const diagnose = compiled.jobs.find(job => job.source.task_id === 'diagnose-bot-alert');
  assert.ok(root);
  assert.ok(diagnose);
  assert.equal(diagnose.trigger_condition, 'contains:ALERT');
  assert.equal(diagnose.execution_intent, 'plan');
  assert.equal(diagnose.execution_read_only, 1);
  assert.equal(diagnose.max_trigger_fanout, 3);
  assert.equal(diagnose.max_queued_dispatches, 8);
});

test('public report publish example validates and compiles approval-gated publish flow', () => {
  const result = validateManifest(publicReportPublishManifest);
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);

  const compiled = compileManifestToScheduler(publicReportPublishManifest);
  assert.equal(compiled.jobs.length, 3);
  const root = compiled.jobs.find(job => job.source.task_id === 'capture-metrics');
  const analyze = compiled.jobs.find(job => job.source.task_id === 'analyze-metrics');
  const publish = compiled.jobs.find(job => job.source.task_id === 'publish-report');
  assert.ok(root);
  assert.ok(analyze);
  assert.ok(publish);
  assert.equal(analyze.execution_intent, 'plan');
  assert.equal(analyze.execution_read_only, 1);
  assert.equal(analyze.output_excerpt_limit_bytes, 1600);
  assert.equal(publish.approval_required, 1);
});

test('on_failure shorthand expands into a failure edge in standalone plans', () => {
  const compiled = compileManifestToStandalone(publicFailureTriageManifest);
  assert.equal(compiled.workflows.length, 1);
  assert.equal(compiled.workflows[0].tasks.length, 2);
  assert.equal(compiled.workflows[0].edges.length, 1);
  assert.equal(compiled.workflows[0].edges[0].on, 'failure');
});

test('disabled tasks and runtime timeouts compile through the scheduler target', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'disabled-timeout-flow',
        name: 'Disabled Timeout Flow',
        tasks: [
          {
            id: 'check-health',
            name: 'Check Health',
            enabled: false,
            shell: {
              program: 'scripts/check_health.sh'
            },
            target: { session_target: 'shell' },
            schedule: { cron: '*/5 * * * *' },
            runtime: { timeout_ms: 45000 },
            delivery: { mode: 'none' }
          },
          {
            id: 'triage-health',
            name: 'Triage Health',
            enabled: false,
            prompt: 'Review the parent task and summarize the issue.',
            target: { session_target: 'isolated', agent_id: 'main' },
            trigger: { parent: 'check-health', on: 'failure' },
            delivery: { mode: 'announce' }
          }
        ]
      }
    ]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.equal(result.errors.length, 0);

  const compiled = compileManifestToScheduler(manifest);
  assert.equal(compiled.jobs.length, 2);
  assert(compiled.jobs.every(job => job.enabled === 0));
  const root = compiled.jobs.find(job => job.source.task_id === 'check-health');
  const diagnose = compiled.jobs.find(job => job.source.task_id === 'triage-health');
  assert.ok(root);
  assert.ok(diagnose);
  assert.equal(root.run_timeout_ms, 45000);
  assert.equal(diagnose.parent_id, root.id);
});

test('shell tasks reject legacy raw command fields and mismatched payload kinds', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'legacy-shell-shape',
        name: 'Legacy Shell Shape',
        tasks: [
          {
            id: 'run-legacy-shell',
            name: 'Run Legacy Shell',
            command: 'echo ok',
            target: {
              session_target: 'shell',
              payload_kind: 'systemEvent'
            },
            schedule: {
              cron: '0 * * * *'
            },
            delivery: {
              mode: 'none'
            }
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.equal(result.errors.some(error => error.path.endsWith('.command') && /not supported/.test(error.message)), true);
  assert.equal(result.errors.some(error => error.path.endsWith('.target.payload_kind') && /shellCommand/.test(error.message)), true);
  assert.equal(result.errors.some(error => error.path.endsWith('.shell') && /required/.test(error.message)), true);
});

test('model policy, execution intent, output hints, and budgets compile through both targets', () => {
  const result = validateManifest(publicFailureTriageManifest);
  assert.equal(result.ok, true);

  const schedulerCompiled = compileManifestToScheduler(publicFailureTriageManifest, { includeExplain: true });
  const standaloneCompiled = compileManifestToStandalone(publicFailureTriageManifest);
  const root = schedulerCompiled.jobs.find(job => job.source.task_id === 'collect-health');
  const triage = schedulerCompiled.jobs.find(job => job.source.task_id === 'triage-failure');

  assert.ok(root);
  assert.ok(triage);
  assert.equal(root.payload_model, 'anthropic/claude-sonnet-4-6');
  assert.equal(root.payload_thinking, 'high');
  assert.equal(triage.execution_intent, 'plan');
  assert.equal(triage.execution_read_only, 1);
  assert.equal(triage.max_trigger_fanout, 4);
  assert.equal(triage.max_pending_approvals, 3);
  assert.equal(triage.max_queued_dispatches, 12);
  assert.equal(triage.output_excerpt_limit_bytes, 1200);
  assert.equal(standaloneCompiled.workflows[0].tasks[1].intent.mode, 'plan');
  assert.equal(standaloneCompiled.workflows[0].tasks[1].output.retrieve, 'on-demand');
});

test('target listing reports structured feature support', async () => {
  const output = JSON.parse(await runCli(['targets']));
  assert.equal(output.ok, true);
  const schedulerTarget = output.targets.find(target => target.name === 'openclaw-scheduler');
  assert.equal(schedulerTarget.features.execution_intent, 'runtime');
  assert.equal(schedulerTarget.features.model_policy, 'model+thinking');
});

test('cli paths reports the default agentcli home layout', async () => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  const output = JSON.parse(await runCli(['paths'], {
    env: {
      ...process.env,
      AGENTCLI_HOME: homeRoot
    }
  }));

  assert.equal(output.ok, true);
  assert.equal(output.paths.root, homeRoot);
  assert.equal(output.paths.manifests, join(homeRoot, 'manifests'));
});

test('cli init creates a valid manifest in cwd', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-init-'));
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  t.after(() => {
    rmSync(workdir, { recursive: true, force: true });
    rmSync(homeRoot, { recursive: true, force: true });
  });

  const output = JSON.parse(await runCli(['init'], {
    cwd: workdir,
    env: { ...process.env, AGENTCLI_HOME: homeRoot }
  }));

  assert.equal(output.ok, true);
  assert.ok(output.written_to.endsWith('agentcli.json'));
  assert.equal(output.manifest.version, '0.1');
  assert.equal(output.manifest.workflows.length, 1);

  const written = JSON.parse(readFileSync(output.written_to, 'utf8'));
  assert.deepEqual(written, output.manifest);
});

test('cli init --tool wraps a specific program', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-init-tool-'));
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  t.after(() => {
    rmSync(workdir, { recursive: true, force: true });
    rmSync(homeRoot, { recursive: true, force: true });
  });

  const output = JSON.parse(await runCli(['init', '--tool', 'echo'], {
    cwd: workdir,
    env: { ...process.env, AGENTCLI_HOME: homeRoot }
  }));

  assert.equal(output.ok, true);
  assert.equal(output.manifest.workflows[0].tasks[0].shell.program, 'echo');
});

test('load-by-name flow resolves manifests from AGENTCLI_HOME/manifests', async (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  t.after(() => rmSync(homeRoot, { recursive: true, force: true }));

  ensureAgentcliHome({ env: { ...process.env, AGENTCLI_HOME: homeRoot } });

  const output = JSON.parse(await runCli(['validate', 'bot-health'], {
    env: {
      ...process.env,
      AGENTCLI_HOME: homeRoot
    }
  }));

  assert.equal(output.ok, true);
  assert.deepEqual(output.errors, []);
});

test('package entry exports the public API', () => {
  assert.equal(MANIFEST_VERSION, '0.2');
  const compiled = compileStandaloneFromIndex(exampleManifest);
  assert.equal(compiled.target, 'standalone');
});

test('cli schema returns json', async () => {
  const output = JSON.parse(await runCli(['schema', 'task']));
  assert.equal(output.ok, true);
  assert.equal(output.schema.type, 'object');
});

test('cli schema manifest reflects v0.2 identity surfaces', async () => {
  const output = JSON.parse(await runCli(['schema', 'manifest']));
  assert.equal(output.ok, true);
  assert.equal(output.schema.fields.version.const, '0.2');
  assert.ok(output.schema.fields.identity_profiles);
  assert.ok(output.schema.fields.authorization_proof_profiles);
  assert.ok(output.schema.fields.authorization_profiles);
  assert.ok(output.schema.fields.evidence_profiles);
});

test('cli -h prints usage', async () => {
  const output = await runCli(['-h']);
  assert.match(output, /^agentcli <command> \[args\]/);
});

test('cli accepts -- as an argument terminator', async () => {
  const output = JSON.parse(await runCli(['validate', '--', JSON.stringify(exampleManifest)]));
  assert.equal(output.ok, true);
  assert.deepEqual(output.errors, []);
});

test('cli validate reads JSON from injected stdin for dash input', async () => {
  const stdin = new PassThrough();
  const outputPromise = runCli(['validate', '-'], { stdin });
  stdin.end(JSON.stringify(exampleManifest));

  const output = JSON.parse(await outputPromise);
  assert.equal(output.ok, true);
  assert.deepEqual(output.errors, []);
});

test('cli describe rpc exposes methods and startup notifications', async () => {
  const output = JSON.parse(await runCli(['describe', 'rpc']));
  assert.equal(output.ok, true);
  assert.ok(Array.isArray(output.description.methods));
  assert.ok(Array.isArray(output.description.notifications));
  assert.equal(output.description.notifications[0].method, 'agentcli.ready');
});

test('cli compile writes safely inside cwd', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const output = JSON.parse(
    await runCli(
      [
        'compile',
        JSON.stringify(exampleManifest),
        '--target',
        'standalone',
        '--write',
        'out/compiled.json'
      ],
      { cwd: workdir }
    )
  );

  assert.equal(output.ok, true);
  assert.equal(output.target, 'standalone');
  assert.equal(output.written_to, join(workdir, 'out/compiled.json'));

  const written = JSON.parse(readFileSync(output.written_to, 'utf8'));
  assert.equal(written.target, 'standalone');
});

test('cli compile rejects writes outside cwd', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  await assert.rejects(
    runCli(
      [
        'compile',
        JSON.stringify(exampleManifest),
        '--write',
        '../compiled.json'
      ],
      { cwd: workdir }
    ),
    /outside the current working directory/
  );
});

test('resolveSchedulerInvocation prefers npm prefix when present', () => {
  const invocation = resolveSchedulerInvocation({ schedulerPrefix: '/tmp/scheduler-prefix', platform: 'linux' });
  assert.equal(invocation.command, 'npm');
  assert.deepEqual(invocation.prefixArgs, ['exec', '--prefix', '/tmp/scheduler-prefix', 'openclaw-scheduler', '--']);
});

test('applyManifestToScheduler plans and executes scheduler upserts', async () => {
  const compiled = compileManifestToScheduler(exampleManifest);
  const existing = [compiled.jobs[0]];
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() {
      return existing;
    },
    addJob(spec) {
      calls.push({ action: 'create', spec });
      return { ok: true, job: spec };
    },
    updateJob(id, spec) {
      calls.push({ action: 'update', id, spec });
      return { ok: true, job: spec };
    }
  };

  const result = await applyManifestToScheduler(exampleManifest, { runner });
  assert.equal(result.ok, true);
  assert.equal(result.job_count, 2);
  assert.deepEqual(result.actions.map(action => action.action), ['updated', 'created']);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].action, 'update');
  assert.equal(calls[1].action, 'create');
  assert.equal('run_timeout_ms' in calls[0].spec, false);
  assert.equal(calls[0].spec.enabled, true);
});

test('applyManifestToScheduler converts enabled flags to booleans for scheduler cli calls', async () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'disabled-create-flow',
        name: 'Disabled Create Flow',
        tasks: [
          {
            id: 'disabled-root',
            name: 'Disabled Root',
            enabled: false,
            shell: {
              program: 'echo',
              args: ['ok']
            },
            target: { session_target: 'shell' },
            schedule: { cron: '0 * * * *' },
            delivery: { mode: 'none' }
          }
        ]
      }
    ]
  };
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() {
      return [];
    },
    addJob(spec) {
      calls.push(spec);
      return { ok: true, job: spec };
    },
    updateJob() {
      throw new Error('unexpected update');
    }
  };

  const result = await applyManifestToScheduler(manifest, { runner });
  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].enabled, false);
});

test('cli apply supports dry-run without invoking scheduler writes', async () => {
  const runner = {
    invocation: { label: 'dry-run-scheduler' },
    listJobs() {
      return [];
    },
    addJob() {
      throw new Error('dry-run should not add jobs');
    },
    updateJob() {
      throw new Error('dry-run should not update jobs');
    }
  };

  const result = await applyManifestToScheduler(exampleManifest, { dryRun: true, runner });
  assert.equal(result.ok, true);
  assert.equal(result.dry_run, true);
  assert.equal(result.job_count, 2);
  assert.deepEqual(result.actions.map(action => action.action), ['created', 'created']);
});

test('applyManifestToScheduler adopt-by-name matches existing job by name and re-keys to stable id', async () => {
  const compiled = compileManifestToScheduler(exampleManifest);
  const stableJob = compiled.jobs[0];
  // Simulate existing job with same name but a legacy UUID
  const legacyId = 'legacy-uuid-aaaa-bbbb-cccc-000000000000';
  const existing = [{ ...stableJob, id: legacyId }];
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() { return existing; },
    addJob(spec) {
      calls.push({ action: 'create', spec });
      return { ok: true, job: spec };
    },
    updateJob(id, spec) {
      calls.push({ action: 'update', id, spec });
      return { ok: true, job: spec };
    }
  };

  const result = await applyManifestToScheduler(exampleManifest, { runner, adoptBy: 'name' });

  assert.equal(result.ok, true);
  assert.equal(result.job_count, 2);

  // First job: matched by name → "adopted", second: no match → "created"
  assert.deepEqual(result.actions.map(a => a.action), ['adopted', 'created']);

  // The adopted action's job_id should be the stable compiled id, not the legacy UUID
  assert.equal(result.actions[0].job_id, stableJob.id);
  assert.notEqual(result.actions[0].job_id, legacyId);

  // updateJob was called with the OLD legacy id but the NEW stable id in spec
  const updateCall = calls.find(c => c.action === 'update');
  assert.ok(updateCall, 'updateJob should have been called for the adopted job');
  assert.equal(updateCall.id, legacyId);
  assert.equal(updateCall.spec.id, stableJob.id);

  // addJob was called for the unmatched second job
  const createCall = calls.find(c => c.action === 'create');
  assert.ok(createCall, 'addJob should have been called for the unmatched job');
});

test('applyManifestToScheduler adopt-by-name creates when no name matches', async () => {
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() {
      return [{ id: 'some-uuid', name: 'Completely Different Job Name' }];
    },
    addJob(spec) {
      calls.push({ action: 'create', spec });
      return { ok: true, job: spec };
    },
    updateJob() {
      throw new Error('should not update when no name matches');
    }
  };

  const result = await applyManifestToScheduler(exampleManifest, { runner, adoptBy: 'name' });

  assert.equal(result.ok, true);
  assert.deepEqual(result.actions.map(a => a.action), ['created', 'created']);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(c => c.action === 'create'));
});

test('applyManifestToScheduler adopt-by-id (default) still works correctly', async () => {
  const compiled = compileManifestToScheduler(exampleManifest);
  // Existing has first job matching by id
  const existing = [compiled.jobs[0]];
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() { return existing; },
    addJob(spec) {
      calls.push({ action: 'create', spec });
      return { ok: true, job: spec };
    },
    updateJob(id, spec) {
      calls.push({ action: 'update', id, spec });
      return { ok: true, job: spec };
    }
  };

  const result = await applyManifestToScheduler(exampleManifest, { runner, adoptBy: 'id' });

  assert.equal(result.ok, true);
  assert.deepEqual(result.actions.map(a => a.action), ['updated', 'created']);
  // updated action should use the stable compiled id (not legacy)
  assert.equal(calls[0].action, 'update');
  assert.equal(calls[0].id, compiled.jobs[0].id);
});

test('applyManifestToScheduler adopt-by-name dry-run does not invoke scheduler writes', async () => {
  const compiled = compileManifestToScheduler(exampleManifest);
  const legacyId = 'legacy-uuid-dry-run-0000-0000-0000';
  const existing = [{ ...compiled.jobs[0], id: legacyId }];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() { return existing; },
    addJob() { throw new Error('dry-run should not add jobs'); },
    updateJob() { throw new Error('dry-run should not update jobs'); }
  };

  const result = await applyManifestToScheduler(exampleManifest, { runner, adoptBy: 'name', dryRun: true });

  assert.equal(result.ok, true);
  assert.equal(result.dry_run, true);
  // Still reports what would happen
  assert.deepEqual(result.actions.map(a => a.action), ['adopted', 'created']);
  // job_id in plan reflects the stable id, not the legacy UUID
  assert.equal(result.actions[0].job_id, compiled.jobs[0].id);
});

test('cli apply --adopt-by with invalid value throws', async () => {
  await assert.rejects(
    runCli(['apply', JSON.stringify(exampleManifest), '--adopt-by', 'uuid']),
    /Invalid --adopt-by value/
  );
});

test('cli falls back to json for non-streaming commands in ndjson mode', async () => {
  const output = JSON.parse(await runCli(['compile', JSON.stringify(exampleManifest)], {
    env: {
      ...process.env,
      AGENTCLI_OUTPUT: 'ndjson'
    }
  }));

  assert.equal(output.ok, true);
  assert.equal(output.target, 'standalone');
});

test('inspect applies field masks and sanitization', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-'));
  const dbPath = join(workdir, 'scheduler.sqlite');
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE jobs (
      id TEXT,
      payload_message TEXT,
      created_at TEXT
    );
  `);
  db.prepare('INSERT INTO jobs (id, payload_message, created_at) VALUES (?, ?, ?)')
    .run('job-1', 'line one ```\u0007danger', '2026-03-06T12:00:00Z');
  db.close();

  const result = await inspectSchedulerState({
    dbPath,
    entity: 'jobs',
    fields: ['id', 'payload_message'],
    sanitize: 'basic'
  });

  assert.equal(result.ok, true);
  assert.deepEqual(Object.keys(result.items[0]).sort(), ['id', 'payload_message']);
  assert.equal(result.items[0].payload_message.includes('```'), false);
  assert.equal(result.items[0].payload_message.includes('\u0007'), false);
});

test('json-rpc compile request returns compiled output', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: '1',
    method: 'agentcli.compile',
    params: {
      target: 'standalone',
      manifest: exampleManifest,
      explain: true
    }
  });

  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, '1');
  assert.equal(response.result.ok, true);
  assert.equal(response.result.output.target, 'standalone');
  assert.ok(Array.isArray(response.result.output.explain));
});

test('json-rpc compile errors include validation payload in error.data', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'compile-invalid',
    method: 'agentcli.compile',
    params: {
      target: 'standalone',
      manifest: { version: '0.1', workflows: [] }
    }
  });

  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, 'compile-invalid');
  assert.equal(response.error.code, -32602);
  assert.equal(response.error.message, 'Manifest validation failed');
  assert.equal(response.error.data.ok, false);
  assert.ok(Array.isArray(response.error.data.errors));
});

test('json-rpc caller-fixable parameter errors return invalid params', async () => {
  const cases = [
    {
      request: {
        jsonrpc: '2.0',
        id: 'schema-invalid',
        method: 'agentcli.schema',
        params: { target: 'unknown-target' }
      },
      message: /Unknown schema target/
    },
    {
      request: {
        jsonrpc: '2.0',
        id: 'describe-invalid',
        method: 'agentcli.describe',
        params: { target: 'unknown-topic' }
      },
      message: /Unknown description target/
    },
    {
      request: {
        jsonrpc: '2.0',
        id: 'compile-invalid-target',
        method: 'agentcli.compile',
        params: {
          target: 'not-a-target',
          manifest: exampleManifest
        }
      },
      message: /Unsupported compile target/
    },
    {
      request: {
        jsonrpc: '2.0',
        id: 'inspect-invalid-entity',
        method: 'agentcli.inspect',
        params: { entity: 'widgets', dbPath: '/tmp/unused.sqlite' }
      },
      message: /Unsupported inspect entity/
    },
    {
      request: {
        jsonrpc: '2.0',
        id: 'params-not-object',
        method: 'agentcli.describe',
        params: ['rpc']
      },
      message: /Params must be an object/
    }
  ];

  for (const testCase of cases) {
    const response = await handleJsonRpcRequest(testCase.request);
    assert.equal(response.error.code, -32602, testCase.request.id);
    assert.match(response.error.message, testCase.message, testCase.request.id);
  }
});

test('serveJsonRpc emits ready notification before responses', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks = [];
  output.on('data', chunk => chunks.push(String(chunk)));

  const serving = serveJsonRpc({ input, output });
  input.write(`${JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'agentcli.ping' })}\n`);
  input.end();
  await serving;

  const messages = chunks.join('').trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(messages[0], {
    jsonrpc: '2.0',
    method: 'agentcli.ready',
    params: {
      ok: true,
      manifest_version: MANIFEST_VERSION
    }
  });
  assert.deepEqual(messages[1], {
    jsonrpc: '2.0',
    id: '1',
    result: {
      ok: true,
      pong: true
    }
  });
});

test('json-rpc apply returns scheduler action plan', async () => {
  const compiled = compileManifestToScheduler(exampleManifest);
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'apply-1',
    method: 'agentcli.apply',
    params: {
      manifest: exampleManifest,
      dryRun: true
    }
  }, {
    schedulerRunner: {
      invocation: { label: 'fake-scheduler' },
      listJobs() {
        return [compiled.jobs[0]];
      },
      addJob() {
        throw new Error('dry-run should not add jobs');
      },
      updateJob() {
        throw new Error('dry-run should not update jobs');
      }
    }
  });

  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, 'apply-1');
  assert.equal(response.result.ok, true);
  assert.deepEqual(response.result.actions.map(action => action.action), ['updated', 'created']);
});

test('cli version returns package and manifest version', async () => {
  const output = JSON.parse(await runCli(['version']));
  assert.equal(output.ok, true);
  assert.equal(typeof output.package_version, 'string');
  assert.match(output.package_version, /^\d+\.\d+\.\d+/);
  assert.equal(output.manifest_version, MANIFEST_VERSION);
});

test('cli --version flag returns version', async () => {
  const output = JSON.parse(await runCli(['--version']));
  assert.equal(output.ok, true);
  assert.equal(output.manifest_version, MANIFEST_VERSION);
});

test('cli -v flag returns version', async () => {
  const output = JSON.parse(await runCli(['-v']));
  assert.equal(output.ok, true);
  assert.equal(output.manifest_version, MANIFEST_VERSION);
});

test('json-rpc agentcli.version returns version info', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'ver-1',
    method: 'agentcli.version'
  });

  assert.equal(response.jsonrpc, '2.0');
  assert.equal(response.id, 'ver-1');
  assert.equal(response.result.ok, true);
  assert.equal(typeof response.result.package_version, 'string');
  assert.equal(response.result.manifest_version, MANIFEST_VERSION);
});

test('json-rpc batch request returns clear error', async () => {
  const response = await handleJsonRpcRequest([
    { jsonrpc: '2.0', id: '1', method: 'agentcli.ping' },
    { jsonrpc: '2.0', id: '2', method: 'agentcli.ping' }
  ]);

  assert.equal(response.error.code, -32600);
  assert.match(response.error.message, /Batch requests are not supported/);
});

test('non-object optional blocks fail validation', () => {
  const bad = structuredClone(exampleManifest);
  bad.workflows[0].tasks[0].model_policy = 'fast';
  bad.workflows[0].tasks[0].intent = 42;
  bad.workflows[0].tasks[0].delivery = ['announce'];

  const result = validateManifest(bad);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.endsWith('.model_policy') && /must be an object/.test(e.message)));
  assert.ok(result.errors.some(e => e.path.endsWith('.intent') && /must be an object/.test(e.message)));
  assert.ok(result.errors.some(e => e.path.endsWith('.delivery') && /must be an object/.test(e.message)));
});

test('non-object workflow model_policy fails validation', () => {
  const bad = structuredClone(exampleManifest);
  bad.workflows[0].model_policy = 'fast';

  const result = validateManifest(bad);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.endsWith('.model_policy') && /must be an object/.test(e.message)));
});

test('unknown keys on tasks and workflows emit warnings', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'warn-flow',
        name: 'Warn Flow',
        typo_field: true,
        tasks: [
          {
            id: 't1',
            name: 'Task One',
            prompt: 'hello',
            target: { session_target: 'isolated' },
            schedule: { cron: '0 * * * *' },
            deliveri: { mode: 'announce' }
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.ok(result.warnings.some(w => /unknown key "typo_field"/.test(w.message)));
  assert.ok(result.warnings.some(w => /unknown key "deliveri"/.test(w.message)));
});

test('unknown keys on on_failure emit warnings', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'onfail-warn',
        name: 'OnFail Warn',
        tasks: [
          {
            id: 'root',
            name: 'Root',
            shell: { program: 'check.sh' },
            target: { session_target: 'shell' },
            schedule: { cron: '0 * * * *' },
            delivery: { mode: 'none' },
            on_failure: {
              prompt: 'Diagnose',
              unknown_block: true
            }
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.ok(result.warnings.some(w => /unknown key "unknown_block"/.test(w.message)));
});

test('cli unknown command returns error', async () => {
  await assert.rejects(
    runCli(['nonexistent-command']),
    /Unknown command: nonexistent-command/
  );
});

test('cli inspect rejects invalid sanitize mode', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-'));
  const dbPath = join(workdir, 'scheduler.sqlite');
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const db = new DatabaseSync(dbPath);
  db.exec('CREATE TABLE jobs (id TEXT, created_at TEXT);');
  db.close();

  await assert.rejects(
    runCli(['inspect', 'jobs', '--db', dbPath, '--sanitize', 'full']),
    /Unsupported sanitize mode/
  );
});

test('barrel export includes new public APIs', () => {
  assert.equal(typeof inspectFromIndex, 'function');
  assert.equal(typeof describeTarget, 'function');
  assert.equal(typeof sanitizeForAgent, 'function');
  assert.equal(typeof expandManifestShorthands, 'function');
});

test('cli describe commands includes version command', async () => {
  const output = JSON.parse(await runCli(['describe', 'commands']));
  assert.equal(output.ok, true);
  assert.ok(output.description.items.some(item => item.command === 'version'));
});

test('cli describe rpc includes version method', async () => {
  const output = JSON.parse(await runCli(['describe', 'rpc']));
  assert.equal(output.ok, true);
  assert.ok(output.description.methods.some(m => m.method === 'agentcli.version'));
});

test('invalid AGENTCLI_OUTPUT value throws', async () => {
  await assert.rejects(
    runCli(['version'], { env: { ...process.env, AGENTCLI_OUTPUT: 'yaml' } }),
    /Unknown AGENTCLI_OUTPUT value: yaml/
  );
});

test('ndjson empty items returns empty string', async () => {
  const output = await runCli(['compile', JSON.stringify(exampleManifest)], {
    env: { ...process.env, AGENTCLI_OUTPUT: 'ndjson' }
  });
  // compile output has no items, so ndjson falls through to single JSON line
  const parsed = JSON.parse(output);
  assert.equal(parsed.ok, true);
});

test('tasks without approval block compile with null approval fields', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'no-approval-flow',
        name: 'No Approval Flow',
        tasks: [
          {
            id: 'basic-task',
            name: 'Basic Task',
            prompt: 'Run a basic check.',
            target: { session_target: 'isolated' },
            schedule: { cron: '0 * * * *' }
          }
        ]
      }
    ]
  };

  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.approval_auto, null);
  assert.equal(job.approval_timeout_s, null);
  assert.equal(job.approval_required, 0);
});

test('tasks without intent block compile with null execution_read_only', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'no-intent-flow',
        name: 'No Intent Flow',
        tasks: [
          {
            id: 'basic-task',
            name: 'Basic Task',
            prompt: 'Run a basic check.',
            target: { session_target: 'isolated' },
            schedule: { cron: '0 * * * *' }
          }
        ]
      }
    ]
  };

  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.execution_read_only, null);
  assert.equal(job.delete_after_run, null);
});

test('tasks with explicit intent compile with integer execution_read_only', () => {
  const compiled = compileManifestToScheduler(publicFailureTriageManifest);
  const triage = compiled.jobs.find(j => j.source.task_id === 'triage-failure');
  assert.equal(triage.execution_read_only, 1);
});

test('json-rpc apply adoptBy validation uses invalidParams error path', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'adopt-invalid',
    method: 'agentcli.apply',
    params: {
      manifest: exampleManifest,
      adoptBy: 'uuid'
    }
  }, {
    schedulerRunner: {
      invocation: { label: 'fake' },
      listJobs() { return []; },
      addJob() { return { ok: true }; },
      updateJob() { return { ok: true }; }
    }
  });

  assert.equal(response.error.code, -32602);
  assert.match(response.error.message, /Invalid adoptBy value/);
});

test('malformed JSON input produces contextual parse error', async () => {
  await assert.rejects(
    runCli(['validate', '{not-json}']),
    /Invalid JSON from.*not-json/
  );
});

test('schema task has required fields on schedule and trigger', async () => {
  const output = JSON.parse(await runCli(['schema', 'task']));
  assert.deepEqual(output.schema.fields.schedule.required, ['cron']);
  assert.deepEqual(output.schema.fields.trigger.required, ['parent', 'on']);
});

test('schema task has mutual exclusion note', async () => {
  const output = JSON.parse(await runCli(['schema', 'task']));
  assert.match(output.schema.note, /Exactly one of schedule or trigger/);
});

test('barrel export includes resolveManifestCandidate', () => {
  assert.equal(typeof resolveManifestCandidate, 'function');
});

test('serveJsonRpc suppresses output for notifications (no id)', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks = [];
  output.on('data', chunk => chunks.push(String(chunk)));

  const serving = serveJsonRpc({ input, output });
  input.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'agentcli.ping' })}\n`);
  input.write(`${JSON.stringify({ jsonrpc: '2.0', id: '1', method: 'agentcli.ping' })}\n`);
  input.end();
  await serving;

  const messages = chunks.join('').trim().split('\n').map(line => JSON.parse(line));
  // Should have ready notification + response to id:1, but NOT a response for the notification
  assert.equal(messages[0].method, 'agentcli.ready');
  assert.equal(messages[1].id, '1');
  assert.equal(messages.length, 2);
});

test('cli --home flag overrides AGENTCLI_HOME for paths command', async () => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  const output = JSON.parse(await runCli(['paths', '--home', homeRoot]));
  assert.equal(output.ok, true);
  assert.equal(output.paths.root, homeRoot);
});

test('intent with mode but no read_only compiles with null execution_read_only', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'partial-intent-flow',
        name: 'Partial Intent Flow',
        tasks: [
          {
            id: 'plan-task',
            name: 'Plan Task',
            prompt: 'Plan a check.',
            target: { session_target: 'isolated' },
            intent: { mode: 'plan' },
            schedule: { cron: '0 * * * *' }
          }
        ]
      }
    ]
  };

  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.execution_intent, 'plan');
  assert.equal(job.execution_read_only, null);
});

test('cli schema with unknown target produces invalid_argument error', async () => {
  await assert.rejects(
    runCli(['schema', 'nonexistent']),
    (err) => {
      assert.match(err.message, /Unknown schema target/);
      assert.equal(err.code, 'invalid_argument');
      return true;
    }
  );
});

test('cli describe with unknown target produces invalid_argument error', async () => {
  await assert.rejects(
    runCli(['describe', 'nonexistent']),
    (err) => {
      assert.match(err.message, /Unknown description target/);
      assert.equal(err.code, 'invalid_argument');
      return true;
    }
  );
});

test('whitespace-only trigger condition suffix fails validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'whitespace-cond',
        name: 'Whitespace Condition',
        tasks: [
          {
            id: 'root',
            name: 'Root',
            prompt: 'check',
            target: { session_target: 'isolated' },
            schedule: { cron: '0 * * * *' }
          },
          {
            id: 'child',
            name: 'Child',
            prompt: 'follow up',
            target: { session_target: 'isolated' },
            trigger: { parent: 'root', on: 'success', condition: 'contains:   ' }
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => /contains trigger condition cannot be empty/.test(e.message)));
});

test('non-object schedule produces type error before mutual exclusion check', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'bad-schedule-type',
        name: 'Bad Schedule Type',
        tasks: [
          {
            id: 't1',
            name: 'Task',
            prompt: 'hello',
            target: { session_target: 'isolated' },
            schedule: '0 * * * *'
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.endsWith('.schedule') && /must be an object/.test(e.message)));
});

test('json-rpc compile includes target name in result', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'compile-target',
    method: 'agentcli.compile',
    params: {
      target: 'standalone',
      manifest: exampleManifest
    }
  });

  assert.equal(response.result.ok, true);
  assert.equal(response.result.target, 'standalone');
  assert.equal(response.result.output.target, 'standalone');
});

test('standalone plan schema includes capabilities field', async () => {
  const output = JSON.parse(await runCli(['schema', 'standalonePlan']));
  assert.ok(output.schema.fields.capabilities);
  assert.equal(output.schema.fields.capabilities.type, 'object');
  assert.ok(output.schema.fields.capabilities.fields.authoring);
});

test('rpcRequest schema allows string or number id', async () => {
  const output = JSON.parse(await runCli(['schema', 'rpc-request']));
  assert.deepEqual(output.schema.fields.id.type, ['string', 'number']);
});

test('json-rpc handles integer request ids', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 42,
    method: 'agentcli.ping'
  });

  assert.equal(response.id, 42);
  assert.equal(response.result.ok, true);
});

test('delivery block without mode passes validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'empty-delivery',
        name: 'Empty Delivery',
        tasks: [
          {
            id: 't1',
            name: 'Task',
            prompt: 'hello',
            target: { session_target: 'isolated' },
            schedule: { cron: '0 * * * *' },
            delivery: {}
          }
        ]
      }
    ]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
});

test('cli --fields without a value produces structured error', async () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-'));
  const dbPath = join(workdir, 'scheduler.sqlite');
  const db = new DatabaseSync(dbPath);
  db.exec('CREATE TABLE jobs (id TEXT, created_at TEXT);');
  db.close();

  await assert.rejects(
    runCli(['inspect', 'jobs', '--db', dbPath, '--fields']),
    (err) => {
      assert.match(err.message, /--fields requires/);
      assert.equal(err.code, 'invalid_argument');
      return true;
    }
  );
  rmSync(workdir, { recursive: true, force: true });
});

test('rpcResponse schema allows string or number id', async () => {
  const output = JSON.parse(await runCli(['schema', 'rpc-response']));
  assert.deepEqual(output.schema.fields.id.type, ['string', 'number']);
});

test('trigger with missing on field fails validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        {
          id: 'root', name: 'Root',
          prompt: 'do something',
          target: { session_target: 'isolated' },
          schedule: { cron: '0 * * * *' }
        },
        {
          id: 'child', name: 'Child',
          prompt: 'follow up',
          target: { session_target: 'isolated' },
          trigger: { parent: 'root' }
        }
      ]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  const onError = result.errors.find(e => e.path.includes('trigger.on'));
  assert.ok(onError, 'should have an error for missing trigger.on');
  assert.ok(onError.message.includes('required'));
});

test('empty approval block compiles with null auto field', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        prompt: 'do it',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        approval: {}
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.approval_auto, null, 'empty approval block should produce null auto');
  assert.equal(job.approval_timeout_s, 3600, 'empty approval block should use default timeout');
  assert.equal(job.approval_required, 0, 'empty approval block with no policy defaults required to 0');
});

test('approval with manual policy defaults auto to reject', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        prompt: 'do it',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        approval: { policy: 'manual' }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.approval_auto, 'reject');
  assert.equal(job.approval_required, 1);
});

test('barrel export includes io utilities', async () => {
  const mod = await import('../src/index.js');
  assert.equal(typeof mod.loadJsonInput, 'function');
  assert.equal(typeof mod.writeJsonOutput, 'function');
  assert.equal(typeof mod.resolveSafeOutputPath, 'function');
});

test('standalonePlan schema version has const constraint', async () => {
  const output = JSON.parse(await runCli(['schema', 'standalone-plan']));
  assert.equal(output.schema.fields.version.const, '0.2');
});

test('json-rpc internal error uses fallback message', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'err-test',
    method: 'agentcli.compile',
    params: { manifest: null, target: 'standalone' }
  });
  assert.equal(response.jsonrpc, '2.0');
  assert.ok(response.error);
  assert.equal(typeof response.error.message, 'string');
  assert.ok(response.error.message.length > 0, 'error message should not be empty');
});

test('trigger.on with invalid value fails validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        {
          id: 'root', name: 'Root', prompt: 'go',
          target: { session_target: 'isolated' },
          schedule: { cron: '0 * * * *' }
        },
        {
          id: 'child', name: 'Child', prompt: 'follow',
          target: { session_target: 'isolated' },
          trigger: { parent: 'root', on: 'always' }
        }
      ]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.includes('trigger.on') && /must be one of/.test(e.message)));
});

test('trigger.parent referencing non-existent task fails validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        {
          id: 'root', name: 'Root', prompt: 'go',
          target: { session_target: 'isolated' },
          schedule: { cron: '0 * * * *' }
        },
        {
          id: 'child', name: 'Child', prompt: 'follow',
          target: { session_target: 'isolated' },
          trigger: { parent: 'nonexistent', on: 'success' }
        }
      ]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e =>
    e.path.includes('trigger.parent') && /must reference another task id/.test(e.message)
  ));
});

test('auto-approve policy compiles with correct approval fields', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'do it',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        approval: { policy: 'auto-approve', risk_level: 'low' }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.approval_auto, 'approve');
  assert.equal(job.approval_required, 0);
});

test('delete_after_run true compiles to integer 1', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'do it',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        delete_after_run: true
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  assert.equal(compiled.jobs[0].delete_after_run, 1);
});

test('json-rpc validate returns validation result directly', async () => {
  const valid = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 'v1',
    method: 'agentcli.validate',
    params: { manifest: { version: '0.1', workflows: [{ id: 'w', name: 'W', tasks: [{ id: 't', name: 'T', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '* * * * *' } }] }] } }
  });
  assert.equal(valid.result.ok, true);
  assert.deepEqual(valid.result.errors, []);

  const invalid = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 'v2',
    method: 'agentcli.validate',
    params: { manifest: { version: 'bad' } }
  });
  assert.equal(invalid.result.ok, false);
  assert.ok(invalid.result.errors.length > 0);
  assert.equal(invalid.error, undefined, 'validation failures return result, not error');
});

test('serveJsonRpc emits parse error for malformed JSON', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const lines = [];
  output.on('data', chunk => lines.push(chunk.toString()));

  const done = serveJsonRpc({ input, output, defaults: {} });
  input.write('not valid json\n');
  input.write('{"jsonrpc":"2.0","id":"after","method":"agentcli.ping"}\n');
  input.end();
  await done;

  const responses = lines.join('').trim().split('\n').map(l => JSON.parse(l));
  const ready = responses.find(r => r.method === 'agentcli.ready');
  assert.ok(ready);
  const parseErr = responses.find(r => r.error?.code === -32700);
  assert.ok(parseErr, 'should emit -32700 parse error');
  const pong = responses.find(r => r.id === 'after');
  assert.ok(pong, 'should continue processing after parse error');
});

test('cli --limit without value produces structured error', async () => {
  await assert.rejects(
    () => runCli(['inspect', 'jobs', '--db', '/tmp/unused.sqlite', '--limit']),
    err => err.code === 'invalid_argument' && /--limit/.test(err.message)
  );
});

test('non-object schedule does not produce redundant mutual exclusion error', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: '0 * * * *'
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.endsWith('.schedule') && /must be an object/.test(e.message)));
  assert.ok(!result.errors.some(e => /must define exactly one/.test(e.message)),
    'should not emit mutual exclusion error when type error already covers the problem');
});

test('schema exposes token format on validated fields', async () => {
  const output = JSON.parse(await runCli(['schema', 'task']));
  assert.equal(output.schema.fields.target.fields.agent_id.format, 'token');
  assert.equal(output.schema.fields.delivery.fields.channel.format, 'token');
  assert.equal(output.schema.fields.session.fields.preferred_key.format, 'token');
  assert.equal(output.schema.fields.model_policy.fields.model.format, 'token');
  assert.equal(output.schema.fields.shell.fields.program.format, 'token');
});

test('workflow-level model_policy inherits to tasks and is overridden by task-level policy', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'inherit-flow', name: 'Inherit Flow',
      model_policy: { provider: 'anthropic', model: 'claude-sonnet-4-6', thinking: 'high' },
      tasks: [
        {
          id: 'inherits', name: 'Inherits',
          prompt: 'check',
          target: { session_target: 'isolated' },
          schedule: { cron: '0 * * * *' }
        },
        {
          id: 'overrides', name: 'Overrides',
          prompt: 'check',
          target: { session_target: 'isolated' },
          model_policy: { model: 'claude-opus-4-6' },
          trigger: { parent: 'inherits', on: 'success' }
        }
      ]
    }]
  };

  const compiled = compileManifestToScheduler(manifest);
  const inherits = compiled.jobs.find(j => j.source.task_id === 'inherits');
  const overrides = compiled.jobs.find(j => j.source.task_id === 'overrides');

  assert.equal(inherits.payload_model, 'anthropic/claude-sonnet-4-6');
  assert.equal(inherits.payload_thinking, 'high');
  assert.equal(overrides.payload_model, 'anthropic/claude-opus-4-6');
  assert.equal(overrides.payload_thinking, 'high');
});

test('stableId is deterministic and consistent across calls', () => {
  const id1 = stableId('workflow-a', 'task-1');
  const id2 = stableId('workflow-a', 'task-1');
  const id3 = stableId('workflow-a', 'task-2');

  assert.equal(id1, id2, 'same inputs must produce the same id');
  assert.notEqual(id1, id3, 'different inputs must produce different ids');
  assert.equal(id1.length, 32, 'id must be 32 hex characters');
  assert.match(id1, /^[0-9a-f]{32}$/, 'id must be lowercase hex');
});

test('POSIX shell rendering escapes single-quotes in args', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'quote-flow', name: 'Quote Flow',
      tasks: [{
        id: 'quoted', name: 'Quoted',
        shell: {
          program: 'echo',
          args: ["it's", "don't stop"]
        },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        delivery: { mode: 'none' }
      }]
    }]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, true);

  const compiled = compileManifestToScheduler(manifest);
  const msg = compiled.jobs[0].payload_message;
  assert.ok(!msg.includes("it's"), 'raw single-quote must not appear unescaped');
  assert.ok(msg.includes("'echo'"), 'program must be quoted');
  assert.ok(msg.includes("'\"'\"'"), 'single-quotes must be escaped via quote-break pattern');
});

test('on_failure handler inherits enabled: false from parent task', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'disabled-parent', name: 'Disabled Parent',
      tasks: [{
        id: 'root', name: 'Root',
        enabled: false,
        shell: { program: 'check.sh' },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        delivery: { mode: 'none' },
        on_failure: {
          prompt: 'Diagnose the failure.',
          delivery: { mode: 'announce' }
        }
      }]
    }]
  };

  const compiled = compileManifestToScheduler(manifest);
  assert.equal(compiled.jobs.length, 2);
  const handler = compiled.jobs.find(j => j.source.task_id === 'root.failure');
  assert.ok(handler);
  assert.equal(handler.enabled, 0, 'on_failure handler should inherit disabled state');
});

test('adopt-by-name falls back to id match when name does not match', async () => {
  const compiled = compileManifestToScheduler(exampleManifest);
  const existing = [{ ...compiled.jobs[0], name: 'Renamed Job' }];
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() { return existing; },
    addJob(spec) {
      calls.push({ action: 'create', spec });
      return { ok: true, job: spec };
    },
    updateJob(id, spec) {
      calls.push({ action: 'update', id, spec });
      return { ok: true, job: spec };
    }
  };

  const result = await applyManifestToScheduler(exampleManifest, { runner, adoptBy: 'name' });

  assert.equal(result.ok, true);
  assert.equal(result.actions[0].action, 'updated', 'should fall back to id match when name does not match');
  assert.equal(calls[0].action, 'update');
  assert.equal(calls[0].id, compiled.jobs[0].id);
});

test('json-rpc compile uses defaults.target when no target is specified', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'default-target',
    method: 'agentcli.compile',
    params: {
      manifest: exampleManifest
    }
  }, { target: 'openclaw-scheduler' });

  assert.equal(response.result.ok, true);
  assert.equal(response.result.target, 'openclaw-scheduler');
  assert.ok(Array.isArray(response.result.output.jobs));
});

test('resolveManifestCandidate uses injected cwd for relative paths', (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-resolve-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const result = resolveManifestCandidate('nonexistent.json', { cwd: workdir });
  assert.equal(result, null, 'should not find a nonexistent file');

  const testFile = join(workdir, 'test-manifest.json');
  writeFileSync(testFile, '{}');
  const resolved = resolveManifestCandidate('test-manifest.json', { cwd: workdir });
  assert.equal(resolved, testFile, 'should resolve relative path against injected cwd');
});

test('json-rpc unknown method returns -32601', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0',
    id: 'unknown-method',
    method: 'agentcli.nonexistent'
  });

  assert.equal(response.error.code, -32601);
  assert.match(response.error.message, /Method not found/);
});

test('invalid regex trigger condition fails validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        { id: 'root', name: 'Root', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '0 * * * *' } },
        { id: 'child', name: 'Child', prompt: 'follow', target: { session_target: 'isolated' }, trigger: { parent: 'root', on: 'success', condition: 'regex:[unclosed' } }
      ]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => /invalid regex/.test(e.message) || /Invalid regular expression/.test(e.message)));
});

test('whitespace-only regex trigger condition suffix fails validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        { id: 'root', name: 'Root', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '0 * * * *' } },
        { id: 'child', name: 'Child', prompt: 'follow', target: { session_target: 'isolated' }, trigger: { parent: 'root', on: 'success', condition: 'regex:   ' } }
      ]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => /regex trigger condition cannot be empty/.test(e.message)));
});

test('auto-reject policy compiles with correct approval fields', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'do it',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        approval: { policy: 'auto-reject' }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.approval_auto, 'reject');
  assert.equal(job.approval_required, 0);
});

test('manual policy with explicit required:false still compiles required to 1', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'do it',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        approval: { policy: 'manual', required: false }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.approval_required, 1, 'manual policy always implies required=1');
  assert.equal(job.approval_auto, 'reject');
});

test('output offload always sets threshold to 128', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'do it',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        output: { offload: 'always' }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  assert.equal(compiled.jobs[0].output_offload_threshold_bytes, 128);
});

test('output retrieve inline increases store limit', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'do it',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        output: { retrieve: 'inline', preview_bytes: 20000 }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  assert.equal(compiled.jobs[0].output_store_limit_bytes, 80000);
});

test('resolveSchedulerInvocation with .js suffix uses node execPath', () => {
  const invocation = resolveSchedulerInvocation({ schedulerBin: '/opt/scheduler.js' });
  assert.equal(invocation.command, process.execPath);
  assert.deepEqual(invocation.prefixArgs, ['/opt/scheduler.js']);
});

test('resolveSchedulerInvocation with plain binary uses it directly', () => {
  const invocation = resolveSchedulerInvocation({ schedulerBin: 'openclaw-scheduler' });
  assert.equal(invocation.command, 'openclaw-scheduler');
  assert.deepEqual(invocation.prefixArgs, []);
});

test('on_failure inherits agent_id from parent target', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'inherit-agent', name: 'Inherit Agent',
      tasks: [{
        id: 'root', name: 'Root',
        prompt: 'check',
        target: { session_target: 'isolated', agent_id: 'bot-agent' },
        schedule: { cron: '0 * * * *' },
        on_failure: {
          prompt: 'Diagnose.',
          delivery: { mode: 'announce' }
        }
      }]
    }]
  };

  const compiled = compileManifestToScheduler(manifest);
  const handler = compiled.jobs.find(j => j.source.task_id === 'root.failure');
  assert.ok(handler);
  assert.equal(handler.agent_id, 'bot-agent');
});

test('resolveAgentcliHome expands bare tilde to home directory', async () => {
  const { resolveAgentcliHome } = await import('../src/home.js');
  const result = resolveAgentcliHome({ env: { AGENTCLI_HOME: '~' }, homeDir: '/home/test' });
  assert.equal(result, '/home/test');
});

test('shell task with program only and no args renders correctly', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'minimal-shell', name: 'Minimal Shell',
      tasks: [{
        id: 'run', name: 'Run',
        shell: { program: 'uptime' },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        delivery: { mode: 'none' }
      }]
    }]
  };

  const result = validateManifest(manifest);
  assert.equal(result.ok, true);

  const compiled = compileManifestToScheduler(manifest);
  assert.equal(compiled.jobs[0].payload_message, "'uptime'");
});

test('trigger delay_s flows through to compiled scheduler job', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        { id: 'root', name: 'Root', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '0 * * * *' } },
        { id: 'delayed', name: 'Delayed', prompt: 'follow', target: { session_target: 'isolated' }, trigger: { parent: 'root', on: 'success', delay_s: 300 } }
      ]
    }]
  };

  const compiled = compileManifestToScheduler(manifest);
  const delayed = compiled.jobs.find(j => j.source.task_id === 'delayed');
  assert.equal(delayed.trigger_delay_s, 300);
});

test('duplicate workflow ids fail validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      { id: 'same', name: 'First', tasks: [{ id: 't', name: 'T', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '0 * * * *' } }] },
      { id: 'same', name: 'Second', tasks: [{ id: 't', name: 'T', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '0 * * * *' } }] }
    ]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => /unique/.test(e.message)));
});

test('duplicate task ids within a workflow fail validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        { id: 'dup', name: 'First', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '0 * * * *' } },
        { id: 'dup', name: 'Second', prompt: 'follow', target: { session_target: 'isolated' }, trigger: { parent: 'dup', on: 'success' } }
      ]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => /unique/.test(e.message)));
});

test('json-rpc non-object message returns -32600', async () => {
  const response = await handleJsonRpcRequest('hello');
  assert.equal(response.error.code, -32600);
});

test('json-rpc wrong jsonrpc version returns -32600', async () => {
  const response = await handleJsonRpcRequest({ jsonrpc: '1.0', id: 'x', method: 'agentcli.ping' });
  assert.equal(response.error.code, -32600);
});

test('AGENTCLI_TARGET env var selects compile target', async () => {
  const output = JSON.parse(await runCli(['compile', JSON.stringify(exampleManifest)], {
    env: { ...process.env, AGENTCLI_TARGET: 'openclaw-scheduler' }
  }));
  assert.equal(output.ok, true);
  assert.equal(output.target, 'openclaw-scheduler');
  assert.ok(Array.isArray(output.output.jobs));
});

test('cli --json with no command returns JSON help', async () => {
  const output = JSON.parse(await runCli(['--json']));
  assert.equal(output.ok, true);
  assert.ok(typeof output.usage === 'string');
  assert.ok(output.usage.length > 0);
});

test('cli init rejects when agentcli.json already exists', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-init-dup-'));
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  t.after(() => {
    rmSync(workdir, { recursive: true, force: true });
    rmSync(homeRoot, { recursive: true, force: true });
  });

  const envOverride = { ...process.env, AGENTCLI_HOME: homeRoot };
  await runCli(['init'], { cwd: workdir, env: envOverride });

  await assert.rejects(
    runCli(['init'], { cwd: workdir, env: envOverride }),
    /File already exists/
  );
});

// --- Sweep 10 tests ---

test('approval.required on scheduled task emits warning', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        approval: { required: true }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.ok(result.warnings.some(w => /approval_required.*root scheduled/.test(w.message)));
});

test('approval.policy + approval.required conflict emits warning', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        { id: 'root', name: 'Root', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '0 * * * *' } },
        {
          id: 'child', name: 'Child', prompt: 'follow',
          target: { session_target: 'isolated' },
          trigger: { parent: 'root', on: 'success' },
          approval: { policy: 'manual', required: false }
        }
      ]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.ok(result.warnings.some(w => /policy takes precedence/.test(w.message)));
});

test('context.limit vs budgets.max_context_items conflict emits warning', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        budgets: { max_context_items: 10 },
        context: { limit: 5 }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.ok(result.warnings.some(w => /context\.limit takes precedence/.test(w.message)));
});

test('shell target with plan intent emits advisory warning', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'check.sh' },
        target: { session_target: 'shell' },
        intent: { mode: 'plan' },
        schedule: { cron: '0 * * * *' },
        delivery: { mode: 'none' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.ok(result.warnings.some(w => /shell targets.*intent may be advisory/.test(w.message)));
});

test('sanitizeForAgent strips ANSI escape sequences', () => {
  const input = '\x1b[31mred text\x1b[0m';
  const result = sanitizeForAgent(input);
  assert.equal(result, 'red text');
});

test('sanitizeForAgent recurses into arrays', () => {
  const input = ['\x1b[1mbold\x1b[0m', 'plain'];
  const result = sanitizeForAgent(input);
  assert.deepEqual(result, ['bold', 'plain']);
});

test('sanitizeForAgent passes through primitives', () => {
  assert.equal(sanitizeForAgent(42), 42);
  assert.equal(sanitizeForAgent(true), true);
  assert.equal(sanitizeForAgent(null), null);
});

test('applyFieldMask supports dot-notation nested paths', () => {
  const item = { source: { workflow_id: 'w1', task_id: 't1' }, name: 'Job' };
  const result = applyFieldMask(item, ['source.task_id', 'name']);
  assert.deepEqual(result, { source: { task_id: 't1' }, name: 'Job' });
});

test('parseFieldMask returns null for empty/whitespace-only input', () => {
  assert.equal(parseFieldMask(''), null);
  assert.equal(parseFieldMask(' , , '), null);
  assert.equal(parseFieldMask(null), null);
  assert.equal(parseFieldMask(undefined), null);
});

test('parseFieldMask rejects non-string input', () => {
  assert.throws(() => parseFieldMask(123), /--fields requires/);
  assert.throws(() => parseFieldMask(true), /--fields requires/);
});

test('resolveSafeOutputPath rejects dot path', () => {
  assert.throws(() => resolveSafeOutputPath('.'), /must point to a file/);
});

test('loadJsonInput rejects falsy input', async () => {
  await assert.rejects(
    () => import('../src/io.js').then(m => m.loadJsonInput(null)),
    /Missing input/
  );
  await assert.rejects(
    () => import('../src/io.js').then(m => m.loadJsonInput('')),
    /Missing input/
  );
});

test('on_failure with shell and no explicit target infers shell session_target', () => {
  const task = {
    id: 'root', name: 'Root',
    prompt: 'check',
    target: { session_target: 'isolated', agent_id: 'bot' },
    on_failure: {
      shell: { program: 'notify.sh', args: ['--alert'] }
    }
  };
  const handler = buildOnFailureTask(task);
  assert.equal(handler.target.session_target, 'shell');
  assert.equal(handler.target.agent_id, 'bot');
  assert.ok(handler.shell);
  assert.equal(handler.shell.program, 'notify.sh');
});

test('on_failure with explicit target overrides inference', () => {
  const task = {
    id: 'root', name: 'Root',
    prompt: 'check',
    target: { session_target: 'isolated', agent_id: 'bot' },
    on_failure: {
      prompt: 'Diagnose failure.',
      target: { session_target: 'main', agent_id: 'ops' }
    }
  };
  const handler = buildOnFailureTask(task);
  assert.equal(handler.target.session_target, 'main');
  assert.equal(handler.target.agent_id, 'ops');
});

test('cli schema accepts kebab-case aliases', async () => {
  const output = JSON.parse(await runCli(['schema', 'scheduler-job']));
  assert.equal(output.ok, true);
  assert.ok(output.schema.fields.id);
});

test('subpath exports resolve correctly', async () => {
  const describe = await import('../src/describe.js');
  assert.equal(typeof describe.describeTarget, 'function');
  const sanitize = await import('../src/sanitize.js');
  assert.equal(typeof sanitize.sanitizeForAgent, 'function');
  const fields = await import('../src/fields.js');
  assert.equal(typeof fields.parseFieldMask, 'function');
  assert.equal(typeof fields.applyFieldMask, 'function');
  const io = await import('../src/io.js');
  assert.equal(typeof io.loadJsonInput, 'function');
  assert.equal(typeof io.resolveSafeOutputPath, 'function');
});

// --- Sweep 11 tests ---

test('invalid token characters in agent_id fail validation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated', agent_id: 'bad<agent>' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.includes('agent_id') && /token/.test(e.message)));
});

test('sanitizeForAgent recurses into nested objects', () => {
  const input = { outer: { inner: '\x1b[32mgreen\x1b[0m' }, plain: 'ok' };
  const result = sanitizeForAgent(input);
  assert.equal(result.outer.inner, 'green');
  assert.equal(result.plain, 'ok');
});

test('sanitizeForAgent with unsupported mode throws', () => {
  assert.throws(() => sanitizeForAgent('test', 'full'), /Unsupported sanitize mode/);
});

test('sanitizeForAgent with mode none returns value unchanged', () => {
  const input = '\x1b[31mred\x1b[0m';
  assert.equal(sanitizeForAgent(input, 'none'), input);
  assert.equal(sanitizeForAgent(input, null), input);
});

test('on_failure defaults agent_id to main when parent has no agent_id', () => {
  const task = {
    id: 'root', name: 'Root',
    prompt: 'check',
    target: { session_target: 'isolated' },
    on_failure: { prompt: 'Diagnose.' }
  };
  const handler = buildOnFailureTask(task);
  assert.equal(handler.target.agent_id, 'main');
});

test('expandManifestShorthands passes through tasks without on_failure unchanged', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        { id: 't1', name: 'T1', prompt: 'go', target: { session_target: 'isolated' }, schedule: { cron: '0 * * * *' } },
        { id: 't2', name: 'T2', prompt: 'follow', target: { session_target: 'isolated' }, trigger: { parent: 't1', on: 'success' } }
      ]
    }]
  };
  const expanded = expandManifestShorthands(manifest);
  assert.equal(expanded.workflows[0].tasks.length, 2);
  assert.equal(expanded.workflows[0].tasks[0].id, 't1');
  assert.equal(expanded.workflows[0].tasks[1].id, 't2');
});

test('intent with explicit read_only false compiles to 0', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        intent: { mode: 'execute', read_only: false }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  assert.equal(compiled.jobs[0].execution_read_only, 0);
  assert.equal(compiled.jobs[0].execution_intent, 'execute');
});

test('shell env validation rejects non-object env', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', env: 'FOO=bar' },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        delivery: { mode: 'none' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.includes('.env') && /must be an object/.test(e.message)));
});

test('approval required false with no policy compiles to required 0', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        approval: { required: false }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.approval_required, 0);
  assert.equal(job.approval_auto, null);
});

test('json-rpc describe rpc target returns methods and notifications', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 'desc-rpc',
    method: 'agentcli.describe',
    params: { target: 'rpc' }
  });
  assert.equal(response.result.ok, true);
  assert.ok(Array.isArray(response.result.description.methods));
  assert.ok(Array.isArray(response.result.description.notifications));
  assert.ok(response.result.description.methods.some(m => m.method === 'agentcli.ping'));
});

test('json-rpc describe with invalid target returns -32602', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 'desc-bad',
    method: 'agentcli.describe',
    params: { target: 'nonexistent' }
  });
  assert.equal(response.error.code, -32602);
  assert.match(response.error.message, /Unknown description target/);
});

test('json-rpc schema with invalid target returns -32602', async () => {
  const response = await handleJsonRpcRequest({
    jsonrpc: '2.0', id: 'schema-bad',
    method: 'agentcli.schema',
    params: { target: 'nonexistent' }
  });
  assert.equal(response.error.code, -32602);
  assert.match(response.error.message, /Unknown schema target/);
});

test('loadJsonInput with non-existent file path throws', async () => {
  const { loadJsonInput } = await import('../src/io.js');
  await assert.rejects(
    () => loadJsonInput('/tmp/agentcli-nonexistent-file-12345.json'),
    /Input not found/
  );
});

test('compile --explain includes explain in output', async () => {
  const output = JSON.parse(await runCli(['compile', JSON.stringify(exampleManifest), '--explain']));
  assert.equal(output.ok, true);
  assert.ok(Array.isArray(output.output.explain));
  assert.ok(output.output.explain.length > 0);
  assert.ok(output.output.explain[0].compiled_id);
  assert.ok(output.output.explain[0].notes);
});

test('compile --explain to openclaw-scheduler includes model_policy in explain', async () => {
  const output = JSON.parse(await runCli([
    'compile', JSON.stringify(exampleManifest),
    '--target', 'openclaw-scheduler', '--explain'
  ]));
  assert.equal(output.ok, true);
  assert.ok(Array.isArray(output.output.explain));
  assert.ok(output.output.explain[0].model_policy);
  assert.ok(output.output.explain[0].intent);
});

// --- Identity and Contract ---

test('identity block validates valid fields', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'user@example.com', run_as: 'ci-bot' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
});

test('identity block rejects non-object value', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: 'not-an-object',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.includes('identity') && /must be an object/.test(e.message)));
});

test('contract block validates valid fields', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      contract: { sandbox: 'strict', network: 'restricted', max_cost_usd: 5.0, audit: 'always' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
});

test('contract block rejects invalid sandbox enum', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      contract: { sandbox: 'ultra' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.includes('sandbox') && /must be one of/.test(e.message)));
});

test('contract.allowed_paths rejects non-array value', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      contract: { allowed_paths: '/tmp' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.includes('allowed_paths') && /must be an array/.test(e.message)));
});

test('contract.max_cost_usd rejects negative value', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      contract: { max_cost_usd: -1 },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.path.includes('max_cost_usd') && /must be a number >= 0/.test(e.message)));
});

test('identity inherits from workflow to task in compiled plan', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'admin@co.com', run_as: 'deployer' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const compiled = compileManifestToStandalone(manifest);
  const task = compiled.workflows[0].tasks[0];
  assert.equal(task.identity.principal, 'admin@co.com');
  assert.equal(task.identity.run_as, 'deployer');
  assert.equal(task.identity.attestation, null);
});

test('task-level identity overrides workflow-level identity key by key', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'admin@co.com', run_as: 'deployer' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        identity: { run_as: 'builder' }
      }]
    }]
  };
  const compiled = compileManifestToStandalone(manifest);
  const task = compiled.workflows[0].tasks[0];
  assert.equal(task.identity.principal, 'admin@co.com');
  assert.equal(task.identity.run_as, 'builder');
});

test('contract inherits from workflow to task in compiled plan', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      contract: { sandbox: 'strict', network: 'none', audit: 'always' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const compiled = compileManifestToStandalone(manifest);
  const task = compiled.workflows[0].tasks[0];
  assert.equal(task.contract.sandbox, 'strict');
  assert.equal(task.contract.network, 'none');
  assert.equal(task.contract.audit, 'always');
  assert.equal(task.contract.allowed_paths, null);
  assert.equal(task.contract.max_cost_usd, null);
});

test('task-level contract overrides workflow-level contract key by key', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      contract: { sandbox: 'strict', network: 'none' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        contract: { network: 'unrestricted', max_cost_usd: 5 }
      }]
    }]
  };
  const compiled = compileManifestToStandalone(manifest);
  const task = compiled.workflows[0].tasks[0];
  assert.equal(task.contract.sandbox, 'strict');
  assert.equal(task.contract.network, 'unrestricted');
  assert.equal(task.contract.max_cost_usd, 5);
});

test('scheduler compilation emits identity and contract fields', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'user@co.com' },
      contract: { sandbox: 'permissive', allowed_paths: ['/tmp', '/data'], max_cost_usd: 10 },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs[0];
  assert.equal(job.identity_principal, 'user@co.com');
  assert.equal(job.identity_run_as, null);
  assert.equal(job.identity_attestation, null);
  assert.equal(job.contract_sandbox, 'permissive');
  assert.equal(job.contract_allowed_paths, JSON.stringify(['/tmp', '/data']));
  assert.equal(job.contract_max_cost_usd, 10);
  assert.equal(job.contract_network, null);
  assert.equal(job.contract_audit, null);
});

test('on_failure handler propagates identity, contract, and v0.2 auth/evidence via shorthand expansion', () => {
  const manifest = {
    version: '0.2',
    authorization_proof_profiles: [{ id: 'proof', method: 'none', verify: { required: false } }],
    authorization_profiles: [{ id: 'authz', provider: 'none' }],
    evidence_profiles: [{ id: 'evidence', provider: 'none', verify: { required: false } }],
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        on_failure: {
          prompt: 'Handle failure',
          identity: { principal: 'ops@co.com' },
          contract: { audit: 'on-failure' },
          authorization_proof: { ref: 'proof', verify: { required: true } },
          authorization: { ref: 'authz', on_error: 'deny' },
          evidence: { ref: 'evidence', payload: { bind: ['command'] } }
        }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  const expanded = expandManifestShorthands(manifest);
  const failureTask = expanded.workflows[0].tasks.find(t => t.id === 't.failure');
  assert.ok(failureTask);
  assert.equal(failureTask.identity.principal, 'ops@co.com');
  assert.equal(failureTask.contract.audit, 'on-failure');
  assert.equal(failureTask.authorization_proof.ref, 'proof');
  assert.equal(failureTask.authorization_proof.verify.required, true);
  assert.equal(failureTask.authorization.ref, 'authz');
  assert.equal(failureTask.authorization.on_error, 'deny');
  assert.equal(failureTask.evidence.ref, 'evidence');
  assert.deepStrictEqual(failureTask.evidence.payload.bind, ['command']);
});

test('standalone capabilities include identity and contracts', () => {
  const compiled = compileManifestToStandalone(exampleManifest);
  assert.equal(compiled.capabilities.identity, true);
  assert.equal(compiled.capabilities.contracts, true);
});

// --- Skill Path ---

test('cli skill-path returns bundled skill path', async () => {
  const output = JSON.parse(await runCli(['skill-path']));
  assert.equal(output.ok, true);
  assert.ok(output.skill_path.endsWith('SKILL.md'));
  assert.ok(output.home_skill_path);
});

// --- Pretty Output ---

test('cli --pretty flag colorizes JSON output', async () => {
  const output = await runCli(['version', '--pretty']);
  assert.ok(output.includes('\x1b['), 'output should contain ANSI escape codes');
  assert.ok(output.includes('package_version'));
});

// --- Registry and Paths ---

test('paths output includes registry and skill_path', async () => {
  const output = JSON.parse(await runCli(['paths']));
  assert.equal(output.ok, true);
  assert.ok(output.paths.registry);
  assert.ok(output.paths.skill_path);
});

test('init creates registry directory', () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-init-'));
  const result = ensureAgentcliHome({ env: { AGENTCLI_HOME: workdir } });
  assert.equal(result.ok, true);
  assert.ok(existsSync(join(workdir, 'registry')));
  rmSync(workdir, { recursive: true, force: true });
});

// --- Identity/Contract in known keys (no unknown-key warnings) ---

test('identity and contract on workflow do not produce unknown-key warnings', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'user@co.com' },
      contract: { sandbox: 'none' },
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.equal(result.warnings.filter(w => w.message.includes('unknown key')).length, 0);
});

test('identity and contract on task do not produce unknown-key warnings', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        identity: { run_as: 'bot' },
        contract: { network: 'none' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.equal(result.warnings.filter(w => w.message.includes('unknown key')).length, 0);
});

test('identity and contract on on_failure do not produce unknown-key warnings', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'isolated' },
        schedule: { cron: '0 * * * *' },
        on_failure: {
          prompt: 'handle it',
          identity: { principal: 'ops@co.com' },
          contract: { audit: 'always' }
        }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  assert.equal(result.warnings.filter(w => w.message.includes('unknown key')).length, 0);
});

test('identity-contract example manifest validates and compiles', () => {
  const manifest = readExample('identity-contract.json');
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
  const standalone = compileManifestToStandalone(manifest);
  assert.strictEqual(standalone.workflows[0].tasks[0].identity.principal, 'deploy-bot@infra.example.com');
  assert.strictEqual(standalone.workflows[0].tasks[0].contract.sandbox, 'strict');
  const scheduler = compileManifestToScheduler(manifest);
  assert.strictEqual(scheduler.jobs[0].identity_principal, 'deploy-bot@infra.example.com');
  assert.strictEqual(scheduler.jobs[0].contract_sandbox, 'strict');
});

// --- exec: direct task execution ---

test('exec runs a shell task and returns structured result', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 'echo-test', name: 'Echo Test',
        shell: { program: 'echo', args: ['hello-agentcli'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 'echo-test' });
  assert.equal(result.ok, true);
  assert.equal(result.result.exit_code, 0);
  assert.ok(result.result.stdout.includes('hello-agentcli'));
  assert.ok(result.execution_id);
  assert.equal(result.source.workflow_id, 'w');
  assert.equal(result.source.task_id, 'echo-test');
  assert.ok(result.result.output_hash.startsWith('sha256:'));
  assert.equal(result.result.timed_out, false);
});

test('exec rejects non-shell tasks', () => {
  assert.throws(
    () => executeTask(exampleManifest, { taskId: 'collect' }),
    /exec only supports shell-target tasks/
  );
});

test('exec rejects missing taskId', () => {
  assert.throws(
    () => executeTask(shellManifest, {}),
    /taskId is required/
  );
});

test('exec rejects unknown task id', () => {
  assert.throws(
    () => executeTask(shellManifest, { taskId: 'nonexistent' }),
    /Task not found: nonexistent/
  );
});

test('exec rejects unknown workflow id', () => {
  assert.throws(
    () => executeTask(shellManifest, { workflowId: 'bad', taskId: 'check-space' }),
    /Workflow not found: bad/
  );
});

test('exec requires --workflow when multiple workflows present', () => {
  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: 'w1', name: 'W1',
        tasks: [{
          id: 't', name: 'T',
          shell: { program: 'echo' },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' }
        }]
      },
      {
        id: 'w2', name: 'W2',
        tasks: [{
          id: 't', name: 'T',
          shell: { program: 'echo' },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' }
        }]
      }
    ]
  };
  assert.throws(
    () => executeTask(manifest, { taskId: 't' }),
    /Multiple workflows found/
  );
  const result = executeTask(manifest, { workflowId: 'w1', taskId: 't', dryRun: true });
  assert.equal(result.ok, true);
});

test('exec dry-run does not spawn a process', () => {
  const result = executeTask(shellManifest, {
    taskId: 'check-space',
    dryRun: true,
  });
  assert.equal(result.ok, true);
  assert.equal(result.dry_run, true);
  assert.equal(result.command.program, 'df');
  assert.deepEqual(result.command.args, ['-h']);
  assert.ok(!result.result);
});

test('exec resolves identity from workflow to task', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'admin@co.com', run_as: 'deployer' },
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['hi'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        identity: { run_as: 'builder' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't' });
  assert.equal(result.identity.principal, 'admin@co.com');
  assert.equal(result.identity.run_as, 'builder');
});

test('exec enforces contract.allowed_paths against shell.cwd', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', cwd: '/usr/local/secret' },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { allowed_paths: ['/tmp', '/data'] }
      }]
    }]
  };
  assert.throws(
    () => executeTask(manifest, { taskId: 't' }),
    /not under any allowed path/
  );
});

test('exec allows cwd under an allowed path', () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-cwd-'));
  try {
    const manifest = {
      version: '0.1',
      workflows: [{
        id: 'w', name: 'W',
        tasks: [{
          id: 't', name: 'T',
          shell: { program: 'echo', args: ['ok'], cwd: workdir },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
          contract: { allowed_paths: [tmpdir()], audit: 'none' }
        }]
      }]
    };
    const result = executeTask(manifest, { taskId: 't' });
    assert.equal(result.ok, true);
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('exec returns advisory warnings for strict sandbox and network none', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['hi'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { sandbox: 'strict', network: 'none', audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't' });
  assert.ok(result.warnings.some(w => w.includes('sandbox')));
  assert.ok(result.warnings.some(w => w.includes('network')));
});

test('exec writes audit record when contract.audit is always', (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-exec-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['audited'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'always' }
      }]
    }]
  };
  const result = executeTask(manifest, {
    taskId: 't',
    env: { AGENTCLI_HOME: workdir },
  });
  assert.equal(result.ok, true);
  assert.equal(result.audited, true);

  const auditPath = join(workdir, 'state', 'audit.ndjson');
  assert.ok(existsSync(auditPath));
  const records = readAuditLog({ auditPath });
  assert.equal(records.length, 1);
  assert.equal(records[0].source.task_id, 't');
  assert.equal(records[0].result.exit_code, 0);
  assert.ok(records[0].execution_id);
  assert.ok(records[0].timestamp);
});

test('exec skips audit when contract.audit is none', (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-exec-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['silent'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, {
    taskId: 't',
    env: { AGENTCLI_HOME: workdir },
  });
  assert.equal(result.audited, false);
  assert.ok(!existsSync(join(workdir, 'state', 'audit.ndjson')));
});

test('exec audit on-failure only writes on non-zero exit', (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-exec-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));
  const auditPath = join(workdir, 'state', 'audit.ndjson');

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [
        {
          id: 'ok', name: 'OK',
          shell: { program: 'echo', args: ['pass'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
          contract: { audit: 'on-failure' }
        },
        {
          id: 'fail', name: 'Fail',
          shell: { program: 'false' },
          target: { session_target: 'shell' },
          trigger: { parent: 'ok', on: 'failure' },
          contract: { audit: 'on-failure' }
        }
      ]
    }]
  };

  executeTask(manifest, { taskId: 'ok', env: { AGENTCLI_HOME: workdir } });
  assert.ok(!existsSync(auditPath), 'audit should not exist after success');

  executeTask(manifest, { taskId: 'fail', env: { AGENTCLI_HOME: workdir } });
  assert.ok(existsSync(auditPath), 'audit should exist after failure');
  const records = readAuditLog({ auditPath });
  assert.equal(records.length, 1);
  assert.notEqual(records[0].result.exit_code, 0);
});

test('exec captures non-zero exit code', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'false' },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't' });
  assert.equal(result.ok, false);
  assert.notEqual(result.result.exit_code, 0);
});

test('exec respects timeout and reports timed_out', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'sleep', args: ['10'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        runtime: { timeout_ms: 100 },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't' });
  assert.equal(result.ok, false);
  assert.equal(result.result.timed_out, true);
});

test('exec with shell.env passes environment variables', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'sh', args: ['-c', 'echo $AGENTCLI_TEST_VAR'], env: { AGENTCLI_TEST_VAR: 'test-value-42' } },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't' });
  assert.equal(result.ok, true);
  assert.ok(result.result.stdout.includes('test-value-42'));
});

test('exec with shell.stdin pipes input to process', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'cat', stdin: 'hello from stdin' },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't' });
  assert.equal(result.ok, true);
  assert.ok(result.result.stdout.includes('hello from stdin'));
});

test('exec on on_failure expanded task works', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 'root', name: 'Root',
        shell: { program: 'echo', args: ['root'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        on_failure: {
          shell: { program: 'echo', args: ['failure-handler'] }
        }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 'root.failure' });
  assert.equal(result.ok, true);
  assert.ok(result.result.stdout.includes('failure-handler'));
});

// --- CLI exec and audit commands ---

test('cli exec runs a shell task from inline manifest', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['cli-exec-test'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const output = JSON.parse(await runCli(['exec', JSON.stringify(manifest), 't']));
  assert.equal(output.ok, true);
  assert.ok(output.result.stdout.includes('cli-exec-test'));
});

test('cli exec --dry-run does not execute', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['should-not-run'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' }
      }]
    }]
  };
  const output = JSON.parse(await runCli(['exec', JSON.stringify(manifest), 't', '--dry-run']));
  assert.equal(output.ok, true);
  assert.equal(output.dry_run, true);
  assert.ok(!output.result);
});

test('cli exec without task-id throws usage error', async () => {
  await assert.rejects(
    runCli(['exec', JSON.stringify(shellManifest)]),
    /Usage: agentcli exec/
  );
});

test('cli audit returns empty log when no executions', async () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-audit-'));
  try {
    const output = JSON.parse(await runCli(['audit'], { env: { ...process.env, AGENTCLI_HOME: workdir } }));
    assert.equal(output.ok, true);
    assert.equal(output.count, 0);
    assert.deepEqual(output.records, []);
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('cli audit --limit returns limited records', async () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-audit-'));
  try {
    const manifest = {
      version: '0.1',
      workflows: [{
        id: 'w', name: 'W',
        tasks: [{
          id: 't', name: 'T',
          shell: { program: 'echo', args: ['a'] },
          target: { session_target: 'shell' },
          schedule: { cron: '0 * * * *' },
          contract: { audit: 'always' }
        }]
      }]
    };
    const testEnv = { ...process.env, AGENTCLI_HOME: workdir };
    executeTask(manifest, { taskId: 't', env: testEnv });
    executeTask(manifest, { taskId: 't', env: testEnv });
    executeTask(manifest, { taskId: 't', env: testEnv });

    const output = JSON.parse(await runCli(['audit', '--limit', '2'], { env: testEnv }));
    assert.equal(output.ok, true);
    assert.equal(output.count, 2);
    assert.equal(output.records.length, 2);
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('paths output includes audit path', async () => {
  const output = JSON.parse(await runCli(['paths']));
  assert.ok(output.paths.audit);
  assert.ok(output.paths.audit.endsWith('audit.ndjson'));
});

test('paths output includes allowed_signers path', async () => {
  const output = JSON.parse(await runCli(['paths']));
  assert.ok(output.paths.allowed_signers);
  assert.ok(output.paths.allowed_signers.endsWith('allowed_signers'));
});

// --- Attestation: SSH key signing ---

test('resolveSigningKey finds SSH key from home directory', () => {
  const key = resolveSigningKey();
  // On this machine there is at least ~/.ssh/id_rsa
  assert.ok(key === null || key.includes('.ssh/'));
});

test('resolveSigningKey respects AGENTCLI_SIGNING_KEY env', () => {
  const key = resolveSigningKey({ env: { AGENTCLI_SIGNING_KEY: '/nonexistent/key' } });
  assert.equal(key, null);
});

test('buildAttestationPayload produces deterministic canonical JSON', () => {
  const fields = {
    executionId: 'abc123',
    timestamp: '2026-03-19T12:00:00Z',
    source: { workflow_id: 'w', task_id: 't' },
    commandHash: 'sha256:def456',
    principal: 'user@host',
  };
  const p1 = buildAttestationPayload(fields);
  const p2 = buildAttestationPayload(fields);
  assert.equal(p1, p2);
  const parsed = JSON.parse(p1);
  assert.equal(parsed.v, 1);
  assert.equal(parsed.execution_id, 'abc123');
  assert.equal(parsed.principal, 'user@host');
});

test('commandHash is stable for same inputs', () => {
  const shell = { program: 'echo', args: ['hello', 'world'], cwd: '/tmp' };
  const h1 = commandHash(shell);
  const h2 = commandHash(shell);
  assert.equal(h1, h2);
  assert.ok(h1.startsWith('sha256:'));
});

test('commandHash differs for different inputs', () => {
  const h1 = commandHash({ program: 'echo', args: ['a'] });
  const h2 = commandHash({ program: 'echo', args: ['b'] });
  assert.notEqual(h1, h2);
});

test('signPayload returns signed false when no key', () => {
  const result = signPayload('test payload', { keyPath: '/nonexistent/key' });
  assert.equal(result.signed, false);
  assert.ok(result.reason);
});

test('signPayload signs with a valid SSH key', () => {
  const key = resolveSigningKey();
  if (!key) return; // skip if no SSH key on this machine
  const result = signPayload('test payload for signing', { keyPath: key });
  assert.equal(result.signed, true);
  assert.ok(result.attestation.signature.includes('BEGIN SSH SIGNATURE'));
  assert.equal(result.attestation.method, 'ssh-signature');
  assert.equal(result.attestation.namespace, 'agentcli');
  assert.ok(result.attestation.key_fingerprint);
  assert.ok(result.attestation.key_fingerprint.startsWith('SHA256:'));
});

test('sign and verify round-trip succeeds', (t) => {
  const key = resolveSigningKey();
  if (!key) return;

  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-attest-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const payload = 'round-trip test payload';
  const sigResult = signPayload(payload, { keyPath: key });
  assert.equal(sigResult.signed, true);

  const principal = `test@agentcli`;
  const signersPath = join(workdir, 'allowed_signers');
  generateAllowedSigners({ principal, outputPath: signersPath });

  const verifyResult = verifySignature(sigResult.attestation, {
    allowedSignersPath: signersPath,
    principal,
  });
  assert.equal(verifyResult.verified, true);
  assert.equal(verifyResult.principal, principal);
});

test('verifySignature rejects tampered payload', (t) => {
  const key = resolveSigningKey();
  if (!key) return;

  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-tamper-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const sigResult = signPayload('original payload', { keyPath: key });
  assert.equal(sigResult.signed, true);

  const principal = `test@agentcli`;
  const signersPath = join(workdir, 'allowed_signers');
  generateAllowedSigners({ principal, outputPath: signersPath });

  // Tamper: change the signed_payload
  const tampered = { ...sigResult.attestation, signed_payload: 'tampered payload' };
  const verifyResult = verifySignature(tampered, {
    allowedSignersPath: signersPath,
    principal,
  });
  assert.equal(verifyResult.verified, false);
});

test('verifySignature rejects wrong principal', (t) => {
  const key = resolveSigningKey();
  if (!key) return;

  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-wrongp-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const sigResult = signPayload('principal test', { keyPath: key });
  assert.equal(sigResult.signed, true);

  const signersPath = join(workdir, 'allowed_signers');
  generateAllowedSigners({ principal: 'real@user', outputPath: signersPath });

  const verifyResult = verifySignature(sigResult.attestation, {
    allowedSignersPath: signersPath,
    principal: 'wrong@user',
  });
  assert.equal(verifyResult.verified, false);
});

test('verifySignature returns false for missing attestation', () => {
  const result = verifySignature(null, { allowedSignersPath: '/tmp', principal: 'x' });
  assert.equal(result.verified, false);
});

test('exec includes attestation when signing key is available', (t) => {
  const key = resolveSigningKey();
  if (!key) return;

  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-exec-attest-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'test@agentcli' },
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['attested'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'always' }
      }]
    }]
  };
  const result = executeTask(manifest, {
    taskId: 't',
    env: { AGENTCLI_HOME: workdir },
  });
  assert.equal(result.ok, true);
  assert.ok(result.attestation, 'attestation should be present');
  assert.equal(result.attestation.method, 'ssh-signature');
  assert.ok(result.attestation.key_fingerprint);

  // Audit record should also have the full attestation
  const records = readAuditLog({ auditPath: join(workdir, 'state', 'audit.ndjson') });
  assert.equal(records.length, 1);
  assert.ok(records[0].attestation);
  assert.ok(records[0].attestation.signature.includes('BEGIN SSH SIGNATURE'));
  assert.ok(records[0].attestation.signed_payload);
  assert.ok(records[0].command_hash.startsWith('sha256:'));
});

test('exec with signer none skips attestation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['unsigned'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, {
    taskId: 't',
    signer: 'none',
  });
  assert.equal(result.ok, true);
  assert.equal(result.attestation, null);
  assert.equal(result.signer, 'none');
  assert.ok(result.attestation_note.includes('signing disabled'));
});

test('cli verify rejects missing execution-id', async () => {
  await assert.rejects(
    runCli(['verify']),
    /Usage: agentcli verify/
  );
});

test('cli verify rejects unknown execution-id', async () => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-verify-'));
  try {
    await assert.rejects(
      runCli(['verify', 'nonexistent-id'], { env: { ...process.env, AGENTCLI_HOME: workdir } }),
      /Execution not found/
    );
  } finally {
    rmSync(workdir, { recursive: true, force: true });
  }
});

test('cli exec + verify end-to-end round-trip', async (t) => {
  const key = resolveSigningKey();
  if (!key) return;

  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-e2e-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'e2e@agentcli' },
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['e2e'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'always' }
      }]
    }]
  };

  const testEnv = { ...process.env, AGENTCLI_HOME: workdir };

  // Execute
  const execOutput = JSON.parse(await runCli([
    'exec', JSON.stringify(manifest), 't',
  ], { env: testEnv }));
  assert.equal(execOutput.ok, true);
  assert.ok(execOutput.attestation);
  const executionId = execOutput.execution_id;

  // Verify
  const verifyOutput = JSON.parse(await runCli([
    'verify', executionId,
  ], { env: testEnv }));
  assert.equal(verifyOutput.ok, true);
  assert.equal(verifyOutput.verified, true);
  assert.equal(verifyOutput.execution_id, executionId);
  assert.ok(verifyOutput.key_fingerprint);
});

// -- Signing provider registry tests --

test('listProviders includes ssh and none', () => {
  const providers = listProviders();
  assert.ok(providers.includes('ssh'));
  assert.ok(providers.includes('none'));
});

test('getProvider returns null for unknown provider', () => {
  assert.equal(getProvider('nonexistent'), null);
});

test('getProvider returns ssh provider', () => {
  const provider = getProvider('ssh');
  assert.ok(provider);
  assert.equal(provider.name, 'ssh');
  assert.equal(typeof provider.resolve, 'function');
  assert.equal(typeof provider.sign, 'function');
  assert.equal(typeof provider.verify, 'function');
});

test('resolveProvider defaults to ssh', () => {
  const provider = resolveProvider({ env: {} });
  assert.equal(provider.name, 'ssh');
});

test('resolveProvider respects AGENTCLI_SIGNER env', () => {
  const provider = resolveProvider({ env: { AGENTCLI_SIGNER: 'none' } });
  assert.equal(provider.name, 'none');
});

test('resolveProvider respects explicit signer over env', () => {
  const provider = resolveProvider({ signer: 'none', env: { AGENTCLI_SIGNER: 'ssh' } });
  assert.equal(provider.name, 'none');
});

test('resolveProvider throws for unknown signer', () => {
  assert.throws(
    () => resolveProvider({ signer: 'magic' }),
    /Unknown signing provider: "magic"/
  );
});

test('none provider sign returns signed false', () => {
  const provider = getProvider('none');
  const result = provider.sign('test payload', {});
  assert.equal(result.signed, false);
  assert.ok(result.reason.includes('signing disabled'));
});

test('none provider verify returns verified false', () => {
  const provider = getProvider('none');
  const result = provider.verify({ method: 'none' }, {});
  assert.equal(result.verified, false);
});

test('resolveProviderForMethod returns ssh for ssh-signature', () => {
  const provider = resolveProviderForMethod('ssh-signature');
  assert.ok(provider);
  assert.equal(provider.name, 'ssh');
});

test('resolveProviderForMethod returns null for unknown method', () => {
  assert.equal(resolveProviderForMethod('unknown-method'), null);
  assert.equal(resolveProviderForMethod(null), null);
});

test('ssh provider resolve returns null when no key available', () => {
  const provider = getProvider('ssh');
  const config = provider.resolve({ homeDir: '/nonexistent-home-dir', env: {} });
  assert.equal(config, null);
});

test('ssh provider sign returns signed false when config is null', () => {
  const provider = getProvider('ssh');
  const result = provider.sign('test', null);
  assert.equal(result.signed, false);
});

test('registerProvider rejects provider without name', () => {
  assert.throws(
    () => registerProvider({}),
    /must have a string name/
  );
});

test('registerProvider rejects provider without resolve', () => {
  assert.throws(
    () => registerProvider({ name: 'bad', sign: () => {}, verify: () => {} }),
    /must implement resolve/
  );
});

test('registerProvider rejects provider without sign', () => {
  assert.throws(
    () => registerProvider({ name: 'bad', resolve: () => {}, verify: () => {} }),
    /must implement sign/
  );
});

test('registerProvider rejects provider without verify', () => {
  assert.throws(
    () => registerProvider({ name: 'bad', resolve: () => {}, sign: () => {} }),
    /must implement verify/
  );
});

test('exec output includes signer field', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['signer-test'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't', signer: 'none' });
  assert.equal(result.signer, 'none');
});

test('exec with AGENTCLI_SIGNER=none skips attestation', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['env-signer'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, {
    taskId: 't',
    env: { ...process.env, AGENTCLI_SIGNER: 'none' },
  });
  assert.equal(result.signer, 'none');
  assert.equal(result.attestation, null);
});

test('exec rejects unknown signer', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['bad'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  assert.throws(
    () => executeTask(manifest, { taskId: 't', signer: 'imaginary' }),
    /Unknown signing provider/
  );
});

test('cli exec --signer none skips attestation', async () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['cli-signer'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const output = JSON.parse(await runCli([
    'exec', JSON.stringify(manifest), 't', '--signer', 'none',
  ]));
  assert.equal(output.signer, 'none');
  assert.equal(output.attestation, null);
});

test('verify output includes method field', async (t) => {
  const key = resolveSigningKey();
  if (!key) return;

  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-verify-method-'));
  t.after(() => rmSync(workdir, { recursive: true, force: true }));

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      identity: { principal: 'method-test@agentcli' },
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['method'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'always' }
      }]
    }]
  };

  const testEnv = { ...process.env, AGENTCLI_HOME: workdir };

  const execOutput = JSON.parse(await runCli([
    'exec', JSON.stringify(manifest), 't',
  ], { env: testEnv }));
  assert.equal(execOutput.ok, true);

  const verifyOutput = JSON.parse(await runCli([
    'verify', execOutput.execution_id,
  ], { env: testEnv }));
  assert.equal(verifyOutput.verified, true);
  assert.equal(verifyOutput.method, 'ssh-signature');
});

// -- registerTarget tests --

import { registerTarget } from '../src/targets.js';

test('registerTarget rejects target without name', () => {
  assert.throws(() => registerTarget({}), /must have a non-empty string name/);
});

test('registerTarget rejects target without compile', () => {
  assert.throws(
    () => registerTarget({ name: 'test-no-compile' }),
    /must implement compile/
  );
});

test('registerTarget rejects duplicate target name', () => {
  assert.throws(
    () => registerTarget({ name: 'standalone', compile: () => {} }),
    /already registered/
  );
});

// -- init tests --

import { createManifestScaffold } from '../src/init.js';

test('createManifestScaffold produces a valid manifest', () => {
  const { manifest, warnings } = createManifestScaffold();
  const validation = validateManifest(manifest);
  assert.equal(validation.ok, true);
  assert.equal(manifest.workflows[0].tasks[0].shell.program, 'echo');
  assert.deepEqual(warnings, []);
});

test('createManifestScaffold with --tool sets program', () => {
  const { manifest } = createManifestScaffold({ tool: 'echo' });
  assert.equal(manifest.workflows[0].tasks[0].shell.program, 'echo');
  assert.deepEqual(manifest.workflows[0].tasks[0].shell.args, []);
});

test('createManifestScaffold with custom ids', () => {
  const { manifest } = createManifestScaffold({
    workflowId: 'deploy',
    taskId: 'build',
  });
  assert.equal(manifest.workflows[0].id, 'deploy');
  assert.equal(manifest.workflows[0].tasks[0].id, 'build');
});

test('createManifestScaffold warns for missing tool on PATH', () => {
  const { warnings } = createManifestScaffold({ tool: 'nonexistent-binary-xyz' });
  assert.equal(warnings.length, 1);
  assert.ok(warnings[0].includes('not found on PATH'));
});

test('cli init with --output writes to custom path', async (t) => {
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-init-out-'));
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  t.after(() => {
    rmSync(workdir, { recursive: true, force: true });
    rmSync(homeRoot, { recursive: true, force: true });
  });

  const customPath = join(workdir, 'custom.json');
  const output = JSON.parse(await runCli([
    'init', '--output', customPath,
  ], { cwd: workdir, env: { ...process.env, AGENTCLI_HOME: homeRoot } }));

  assert.equal(output.ok, true);
  assert.equal(output.written_to, customPath);
  assert.ok(existsSync(customPath));
});

// -- registry tests --

import { listRegistry, addToRegistry, showRegistryEntry, removeFromRegistry } from '../src/registry.js';

test('registry list returns empty for fresh home', (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-reg-'));
  t.after(() => rmSync(homeRoot, { recursive: true, force: true }));

  const entries = listRegistry({ env: { AGENTCLI_HOME: homeRoot } });
  assert.deepEqual(entries, []);
});

test('registry add/show/list/remove lifecycle', (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-reg-'));
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-reg-work-'));
  t.after(() => {
    rmSync(homeRoot, { recursive: true, force: true });
    rmSync(workdir, { recursive: true, force: true });
  });

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'test-wf', name: 'Test',
      tasks: [{
        id: 't', name: 'T', prompt: 'do it',
        target: { session_target: 'main' },
        schedule: { cron: '0 * * * *' },
      }]
    }]
  };
  const filePath = join(workdir, 'test.json');
  writeFileSync(filePath, JSON.stringify(manifest));

  const addResult = addToRegistry(filePath, { env: { AGENTCLI_HOME: homeRoot } });
  assert.equal(addResult.name, 'test');

  const entries = listRegistry({ env: { AGENTCLI_HOME: homeRoot } });
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'test');
  assert.equal(entries[0].workflows[0].id, 'test-wf');

  const shown = showRegistryEntry('test', { env: { AGENTCLI_HOME: homeRoot } });
  assert.deepEqual(shown, manifest);

  const removed = removeFromRegistry('test', { env: { AGENTCLI_HOME: homeRoot } });
  assert.equal(removed.removed, true);

  assert.deepEqual(listRegistry({ env: { AGENTCLI_HOME: homeRoot } }), []);
});

test('registry add rejects invalid manifest', (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-reg-'));
  const workdir = mkdtempSync(join(tmpdir(), 'agentcli-reg-work-'));
  t.after(() => {
    rmSync(homeRoot, { recursive: true, force: true });
    rmSync(workdir, { recursive: true, force: true });
  });

  const filePath = join(workdir, 'bad.json');
  writeFileSync(filePath, JSON.stringify({ version: '0.1' }));

  assert.throws(
    () => addToRegistry(filePath, { env: { AGENTCLI_HOME: homeRoot } }),
    /validation failed/
  );
});

test('registry show rejects missing entry', (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-reg-'));
  t.after(() => rmSync(homeRoot, { recursive: true, force: true }));

  assert.throws(
    () => showRegistryEntry('nope', { env: { AGENTCLI_HOME: homeRoot } }),
    /not found/
  );
});

test('cli registry list returns entries', async (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-reg-cli-'));
  t.after(() => rmSync(homeRoot, { recursive: true, force: true }));

  const output = JSON.parse(await runCli(['registry', 'list'], {
    env: { ...process.env, AGENTCLI_HOME: homeRoot }
  }));
  assert.equal(output.ok, true);
  assert.ok(Array.isArray(output.entries));
});

// -- import tests --

import { importManifest } from '../src/import.js';

test('import discovers agentcli.json in directory', (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-imp-'));
  const toolDir = mkdtempSync(join(tmpdir(), 'agentcli-tool-'));
  t.after(() => {
    rmSync(homeRoot, { recursive: true, force: true });
    rmSync(toolDir, { recursive: true, force: true });
  });

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'imported', name: 'Imported',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'main' },
        schedule: { cron: '0 * * * *' },
      }]
    }]
  };
  writeFileSync(join(toolDir, 'agentcli.json'), JSON.stringify(manifest));

  const result = importManifest(toolDir, { env: { AGENTCLI_HOME: homeRoot } });
  assert.ok(result.path);
  assert.equal(result.discovery, 'agentcli.json');

  const entries = listRegistry({ env: { AGENTCLI_HOME: homeRoot } });
  assert.equal(entries.length, 1);
});

test('import discovers package.json agentcli field', (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-imp-'));
  const toolDir = mkdtempSync(join(tmpdir(), 'agentcli-tool-'));
  t.after(() => {
    rmSync(homeRoot, { recursive: true, force: true });
    rmSync(toolDir, { recursive: true, force: true });
  });

  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'pkg-tool', name: 'Pkg',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'main' },
        schedule: { cron: '0 * * * *' },
      }]
    }]
  };
  writeFileSync(join(toolDir, 'manifest.json'), JSON.stringify(manifest));
  writeFileSync(join(toolDir, 'package.json'), JSON.stringify({ name: 'my-tool', agentcli: 'manifest.json' }));

  const result = importManifest(toolDir, { env: { AGENTCLI_HOME: homeRoot } });
  assert.ok(result.discovery.includes('package.json'));
});

test('import rejects directory without manifest', (t) => {
  const toolDir = mkdtempSync(join(tmpdir(), 'agentcli-empty-'));
  t.after(() => rmSync(toolDir, { recursive: true, force: true }));

  assert.throws(
    () => importManifest(toolDir, { env: { AGENTCLI_HOME: '/tmp' } }),
    /No agentcli manifest found/
  );
});

// -- merge tests --

import { mergeManifests } from '../src/merge.js';

test('mergeManifests combines two manifests', () => {
  const a = {
    version: '0.1',
    workflows: [{
      id: 'a', name: 'A',
      tasks: [{ id: 't1', name: 'T1', prompt: 'go', target: { session_target: 'main' }, schedule: { cron: '0 * * * *' } }]
    }]
  };
  const b = {
    version: '0.1',
    workflows: [{
      id: 'b', name: 'B',
      tasks: [{ id: 't2', name: 'T2', prompt: 'go', target: { session_target: 'main' }, schedule: { cron: '0 * * * *' } }]
    }]
  };
  const merged = mergeManifests([a, b]);
  assert.equal(merged.workflows.length, 2);
  assert.equal(merged.workflows[0].id, 'a');
  assert.equal(merged.workflows[1].id, 'b');
});

test('mergeManifests rejects duplicate workflow ids', () => {
  const a = {
    version: '0.1',
    workflows: [{
      id: 'dup', name: 'A',
      tasks: [{ id: 't', name: 'T', prompt: 'go', target: { session_target: 'main' }, schedule: { cron: '0 * * * *' } }]
    }]
  };
  const b = {
    version: '0.1',
    workflows: [{
      id: 'dup', name: 'B',
      tasks: [{ id: 't', name: 'T', prompt: 'go', target: { session_target: 'main' }, schedule: { cron: '0 * * * *' } }]
    }]
  };
  assert.throws(
    () => mergeManifests([a, b]),
    /Duplicate workflow id "dup"/
  );
});

test('mergeManifests requires at least two manifests', () => {
  assert.throws(
    () => mergeManifests([{ version: '0.1', workflows: [{ id: 'a', name: 'A', tasks: [{ id: 't', name: 'T', prompt: 'go', target: { session_target: 'main' }, schedule: { cron: '0 * * * *' } }] }] }]),
    /at least two manifests/
  );
});

test('cli merge combines two manifests', async () => {
  const a = { version: '0.1', workflows: [{ id: 'cli-a', name: 'A', tasks: [{ id: 't', name: 'T', prompt: 'go', target: { session_target: 'main' }, schedule: { cron: '0 * * * *' } }] }] };
  const b = { version: '0.1', workflows: [{ id: 'cli-b', name: 'B', tasks: [{ id: 't', name: 'T', prompt: 'go', target: { session_target: 'main' }, schedule: { cron: '0 * * * *' } }] }] };

  const output = JSON.parse(await runCli([
    'merge', JSON.stringify(a), JSON.stringify(b),
  ]));
  assert.equal(output.ok, true);
  assert.equal(output.manifest.workflows.length, 2);
});

// -- output.format structured results tests --

test('output.format json in validation is accepted', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'main' },
        schedule: { cron: '0 * * * *' },
        output: { format: 'json' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, true);
});

test('output.format invalid value is rejected', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T', prompt: 'go',
        target: { session_target: 'main' },
        schedule: { cron: '0 * * * *' },
        output: { format: 'xml' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.equal(result.ok, false);
});

test('exec parses structured json output', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['{"status":"ok","count":42}'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        output: { format: 'json' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't', signer: 'none' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.result.structured, { status: 'ok', count: 42 });
});

test('exec structured json parse failure is non-fatal', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['not json'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        output: { format: 'json' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't', signer: 'none' });
  assert.equal(result.ok, true);
  assert.equal(result.result.structured, null);
  assert.ok(result.warnings.some(w => w.includes('not valid JSON')));
});

test('exec parses ndjson output', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'printf', args: ['{"a":1}\\n{"b":2}\\n'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        output: { format: 'ndjson' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't', signer: 'none' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.result.structured, [{ a: 1 }, { b: 2 }]);
});

test('exec without output.format returns structured null', () => {
  const manifest = {
    version: '0.1',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        shell: { program: 'echo', args: ['plain'] },
        target: { session_target: 'shell' },
        schedule: { cron: '0 * * * *' },
        contract: { audit: 'none' }
      }]
    }]
  };
  const result = executeTask(manifest, { taskId: 't', signer: 'none' });
  assert.equal(result.result.structured, null);
});

// ---------------------------------------------------------------------------
// v0.2 Execution Identity Tests
// ---------------------------------------------------------------------------

const identityV2Manifest = readExample('identity-v2.json');
const proofEnabledManifest = {
  version: '0.2',
  identity_profiles: [
    {
      id: 'agent',
      provider: 'none',
      subject: {
        kind: 'agent',
        principal: 'agent://local/proof-agent',
        delegation_mode: 'none'
      },
      trust: { level: 'supervised' },
      presentation: { handoff: 'none', cleanup: 'always' }
    }
  ],
  authorization_proof_profiles: [
    {
      id: 'jwt-proof',
      method: 'jwt',
      proof: { value_from: { env: 'TEST_AGENTCLI_JWT' } },
      claims: { subject: 'agentcli-proof' },
      verify: { required: true }
    }
  ],
  authorization_profiles: [
    {
      id: 'permit',
      provider: 'none',
      provider_config: { team: 'ops' },
      request: { include: ['identity'] },
      decision: { allow_values: ['permit'] }
    }
  ],
  evidence_profiles: [
    {
      id: 'none-evidence',
      provider: 'none',
      payload: { bind: ['execution_id', 'command', 'result'] },
      verify: { required: false }
    }
  ],
  workflows: [
    {
      id: 'proof-workflow',
      name: 'Proof Workflow',
      identity: { ref: 'agent' },
      authorization_proof: { ref: 'jwt-proof' },
      tasks: [
        {
          id: 'proof-task',
          name: 'Proof Task',
          target: { session_target: 'shell' },
          shell: { program: 'echo', args: ['proof-ok'] },
          schedule: { cron: '0 * * * *' },
          authorization: {
            ref: 'permit',
            provider_config: { task: 'proof-task' }
          },
          evidence: {
            ref: 'none-evidence',
            payload: { bind: ['command'] }
          }
        }
      ]
    }
  ]
};
const applyProofManifest = {
  version: '0.2',
  authorization_proof_profiles: [
    {
      id: 'jwt-proof',
      method: 'jwt',
      proof: { value_from: { env: 'TEST_AGENTCLI_JWT' } },
      claims: { subject: 'agentcli-proof' },
      verify: { required: true }
    }
  ],
  workflows: [
    {
      id: 'apply-proof',
      name: 'Apply Proof',
      authorization_proof: { ref: 'jwt-proof' },
      tasks: [
        {
          id: 'verify-me',
          name: 'Verify Me',
          target: { session_target: 'shell' },
          shell: { program: 'echo', args: ['apply-proof'] },
          schedule: { cron: '0 * * * *' }
        }
      ]
    }
  ]
};
const applyProofOverrideManifest = {
  version: '0.2',
  authorization_proof_profiles: [
    {
      id: 'jwt-proof',
      method: 'jwt',
      proof: { value_from: { env: 'TEST_AGENTCLI_JWT' } },
      claims: { subject: 'wrong-subject' },
      verify: { required: true }
    }
  ],
  workflows: [
    {
      id: 'apply-proof-override',
      name: 'Apply Proof Override',
      tasks: [
        {
          id: 'verify-override',
          name: 'Verify Override',
          target: { session_target: 'shell' },
          shell: { program: 'echo', args: ['apply-proof-override'] },
          schedule: { cron: '0 * * * *' },
          authorization_proof: {
            ref: 'jwt-proof',
            claims: { subject: 'agentcli-proof' }
          }
        }
      ]
    }
  ]
};
const applyOnFailureProofManifest = {
  version: '0.2',
  authorization_proof_profiles: [
    {
      id: 'jwt-proof',
      method: 'jwt',
      proof: { value_from: { env: 'TEST_AGENTCLI_JWT' } },
      claims: { subject: 'agentcli-proof' },
      verify: { required: true }
    }
  ],
  workflows: [
    {
      id: 'apply-proof-failure',
      name: 'Apply Proof Failure',
      tasks: [
        {
          id: 'primary',
          name: 'Primary',
          target: { session_target: 'shell' },
          shell: { program: 'echo', args: ['primary'] },
          schedule: { cron: '0 * * * *' },
          on_failure: {
            name: 'Handle Failure',
            shell: { program: 'echo', args: ['failure'] },
            authorization_proof: { ref: 'jwt-proof' }
          }
        }
      ]
    }
  ]
};

// -- Schema and Validation Tests --

test('v0.2 manifest with identity_profiles validates', () => {
  const manifest = structuredClone(identityV2Manifest);
  const result = validateManifest(manifest);
  assert.strictEqual(result.ok, true, `Validation failed: ${JSON.stringify(result.errors)}`);
});

test('v0.2 manifest version is accepted', () => {
  const manifest = {
    version: '0.2',
    workflows: [{
      id: 'w', name: 'W',
      tasks: [{
        id: 't', name: 'T',
        target: { session_target: 'shell' },
        shell: { program: 'echo' },
        schedule: { cron: '* * * * *' }
      }]
    }]
  };
  const result = validateManifest(manifest);
  assert.strictEqual(result.ok, true);
});

// -- Identity Provider Registry Tests --

test('identity provider registry lists none and env-bearer', async () => {
  const { listProviders: listIdentityProviders } = await import('../src/identity/index.js');
  await import('../src/identity/none.js');
  await import('../src/identity/env-bearer.js');
  const providers = listIdentityProviders();
  assert.ok(providers.includes('none'));
  assert.ok(providers.includes('env-bearer'));
});

test('none identity provider resolves minimal session', async () => {
  const { getProvider: getIdentityProvider } = await import('../src/identity/index.js');
  await import('../src/identity/none.js');
  const provider = getIdentityProvider('none');
  const session = provider.resolveSession({
    profile: {
      subject: { principal: 'test://p' },
      trust: { level: 'supervised' }
    }
  }, {});
  assert.strictEqual(session.provider, 'none');
  assert.strictEqual(session.subject.principal, 'test://p');
  assert.deepStrictEqual(session.credentials, {});
});

test('none identity provider validateProfile always succeeds', async () => {
  const { getProvider: getIdentityProvider } = await import('../src/identity/index.js');
  await import('../src/identity/none.js');
  const provider = getIdentityProvider('none');
  const result = provider.validateProfile({}, {});
  assert.strictEqual(result.valid, true);
});

test('env-bearer identity provider validates profile with token_env', async () => {
  const { getProvider: getIdentityProvider } = await import('../src/identity/index.js');
  await import('../src/identity/env-bearer.js');
  const provider = getIdentityProvider('env-bearer');
  const result = provider.validateProfile({
    auth: { provider_config: { token_env: 'MY_TOKEN' } }
  }, {});
  assert.strictEqual(result.valid, true);
});

test('env-bearer identity provider rejects profile without token_env', async () => {
  const { getProvider: getIdentityProvider } = await import('../src/identity/index.js');
  await import('../src/identity/env-bearer.js');
  const provider = getIdentityProvider('env-bearer');
  const result = provider.validateProfile({ auth: {} }, {});
  assert.strictEqual(result.valid, false);
  assert.ok(result.errors.length > 0);
});

test('env-bearer resolves session with token from env', async () => {
  const { getProvider: getIdentityProvider } = await import('../src/identity/index.js');
  await import('../src/identity/env-bearer.js');
  const provider = getIdentityProvider('env-bearer');
  const session = provider.resolveSession({
    profile: {
      subject: { kind: 'service', principal: 'agent://svc' },
      auth: { required: true, provider_config: { token_env: 'TEST_TOK' } },
      trust: { level: 'restricted' }
    }
  }, { env: { TEST_TOK: 'abc123' } });
  assert.strictEqual(session.provider, 'env-bearer');
  assert.strictEqual(session.subject.principal, 'agent://svc');
  assert.strictEqual(session.credentials.access_token.value, 'abc123');
  assert.strictEqual(session.credentials.access_token.kind, 'bearer');
});

test('env-bearer resolves empty credentials when token missing and not required', async () => {
  const { getProvider: getIdentityProvider } = await import('../src/identity/index.js');
  await import('../src/identity/env-bearer.js');
  const provider = getIdentityProvider('env-bearer');
  const session = provider.resolveSession({
    profile: {
      subject: { principal: 'agent://svc' },
      auth: { required: false, provider_config: { token_env: 'MISSING_TOK' } },
      trust: { level: 'restricted' }
    }
  }, { env: {} });
  assert.strictEqual(session.provider, 'env-bearer');
  assert.deepStrictEqual(session.credentials, {});
});

test('env-bearer throws when token missing and required', async () => {
  const { getProvider: getIdentityProvider } = await import('../src/identity/index.js');
  await import('../src/identity/env-bearer.js');
  const provider = getIdentityProvider('env-bearer');
  assert.throws(() => {
    provider.resolveSession({
      profile: {
        subject: { principal: 'agent://svc' },
        auth: { required: true, provider_config: { token_env: 'MISSING_TOK' } },
        trust: { level: 'restricted' }
      }
    }, { env: {} });
  }, /Bearer token not found/);
});

// -- Session Utilities Tests --

test('resolveSourcePath navigates session objects', async () => {
  const { resolveSourcePath } = await import('../src/identity/session.js');
  const session = {
    credentials: {
      access_token: {
        value: 'secret123',
        expires_at: '2026-12-31T00:00:00Z'
      }
    }
  };
  assert.strictEqual(resolveSourcePath(session, 'credentials.access_token.value'), 'secret123');
  assert.strictEqual(resolveSourcePath(session, 'credentials.access_token.expires_at'), '2026-12-31T00:00:00Z');
  assert.strictEqual(resolveSourcePath(session, 'credentials.missing.path'), undefined);
});

test('resolveSourcePath returns undefined for null session', async () => {
  const { resolveSourcePath } = await import('../src/identity/session.js');
  assert.strictEqual(resolveSourcePath(null, 'credentials.value'), undefined);
  assert.strictEqual(resolveSourcePath({}, ''), undefined);
});

test('compareTrustLevels orders correctly', async () => {
  const { compareTrustLevels } = await import('../src/identity/session.js');
  assert.strictEqual(compareTrustLevels('untrusted', 'autonomous'), -1);
  assert.strictEqual(compareTrustLevels('supervised', 'supervised'), 0);
  assert.strictEqual(compareTrustLevels('autonomous', 'restricted'), 1);
  assert.strictEqual(compareTrustLevels('restricted', 'supervised'), -1);
  assert.strictEqual(compareTrustLevels('supervised', 'restricted'), 1);
});

test('compareTrustLevels throws on unknown level', async () => {
  const { compareTrustLevels } = await import('../src/identity/session.js');
  assert.throws(() => compareTrustLevels('bogus', 'supervised'), /Unknown trust level/);
});

test('redactSession removes credential values', async () => {
  const { redactSession } = await import('../src/identity/session.js');
  const session = {
    provider: 'test',
    credentials: {
      access_token: { value: 'secret', kind: 'bearer' }
    }
  };
  const redacted = redactSession(session);
  assert.strictEqual(redacted.credentials.access_token.value, '[REDACTED]');
  assert.strictEqual(redacted.credentials.access_token.kind, '[REDACTED]');
  assert.strictEqual(redacted.provider, 'test');
});

test('redactSession preserves nested structure', async () => {
  const { redactSession } = await import('../src/identity/session.js');
  const session = {
    provider: 'test',
    credentials: {
      nested: { inner: { deep_secret: 'hidden' } }
    }
  };
  const redacted = redactSession(session);
  assert.strictEqual(redacted.credentials.nested.inner.deep_secret, '[REDACTED]');
  assert.strictEqual(redacted.provider, 'test');
});

test('buildCredentialSummary returns types and expiry', async () => {
  const { buildCredentialSummary } = await import('../src/identity/session.js');
  const session = {
    credentials: {
      access_token: { kind: 'bearer', expires_at: '2026-12-31T00:00:00Z' },
      refresh_token: { kind: 'refresh', expires_at: '2027-06-30T00:00:00Z' }
    }
  };
  const summary = buildCredentialSummary(session);
  assert.ok(summary.credential_types.includes('bearer'));
  assert.ok(summary.credential_types.includes('refresh'));
  assert.strictEqual(summary.expires_at, '2026-12-31T00:00:00Z');
});

test('validateTrustLevel accepts canonical levels', async () => {
  const { validateTrustLevel } = await import('../src/identity/session.js');
  assert.strictEqual(validateTrustLevel('untrusted').valid, true);
  assert.strictEqual(validateTrustLevel('restricted').valid, true);
  assert.strictEqual(validateTrustLevel('supervised').valid, true);
  assert.strictEqual(validateTrustLevel('autonomous').valid, true);
  assert.strictEqual(validateTrustLevel('bogus').valid, false);
});

test('formatMaterializationValue handles raw, json, and base64', async () => {
  const { formatMaterializationValue } = await import('../src/identity/session.js');
  assert.strictEqual(formatMaterializationValue('hello', 'raw'), 'hello');
  assert.strictEqual(formatMaterializationValue({ a: 1 }, 'json'), '{"a":1}');
  assert.strictEqual(formatMaterializationValue('hello', 'base64'), Buffer.from('hello').toString('base64'));
});

// -- Evidence Provider Tests --

test('evidence provider registry lists none and ssh', async () => {
  const { listEvidenceProviders } = await import('../src/evidence/index.js');
  await import('../src/evidence/none.js');
  await import('../src/evidence/ssh.js');
  const providers = listEvidenceProviders();
  assert.ok(providers.includes('none'));
  assert.ok(providers.includes('ssh'));
});

test('none evidence provider returns attested: false', async () => {
  const { getEvidenceProvider } = await import('../src/evidence/index.js');
  await import('../src/evidence/none.js');
  const provider = getEvidenceProvider('none');
  const result = provider.attest('payload', {}, {});
  assert.strictEqual(result.attested, false);
});

test('none evidence provider verify returns verified: false', async () => {
  const { getEvidenceProvider } = await import('../src/evidence/index.js');
  await import('../src/evidence/none.js');
  const provider = getEvidenceProvider('none');
  const result = provider.verify();
  assert.strictEqual(result.verified, false);
});

test('none evidence provider describe returns provider none', async () => {
  const { getEvidenceProvider } = await import('../src/evidence/index.js');
  await import('../src/evidence/none.js');
  const provider = getEvidenceProvider('none');
  const result = provider.describe();
  assert.strictEqual(result.provider, 'none');
  assert.strictEqual(result.attested, false);
});

test('ssh evidence provider resolves signing key', async () => {
  const { resolveSigningKey: resolveEvidenceSigningKey } = await import('../src/evidence/ssh.js');
  const result = resolveEvidenceSigningKey({ signingKey: '/nonexistent/key' });
  assert.strictEqual(result, null);
});

// -- Evidence Payload Tests --

test('buildEvidencePayload filters by bind targets', async () => {
  const { buildEvidencePayload } = await import('../src/evidence/payload.js');
  const payload = buildEvidencePayload({
    executionId: 'abc123',
    timestamp: '2026-03-21T00:00:00Z',
    source: { workflow_id: 'w', task_id: 't' },
    command: { program: 'echo', args: [], cwd: '/tmp' },
    result: { exit_code: 0, duration_ms: 10 },
    contract: { sandbox: 'permissive' },
    bindTargets: ['execution_id', 'command'],
  });
  assert.ok(payload.execution_id);
  assert.ok(payload.command);
  assert.strictEqual(payload.contract, undefined);
  assert.strictEqual(payload.result, undefined);
});

test('buildEvidencePayload always includes timestamp and source', async () => {
  const { buildEvidencePayload } = await import('../src/evidence/payload.js');
  const payload = buildEvidencePayload({
    executionId: 'abc123',
    timestamp: '2026-03-21T00:00:00Z',
    source: { workflow_id: 'w', task_id: 't' },
    bindTargets: [],
  });
  assert.strictEqual(payload.timestamp, '2026-03-21T00:00:00Z');
  assert.deepStrictEqual(payload.source, { workflow_id: 'w', task_id: 't' });
  assert.strictEqual(payload.execution_id, undefined);
});

test('serializePayload canonical-json sorts keys', async () => {
  const { serializePayload } = await import('../src/evidence/payload.js');
  const result = serializePayload({ z: 1, a: 2 }, 'canonical-json');
  assert.strictEqual(result, '{"a":2,"z":1}');
});

test('serializePayload canonical-json sorts nested keys', async () => {
  const { serializePayload } = await import('../src/evidence/payload.js');
  const result = serializePayload({ z: { b: 2, a: 1 }, m: 3 }, 'canonical-json');
  assert.strictEqual(result, '{"m":3,"z":{"a":1,"b":2}}');
});

test('serializePayload json mode does not sort keys', async () => {
  const { serializePayload } = await import('../src/evidence/payload.js');
  const result = serializePayload({ z: 1, a: 2 }, 'json');
  assert.strictEqual(result, '{"z":1,"a":2}');
});

test('collectComplianceContext returns null for missing fields', async () => {
  const { collectComplianceContext } = await import('../src/evidence/payload.js');
  const result = collectComplianceContext({}, { model_version: true });
  assert.strictEqual(result.model_version, null);
});

test('collectComplianceContext passes through available values', async () => {
  const { collectComplianceContext } = await import('../src/evidence/payload.js');
  const result = collectComplianceContext(
    { compliance_context: { model_version: 'gpt-5-nano' } },
    { model_version: true }
  );
  assert.strictEqual(result.model_version, 'gpt-5-nano');
});

// -- Authorization Proof Verifier Tests --

test('authorization proof verifier registry lists none and jwt', async () => {
  const { listVerifiers } = await import('../src/authorization-proof/index.js');
  await import('../src/authorization-proof/none.js');
  await import('../src/authorization-proof/jwt.js');
  const verifiers = listVerifiers();
  assert.ok(verifiers.includes('none'));
  assert.ok(verifiers.includes('jwt'));
});

test('none verifier rejects verify.required: true', async () => {
  const { getVerifier } = await import('../src/authorization-proof/index.js');
  await import('../src/authorization-proof/none.js');
  const verifier = getVerifier('none');
  const result = verifier.validateProfile({ verify: { required: true } }, {});
  assert.strictEqual(result.valid, false);
});

test('none verifier accepts verify.required: false', async () => {
  const { getVerifier } = await import('../src/authorization-proof/index.js');
  await import('../src/authorization-proof/none.js');
  const verifier = getVerifier('none');
  const result = verifier.validateProfile({ verify: { required: false } }, {});
  assert.strictEqual(result.valid, true);
});

test('none verifier verifyProof returns unverified', async () => {
  const { getVerifier } = await import('../src/authorization-proof/index.js');
  await import('../src/authorization-proof/none.js');
  const verifier = getVerifier('none');
  const result = verifier.verifyProof(null, {}, {});
  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.method, 'none');
});

test('jwt verifier validates profile with issuer', async () => {
  const { getVerifier } = await import('../src/authorization-proof/index.js');
  await import('../src/authorization-proof/jwt.js');
  const verifier = getVerifier('jwt');
  const result = verifier.validateProfile({
    issuer: 'https://issuer.example.com',
    proof: { value_from: { env: 'JWT_TOKEN' } }
  }, {});
  assert.strictEqual(result.valid, true);
});

test('jwt verifier rejects profile with empty issuer', async () => {
  const { getVerifier } = await import('../src/authorization-proof/index.js');
  await import('../src/authorization-proof/jwt.js');
  const verifier = getVerifier('jwt');
  const result = verifier.validateProfile({ issuer: '' }, {});
  assert.strictEqual(result.valid, false);
});

test('jwt verifier rejects non-string proof', async () => {
  const { getVerifier } = await import('../src/authorization-proof/index.js');
  await import('../src/authorization-proof/jwt.js');
  const verifier = getVerifier('jwt');
  const result = verifier.verifyProof(null, {}, {});
  assert.strictEqual(result.verified, false);
  assert.strictEqual(result.method, 'jwt');
});

// -- Authorization Provider Tests --

test('authorization provider registry lists none', async () => {
  const { listAuthorizationProviders } = await import('../src/authorization/index.js');
  await import('../src/authorization/none.js');
  const providers = listAuthorizationProviders();
  assert.ok(providers.includes('none'));
});

test('none authorization provider always permits', async () => {
  const { getAuthorizationProvider } = await import('../src/authorization/index.js');
  await import('../src/authorization/none.js');
  const provider = getAuthorizationProvider('none');
  const result = provider.authorize({}, {}, {});
  assert.strictEqual(result.decision, 'permit');
  assert.strictEqual(result.provider, 'none');
});

test('normalizeDecision maps allow to permit', async () => {
  const { normalizeDecision } = await import('../src/authorization/index.js');
  const result = normalizeDecision('allow', {
    allow_values: ['allow'],
    deny_values: ['deny'],
    escalate_values: []
  });
  assert.strictEqual(result.decision, 'permit');
  assert.strictEqual(result.mapped, true);
});

test('normalizeDecision maps deny to deny', async () => {
  const { normalizeDecision } = await import('../src/authorization/index.js');
  const result = normalizeDecision('deny', {
    allow_values: ['allow'],
    deny_values: ['deny'],
    escalate_values: []
  });
  assert.strictEqual(result.decision, 'deny');
  assert.strictEqual(result.mapped, true);
});

test('normalizeDecision maps escalate values', async () => {
  const { normalizeDecision } = await import('../src/authorization/index.js');
  const result = normalizeDecision('needs-review', {
    allow_values: ['allow'],
    deny_values: ['deny'],
    escalate_values: ['needs-review']
  });
  assert.strictEqual(result.decision, 'require-escalation');
  assert.strictEqual(result.mapped, true);
});

test('normalizeDecision defaults unmapped to deny', async () => {
  const { normalizeDecision } = await import('../src/authorization/index.js');
  const result = normalizeDecision('unknown-value', {
    allow_values: ['allow'],
    deny_values: ['deny'],
    escalate_values: []
  });
  assert.strictEqual(result.decision, 'deny');
  assert.strictEqual(result.mapped, false);
});

test('normalizeAuthorizationRequest includes only listed fields', async () => {
  const { normalizeAuthorizationRequest } = await import('../src/authorization/index.js');
  const result = normalizeAuthorizationRequest({
    source: { workflow_id: 'w', task_id: 't' },
    identity: { principal: 'agent://a', trust_level: 'supervised' },
    contract: { required_trust_level: 'restricted' },
    command: { program: 'echo', args: ['hi'] },
    includeFields: ['identity'],
  });
  assert.ok(result.source);
  assert.ok(result.identity);
  assert.strictEqual(result.contract, undefined);
  assert.strictEqual(result.command, undefined);
});

// -- Three-Stage Merge Tests --

test('resolveIdentityV2 merges workflow and task identity', () => {
  const workflowIdentity = {
    ref: 'profile-a',
    subject: { kind: 'agent', principal: 'agent://a' },
    trust: { level: 'supervised' }
  };
  const taskIdentity = {
    subject: { principal: 'agent://b' },
    trust: { level: 'restricted' }
  };
  const result = resolveIdentityV2(workflowIdentity, taskIdentity);
  assert.strictEqual(result.ref, 'profile-a');
  assert.strictEqual(result.subject.principal, 'agent://b');
  assert.strictEqual(result.subject.kind, 'agent');
  assert.strictEqual(result.trust.level, 'restricted');
});

test('resolveIdentityV2 task ref overrides workflow ref', () => {
  const workflowIdentity = { ref: 'profile-a' };
  const taskIdentity = { ref: 'profile-b' };
  const result = resolveIdentityV2(workflowIdentity, taskIdentity);
  assert.strictEqual(result.ref, 'profile-b');
});

test('resolveIdentityV2 merges auth fields', () => {
  const workflowIdentity = {
    auth: { mode: 'service', scopes: ['read'], provider_config: { token_env: 'TOK' } }
  };
  const taskIdentity = {
    auth: { scopes: ['read', 'write'] }
  };
  const result = resolveIdentityV2(workflowIdentity, taskIdentity);
  assert.strictEqual(result.auth.mode, 'service');
  assert.deepStrictEqual(result.auth.scopes, ['read', 'write']);
  assert.deepStrictEqual(result.auth.provider_config, { token_env: 'TOK' });
});

test('resolveIdentityV2 merges presentation bindings replace', () => {
  const workflowIdentity = {
    presentation: { bindings: [{ source: 'a' }], handoff: 'none' }
  };
  const taskIdentity = {
    presentation: { bindings: [{ source: 'b' }] }
  };
  const result = resolveIdentityV2(workflowIdentity, taskIdentity);
  assert.strictEqual(result.presentation.bindings.length, 1);
  assert.strictEqual(result.presentation.bindings[0].source, 'b');
  assert.strictEqual(result.presentation.handoff, 'none');
});

test('resolveIdentityV2 merges trust constraints', () => {
  const workflowIdentity = {
    trust: { level: 'supervised', constraints: { max_autonomy: 'supervised', escalation: 'fail' } }
  };
  const taskIdentity = {
    trust: { constraints: { escalation: 'warn' } }
  };
  const result = resolveIdentityV2(workflowIdentity, taskIdentity);
  assert.strictEqual(result.trust.level, 'supervised');
  assert.strictEqual(result.trust.constraints.max_autonomy, 'supervised');
  assert.strictEqual(result.trust.constraints.escalation, 'warn');
});

test('resolveIdentityV2 returns nulls for empty inputs', () => {
  const result = resolveIdentityV2({}, {});
  assert.strictEqual(result.ref, null);
  assert.strictEqual(result.subject.kind, null);
  assert.strictEqual(result.subject.principal, null);
  assert.strictEqual(result.trust.level, null);
});

// -- v0.2 Exec Lifecycle Tests --

test('v0.2 exec with none identity provider succeeds (dry run)', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const result = await executeTask(manifest, { taskId: 'echo-identity', dryRun: true });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.dry_run, true);
  assert.ok(result.declared_identity);
  assert.ok(result.principal_used);
});

test('v0.2 exec includes declared identity fields', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const result = await executeTask(manifest, { taskId: 'echo-identity', dryRun: true });
  assert.strictEqual(result.declared_identity.provider, 'none');
  assert.strictEqual(result.declared_identity.subject.principal, 'agent://local/test-agent');
  assert.strictEqual(result.declared_identity.subject.kind, 'agent');
  assert.strictEqual(result.declared_identity.trust_level, 'supervised');
});

test('v0.2 exec includes trust info', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const result = await executeTask(manifest, { taskId: 'echo-identity', dryRun: true });
  assert.ok(result.trust);
  assert.strictEqual(result.trust.declared_level, 'supervised');
  assert.strictEqual(result.trust.effective_level, 'supervised');
});

test('v0.2 exec includes contract with trust fields', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const result = await executeTask(manifest, { taskId: 'echo-identity', dryRun: true });
  assert.strictEqual(result.contract.required_trust_level, 'restricted');
  assert.strictEqual(result.contract.trust_enforcement, 'advisory');
});

test('v0.2 exec with env-bearer identity and missing optional token succeeds', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const result = await executeTask(manifest, { taskId: 'env-token-task', dryRun: true });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.declared_identity.provider, 'env-bearer');
  assert.strictEqual(result.declared_identity.subject.kind, 'service');
});

test('v0.2 exec runs command and returns output', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const result = await executeTask(manifest, { taskId: 'echo-identity' });
  assert.strictEqual(result.ok, true);
  assert.ok(result.result.stdout.includes('hello-v2'));
  assert.strictEqual(result.result.exit_code, 0);
  assert.ok(result.execution_id);
});

test('v0.2 exec principal_used matches profile principal', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const result = await executeTask(manifest, { taskId: 'echo-identity', dryRun: true });
  assert.strictEqual(result.principal_used, 'agent://local/test-agent');
});

test('v0.2 exec with resolved identity includes session description', async () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const result = await executeTask(manifest, { taskId: 'echo-identity', dryRun: true });
  assert.ok(result.resolved_identity);
  assert.strictEqual(result.resolved_identity.provider, 'none');
  assert.deepStrictEqual(result.resolved_identity.credentials, {});
});

test('v0.2 exec resolves authorization proof, authorization, and evidence', async () => {
  const result = await executeTask(proofEnabledManifest, {
    taskId: 'proof-task',
    env: { ...process.env, TEST_AGENTCLI_JWT: unsignedJwt({ sub: 'agentcli-proof' }) }
  });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.authorization_proof.verified, true);
  assert.strictEqual(result.authorization.decision, 'permit');
  assert.strictEqual(result.evidence.provider, 'none');
  assert.strictEqual(result.evidence.attested, false);
});

// -- Conversion Tests --

test('convertManifestV1toV2 converts v0.1 to v0.2', async () => {
  const { convertManifestV1toV2 } = await import('../src/convert.js');
  const v1 = JSON.parse(readFileSync(new URL('../examples/identity-contract.json', import.meta.url), 'utf8'));
  const v2 = convertManifestV1toV2(v1);
  assert.strictEqual(v2.version, '0.2');
  assert.ok(Array.isArray(v2.identity_profiles));
  assert.ok(Array.isArray(v2.evidence_profiles));
  for (const wf of v2.workflows) {
    for (const task of wf.tasks) {
      if (task.identity && task.identity.subject) {
        assert.strictEqual(task.identity.subject.delegation_mode, 'none');
      }
    }
  }
});

test('convertManifestV1toV2 rejects non-v0.1 input', async () => {
  const { convertManifestV1toV2 } = await import('../src/convert.js');
  assert.throws(() => convertManifestV1toV2({ version: '0.2', workflows: [] }), /version 0\.1/);
});

test('convertManifestV1toV2 preserves workflow identity', async () => {
  const { convertManifestV1toV2 } = await import('../src/convert.js');
  const v1 = JSON.parse(readFileSync(new URL('../examples/identity-contract.json', import.meta.url), 'utf8'));
  const v2 = convertManifestV1toV2(v1);
  const wf = v2.workflows[0];
  assert.ok(wf.identity);
  assert.ok(wf.identity.subject);
  assert.strictEqual(wf.identity.subject.principal, 'deploy-bot@infra.example.com');
});

test('convertManifestV1toV2 creates authorization_proof_profile for oidc attestation', async () => {
  const { convertManifestV1toV2 } = await import('../src/convert.js');
  const v1 = JSON.parse(readFileSync(new URL('../examples/identity-contract.json', import.meta.url), 'utf8'));
  const v2 = convertManifestV1toV2(v1);
  assert.ok(Array.isArray(v2.authorization_proof_profiles));
  const jwtProfile = v2.authorization_proof_profiles.find(p => p.method === 'jwt');
  assert.ok(jwtProfile, 'Should create a jwt authorization_proof_profile for oidc attestation');
});

test('convertManifestV1toV2 rejects null input', async () => {
  const { convertManifestV1toV2 } = await import('../src/convert.js');
  assert.throws(() => convertManifestV1toV2(null), /version 0\.1/);
});

// -- Compilation Tests --

test('v0.2 standalone compilation preserves identity profiles', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToStandalone(manifest);
  assert.ok(compiled.identity_profiles);
  assert.strictEqual(compiled.identity_profiles.length, 2);
  assert.ok(compiled.capabilities.identity_declaration);
});

test('v0.2 standalone compilation preserves evidence profiles', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToStandalone(manifest);
  assert.ok(compiled.evidence_profiles);
  assert.strictEqual(compiled.evidence_profiles.length, 1);
  assert.ok(compiled.capabilities.evidence_generation);
});

test('v0.2 standalone compilation preserves authorization_proof_profiles', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToStandalone(manifest);
  assert.ok(compiled.authorization_proof_profiles);
  assert.strictEqual(compiled.authorization_proof_profiles.length, 1);
});

test('v0.2 standalone compiled tasks include identity ref', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToStandalone(manifest);
  const task = compiled.workflows[0].tasks.find(t => t.source.task_id === 'echo-identity');
  assert.ok(task);
  assert.strictEqual(task.identity.ref, 'local-agent');
  // Subject fields are null in compiled output -- profile lookup happens at execution time
  assert.ok(task.identity.subject);
});

test('v0.2 standalone compiled tasks include evidence ref', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToStandalone(manifest);
  const task = compiled.workflows[0].tasks.find(t => t.source.task_id === 'echo-identity');
  assert.ok(task);
  assert.strictEqual(task.evidence.ref, 'ssh-evidence');
});

test('v0.2 scheduler compilation includes identity flat fields', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs.find(j => j.source.task_id === 'echo-identity');
  assert.ok(job);
  assert.strictEqual(job.identity_ref, 'local-agent');
  assert.strictEqual(job.identity_subject_principal, 'agent://local/test-agent');
  assert.strictEqual(job.identity_subject_kind, 'agent');
  assert.strictEqual(job.identity_trust_level, 'supervised');
  assert.strictEqual(job.identity_delegation_mode, 'none');
});

test('v0.2 scheduler compilation includes evidence ref', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs.find(j => j.source.task_id === 'echo-identity');
  assert.ok(job);
  assert.strictEqual(job.evidence_ref, 'ssh-evidence');
});

test('v0.2 scheduler compilation includes contract trust fields', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs.find(j => j.source.task_id === 'echo-identity');
  assert.ok(job);
  assert.strictEqual(job.contract_required_trust_level, 'restricted');
  assert.strictEqual(job.contract_trust_enforcement, 'advisory');
});

test('v0.2 scheduler compilation preserves profile arrays', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToScheduler(manifest);
  assert.ok(compiled.identity_profiles);
  assert.strictEqual(compiled.identity_profiles.length, 2);
  assert.ok(compiled.authorization_proof_profiles);
  assert.ok(compiled.evidence_profiles);
});

test('v0.2 scheduler compilation env-token task includes correct identity fields', () => {
  const manifest = JSON.parse(readFileSync(new URL('../examples/identity-v2.json', import.meta.url), 'utf8'));
  const compiled = compileManifestToScheduler(manifest);
  const job = compiled.jobs.find(j => j.source.task_id === 'env-token-task');
  assert.ok(job);
  assert.strictEqual(job.identity_ref, 'env-token-agent');
  assert.strictEqual(job.identity_subject_principal, 'agent://local/env-service');
  assert.strictEqual(job.identity_trust_level, 'restricted');
});

test('v0.2 scheduler compilation includes resolved authorization and evidence declarations', () => {
  const compiled = compileManifestToScheduler(proofEnabledManifest);
  const job = compiled.jobs.find(candidate => candidate.source.task_id === 'proof-task');
  assert.ok(job);
  assert.deepStrictEqual(job.authorization_proof.claims, { subject: 'agentcli-proof' });
  assert.strictEqual(job.authorization_proof.verify.required, true);
  assert.deepStrictEqual(job.authorization.provider_config, { team: 'ops', task: 'proof-task' });
  assert.deepStrictEqual(job.authorization.request, { include: ['identity'] });
  assert.deepStrictEqual(job.evidence.payload.bind, ['command']);
  assert.strictEqual(job.evidence.verify.required, false);
});

test('applyManifestToScheduler returns authorization proof verification summaries', async () => {
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() {
      return [];
    },
    addJob(spec) {
      calls.push(spec);
      return { ok: true, job: spec };
    },
    updateJob() {
      throw new Error('should not update jobs');
    }
  };

  const result = await applyManifestToScheduler(applyProofManifest, {
    runner,
    env: { ...process.env, TEST_AGENTCLI_JWT: unsignedJwt({ sub: 'agentcli-proof' }) }
  });

  assert.strictEqual(result.ok, true);
  assert.ok(Array.isArray(result.authorization_proof_verifications));
  assert.strictEqual(result.authorization_proof_verifications.length, 1);
  assert.strictEqual(result.authorization_proof_verifications[0].source.task_id, 'verify-me');
  assert.strictEqual(result.authorization_proof_verifications[0].verification.verified, true);
  assert.ok(calls[0].authorization_proof_verification);
  assert.strictEqual(calls[0].authorization_proof_verification.verified, true);
});

test('applyManifestToScheduler rejects generated on_failure authorization when target lacks hook', async () => {
  const manifest = {
    version: '0.2',
    authorization_profiles: [{ id: 'authz', provider: 'none' }],
    workflows: [
      {
        id: 'apply-auth-failure',
        name: 'Apply Auth Failure',
        tasks: [
          {
            id: 'primary',
            name: 'Primary',
            target: { session_target: 'shell' },
            shell: { program: 'echo', args: ['primary'] },
            schedule: { cron: '0 * * * *' },
            on_failure: {
              shell: { program: 'echo', args: ['failure'] },
              authorization: { ref: 'authz' }
            }
          }
        ]
      }
    ]
  };

  await assert.rejects(
    () => applyManifestToScheduler(manifest, {
      runner: {
        invocation: { label: 'fake-scheduler' },
        listJobs() {
          return [];
        },
        addJob() {
          throw new Error('should not add jobs');
        },
        updateJob() {
          throw new Error('should not update jobs');
        }
      }
    }),
    /authorization_hook/
  );
});

test('applyManifestToScheduler proof fallback uses resolved task proof declaration', async () => {
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() {
      return [];
    },
    addJob(spec) {
      calls.push(spec);
      return { ok: true, job: spec };
    },
    updateJob() {
      throw new Error('should not update jobs');
    }
  };

  const result = await applyManifestToScheduler(applyProofOverrideManifest, {
    runner,
    env: { ...process.env, TEST_AGENTCLI_JWT: unsignedJwt({ sub: 'agentcli-proof' }) }
  });

  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.authorization_proof_verifications.length, 1);
  assert.strictEqual(result.authorization_proof_verifications[0].source.task_id, 'verify-override');
  assert.deepStrictEqual(calls[0].authorization_proof.claims, { subject: 'agentcli-proof' });
  assert.strictEqual(calls[0].authorization_proof_verification.verified, true);
});

test('applyManifestToScheduler proof fallback covers generated on_failure tasks', async () => {
  const calls = [];
  const runner = {
    invocation: { label: 'fake-scheduler' },
    listJobs() {
      return [];
    },
    addJob(spec) {
      calls.push(spec);
      return { ok: true, job: spec };
    },
    updateJob() {
      throw new Error('should not update jobs');
    }
  };

  const result = await applyManifestToScheduler(applyOnFailureProofManifest, {
    runner,
    env: { ...process.env, TEST_AGENTCLI_JWT: unsignedJwt({ sub: 'agentcli-proof' }) }
  });

  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.authorization_proof_verifications.length, 1);
  assert.strictEqual(result.authorization_proof_verifications[0].source.task_id, 'primary.failure');
  const failureSpec = calls.find(spec => spec.authorization_proof_ref === 'jwt-proof');
  assert.ok(failureSpec);
  assert.strictEqual(failureSpec.authorization_proof.ref, 'jwt-proof');
  assert.ok(failureSpec.authorization_proof_verification);
  assert.strictEqual(failureSpec.authorization_proof_verification.verified, true);
});
