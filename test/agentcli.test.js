import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { DatabaseSync } from 'node:sqlite';
import { compileManifestToStandalone as compileStandaloneFromIndex, MANIFEST_VERSION } from '../src/index.js';
import { validateManifest } from '../src/validate.js';
import { compileManifestToScheduler } from '../src/compiler/openclaw-scheduler.js';
import { compileManifestToStandalone } from '../src/compiler/standalone.js';
import { applyManifestToScheduler, resolveSchedulerInvocation } from '../src/apply.js';
import { runCli } from '../src/cli.js';
import { inspectSchedulerState } from '../src/inspect.js';
import { handleJsonRpcRequest } from '../src/jsonrpc.js';
import { getAgentcliPaths } from '../src/home.js';

function readExample(name) {
  return JSON.parse(readFileSync(new URL(`../examples/${name}`, import.meta.url), 'utf8'));
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

test('invalid enabled type fails validation', () => {
  const bad = structuredClone(exampleManifest);
  bad.workflows[0].tasks[0].enabled = 'false';

  const result = validateManifest(bad);
  assert.equal(result.ok, false);
  assert.match(result.errors[0].message, /must be a boolean/);
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

test('cli init scaffolds a user home with a starter manifest', async (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  t.after(() => rmSync(homeRoot, { recursive: true, force: true }));

  const output = JSON.parse(await runCli(['init'], {
    env: {
      ...process.env,
      AGENTCLI_HOME: homeRoot
    }
  }));

  assert.equal(output.ok, true);
  const paths = getAgentcliPaths({ env: { ...process.env, AGENTCLI_HOME: homeRoot } });
  assert.equal(existsSync(paths.readme), true);
  assert.equal(existsSync(paths.sampleManifest), true);
  assert.ok(output.created.includes(paths.sampleManifest));
});

test('load-by-name flow resolves manifests from AGENTCLI_HOME/manifests', async (t) => {
  const homeRoot = mkdtempSync(join(tmpdir(), 'agentcli-home-'));
  t.after(() => rmSync(homeRoot, { recursive: true, force: true }));

  await runCli(['init'], {
    env: {
      ...process.env,
      AGENTCLI_HOME: homeRoot
    }
  });

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
  assert.equal(MANIFEST_VERSION, '0.1');
  const compiled = compileStandaloneFromIndex(exampleManifest);
  assert.equal(compiled.target, 'standalone');
});

test('cli schema returns json', async () => {
  const output = JSON.parse(await runCli(['schema', 'task']));
  assert.equal(output.ok, true);
  assert.equal(output.schema.type, 'object');
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

test('applyManifestToScheduler plans and executes scheduler upserts', () => {
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

  const result = applyManifestToScheduler(exampleManifest, { runner });
  assert.equal(result.ok, true);
  assert.equal(result.job_count, 2);
  assert.deepEqual(result.actions.map(action => action.action), ['updated', 'created']);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].action, 'update');
  assert.equal(calls[1].action, 'create');
  assert.equal('run_timeout_ms' in calls[0].spec, false);
  assert.equal(calls[0].spec.enabled, true);
});

test('applyManifestToScheduler converts enabled flags to booleans for scheduler cli calls', () => {
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

  const result = applyManifestToScheduler(manifest, { runner });
  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].enabled, false);
});

test('cli apply supports dry-run without invoking scheduler writes', () => {
  const compiled = compileManifestToScheduler(exampleManifest);
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

  const result = applyManifestToScheduler(exampleManifest, { dryRun: true, runner });
  assert.equal(result.ok, true);
  assert.equal(result.dry_run, true);
  assert.equal(result.job_count, 2);
  assert.deepEqual(result.actions.map(action => action.action), ['created', 'created']);
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

test('inspect applies field masks and sanitization', (t) => {
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

  const result = inspectSchedulerState({
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
