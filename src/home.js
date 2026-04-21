import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

function expandLeadingTilde(input, homeDir) {
  if (typeof input !== 'string') return input;
  if (input === '~') return homeDir;
  if (input.startsWith('~/')) return join(homeDir, input.slice(2));
  return input;
}

export function resolveAgentcliHome({ env = process.env, homeDir = homedir() } = {}) {
  return resolve(expandLeadingTilde(env.AGENTCLI_HOME || '~/.agentcli', homeDir));
}

export function getAgentcliPaths({ env = process.env, homeDir = homedir() } = {}) {
  const root = resolveAgentcliHome({ env, homeDir });
  return {
    root,
    manifests: join(root, 'manifests'),
    output: join(root, 'output'),
    state: join(root, 'state'),
    registry: join(root, 'registry'),
    audit: join(root, 'state', 'audit.ndjson'),
    approvals: join(root, 'state', 'approvals.ndjson'),
    allowed_signers: join(root, 'state', 'allowed_signers'),
    skill_path: join(root, 'skills', 'manifest-authoring', 'SKILL.md'),
    readme: join(root, 'README.md'),
    sampleManifest: join(root, 'manifests', 'bot-health.json')
  };
}

function readBundledSample() {
  return readFileSync(new URL('../examples/public-bot-health.json', import.meta.url), 'utf8');
}

export function ensureAgentcliHome({ env = process.env, homeDir = homedir(), force = false } = {}) {
  const paths = getAgentcliPaths({ env, homeDir });
  for (const dir of [paths.root, paths.manifests, paths.output, paths.state, paths.registry]) {
    mkdirSync(dir, { recursive: true });
  }

  const created = [];

  if (force || !existsSync(paths.readme)) {
    const readme = `# agentcli home

This directory holds local manifests and output for agentcli.

Directories:
- manifests: your workflow manifests
- output: compile output written by you
- state: optional local state files

Typical flow:
1. Put a manifest in manifests/
2. Run: agentcli validate <name>
3. Run: agentcli compile <name> --target openclaw-scheduler --explain
4. Run: agentcli apply <name> --db ~/.openclaw/scheduler/scheduler.db --scheduler-prefix ~/.openclaw/scheduler --dry-run
`;
    writeFileSync(paths.readme, readme, 'utf8');
    created.push(paths.readme);
  }

  if (force || !existsSync(paths.sampleManifest)) {
    writeFileSync(paths.sampleManifest, `${readBundledSample().trim()}\n`, 'utf8');
    created.push(paths.sampleManifest);
  }

  return {
    ok: true,
    paths,
    created
  };
}

export function resolveManifestCandidate(input, { cwd = process.cwd(), env = process.env, homeDir = homedir() } = {}) {
  if (!input || input === '-') return null;
  const expanded = resolve(cwd, expandLeadingTilde(input, homeDir));
  if (existsSync(expanded)) return expanded;

  const homePaths = getAgentcliPaths({ env, homeDir });
  const homeCandidates = [
    join(homePaths.manifests, input),
    join(homePaths.manifests, `${input}.json`)
  ];

  for (const candidate of homeCandidates) {
    if (existsSync(candidate)) return candidate;
  }

  return null;
}
