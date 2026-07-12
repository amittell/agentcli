import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

function invalidManagedPath(message) {
  return Object.assign(new Error(message), { code: 'invalid_argument' });
}

function lstatIfPresent(path) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function assertManagedPath(path, expectedType) {
  const state = lstatIfPresent(path);
  if (!state) return null;
  if (state.isSymbolicLink()) {
    throw invalidManagedPath(`Refusing to use symbolic-link ${expectedType}: ${path}`);
  }
  const valid = expectedType === 'directory' ? state.isDirectory() : state.isFile();
  if (!valid) {
    throw invalidManagedPath(`Expected ${expectedType} path but found another file type: ${path}`);
  }
  return state;
}

export function ensurePrivateDirectory(directoryPath, { mode = 0o700 } = {}) {
  const resolvedDirectory = resolve(directoryPath);
  assertManagedPath(resolvedDirectory, 'directory');
  mkdirSync(resolvedDirectory, { recursive: true, mode });
  assertManagedPath(resolvedDirectory, 'directory');

  if (process.platform !== 'win32') {
    let descriptor;
    try {
      descriptor = openSync(
        resolvedDirectory,
        fsConstants.O_RDONLY |
          (fsConstants.O_DIRECTORY || 0) |
          (fsConstants.O_NOFOLLOW || 0)
      );
      if (!fstatSync(descriptor).isDirectory()) {
        throw invalidManagedPath(`Expected directory path but found another file type: ${resolvedDirectory}`);
      }
      fchmodSync(descriptor, mode);
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
    }
  }

  return resolvedDirectory;
}

export function assertRegularFileDescriptor(
  descriptor,
  filePath,
  { code = 'invalid_argument' } = {}
) {
  const state = fstatSync(descriptor);
  if (!state.isFile()) {
    throw Object.assign(
      new Error(`Refusing to use a non-regular file: ${filePath}`),
      { code }
    );
  }
  return state;
}

function tightenPrivateFile(filePath, mode) {
  assertManagedPath(filePath, 'regular file');
  let descriptor;
  try {
    descriptor = openSync(
      filePath,
      fsConstants.O_RDONLY |
        (fsConstants.O_NONBLOCK || 0) |
        (fsConstants.O_NOFOLLOW || 0)
    );
    assertRegularFileDescriptor(descriptor, filePath);
    if (process.platform !== 'win32') fchmodSync(descriptor, mode);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function writePrivateFile(filePath, contents, { force, mode = 0o600 }) {
  const existing = assertManagedPath(filePath, 'regular file');
  if (existing && !force) {
    tightenPrivateFile(filePath, mode);
    return false;
  }

  let descriptor;
  try {
    const creationMode = force ? fsConstants.O_TRUNC : fsConstants.O_EXCL;
    descriptor = openSync(
      filePath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        creationMode |
        (fsConstants.O_NONBLOCK || 0) |
        (fsConstants.O_NOFOLLOW || 0),
      mode
    );
    assertRegularFileDescriptor(descriptor, filePath);
    if (process.platform !== 'win32') fchmodSync(descriptor, mode);
    writeFileSync(descriptor, contents, 'utf8');
    return true;
  } catch (error) {
    if (!force && error?.code === 'EEXIST') {
      if (descriptor !== undefined) {
        closeSync(descriptor);
        descriptor = undefined;
      }
      tightenPrivateFile(filePath, mode);
      return false;
    }
    throw error;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

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
  const managedDirectories = [paths.root, paths.manifests, paths.output, paths.state, paths.registry];
  const managedFiles = [paths.readme, paths.sampleManifest];

  for (const directory of managedDirectories) assertManagedPath(directory, 'directory');
  for (const file of managedFiles) assertManagedPath(file, 'regular file');
  for (const directory of managedDirectories) ensurePrivateDirectory(directory);

  const created = [];

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
  if (writePrivateFile(paths.readme, readme, { force })) {
    created.push(paths.readme);
  }

  if (writePrivateFile(paths.sampleManifest, `${readBundledSample().trim()}\n`, { force })) {
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
