import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { isatty } from 'node:tty';
import { assertRegularFileDescriptor, resolveManifestCandidate } from './home.js';

function looksLikeJsonLiteral(input) {
  if (typeof input !== 'string') return false;
  const trimmed = input.trim();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

export async function loadJsonInput(
  input,
  { cwd = process.cwd(), env = process.env, stdin = process.stdin } = {}
) {
  if (!input) {
    throw Object.assign(
      new Error('Missing input. Pass a file path or JSON string.'),
      { code: 'invalid_argument' }
    );
  }
  const resolvedPath = resolveManifestCandidate(input, { cwd, env });
  if (input === '-' && (stdin?.isTTY ?? isatty(0))) {
    throw Object.assign(
      new Error('stdin is a TTY. Pipe JSON data or pass a file path.'),
      { code: 'invalid_argument' }
    );
  }
  const raw = input === '-'
    ? await readStdinText(stdin)
    : resolvedPath
      ? readFileSync(resolvedPath, 'utf8')
      : looksLikeJsonLiteral(input)
        ? input
        : (() => {
            throw Object.assign(
              new Error(`Input not found: ${input}. Pass a file path, a manifest name from AGENTCLI_HOME/manifests, or a JSON string.`),
              { code: 'invalid_argument' }
            );
          })();
  try {
    return JSON.parse(raw);
  } catch (err) {
    const source = input === '-' ? 'stdin' : resolvedPath || input;
    throw Object.assign(
      new Error(`Invalid JSON from ${source}: ${err.message}`),
      { code: 'parse_error' }
    );
  }
}

async function readStdinText(stream) {
  if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') {
    throw Object.assign(
      new Error('stdin is not readable. Pipe JSON data or pass a file path.'),
      { code: 'invalid_argument' }
    );
  }

  let raw = '';
  for await (const chunk of stream) {
    raw += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
  }
  return raw;
}

function invalidOutput(message) {
  return Object.assign(new Error(message), { code: 'invalid_argument' });
}

function isWithin(basePath, candidatePath) {
  const pathFromBase = relative(basePath, candidatePath);
  return pathFromBase === '' || (
    pathFromBase !== '..' &&
    !pathFromBase.startsWith(`..${sep}`) &&
    !isAbsolute(pathFromBase)
  );
}

function nearestExistingAncestor(candidatePath) {
  let current = candidatePath;
  while (!existsSync(current)) {
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
  return current;
}

export function resolveSafeOutputPath(outputPath, cwd = process.cwd()) {
  if (!outputPath) {
    throw invalidOutput('Missing output path.');
  }

  const baseDir = resolve(cwd);
  if (!existsSync(baseDir)) {
    throw invalidOutput(`Current working directory does not exist: ${baseDir}`);
  }
  const baseRealPath = realpathSync(baseDir);
  const resolvedPath = resolve(baseDir, outputPath);
  const relativePath = relative(baseDir, resolvedPath);

  if (relativePath === '' || relativePath === '.') {
    throw invalidOutput('Output path must point to a file inside the current working directory.');
  }

  if (!isWithin(baseDir, resolvedPath)) {
    throw invalidOutput('Refusing to write outside the current working directory.');
  }

  const existingAncestor = nearestExistingAncestor(dirname(resolvedPath));
  if (!existingAncestor) {
    throw invalidOutput('Unable to resolve an existing parent directory for the output path.');
  }
  const realAncestor = realpathSync(existingAncestor);
  if (!isWithin(baseRealPath, realAncestor)) {
    throw invalidOutput('Refusing to write through a symlink outside the current working directory.');
  }

  if (existsSync(resolvedPath)) {
    const outputState = lstatSync(resolvedPath);
    if (outputState.isSymbolicLink()) {
      throw invalidOutput('Refusing to overwrite a symbolic link.');
    }
    if (!outputState.isFile()) {
      throw invalidOutput('Refusing to overwrite a non-regular file.');
    }
    if (!isWithin(baseRealPath, realpathSync(resolvedPath))) {
      throw invalidOutput('Refusing to overwrite a file outside the current working directory.');
    }
  }

  return resolvedPath;
}

export function writeJsonOutput(
  outputPath,
  payload,
  { cwd = process.cwd(), overwrite = true } = {}
) {
  if (typeof overwrite !== 'boolean') {
    throw invalidOutput('Output overwrite option must be a boolean.');
  }
  const serialized = `${JSON.stringify(payload, null, 2)}\n`;
  let resolvedPath = resolveSafeOutputPath(outputPath, cwd);
  mkdirSync(dirname(resolvedPath), { recursive: true, mode: 0o700 });
  resolvedPath = resolveSafeOutputPath(outputPath, cwd);

  let fd;
  try {
    fd = openSync(
      resolvedPath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        (overwrite ? fsConstants.O_TRUNC : fsConstants.O_EXCL) |
        (fsConstants.O_NONBLOCK || 0) |
        (fsConstants.O_NOFOLLOW || 0),
      0o600
    );
    assertRegularFileDescriptor(fd, resolvedPath);
    if (process.platform !== 'win32') fchmodSync(fd, 0o600);
    writeFileSync(fd, serialized, 'utf8');
  } catch (err) {
    if (err?.code === 'ELOOP') {
      throw invalidOutput('Refusing to overwrite a symbolic link.');
    }
    throw err;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  return resolvedPath;
}
