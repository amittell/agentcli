import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join, basename, extname } from 'node:path';
import { validateManifest } from './validate.js';
import {
  assertRegularFileDescriptor,
  ensurePrivateDirectory,
  getAgentcliPaths,
} from './home.js';

function registryDir({ env = process.env } = {}) {
  const paths = getAgentcliPaths({ env });
  ensurePrivateDirectory(paths.registry);
  return paths.registry;
}

function entryPath(dir, name) {
  const safeName = name.replace(/\.json$/, '');
  if (!safeName || /[/\\]/.test(safeName)) {
    throw Object.assign(
      new Error(`Invalid registry entry name: "${name}"`),
      { code: 'invalid_argument' }
    );
  }
  return join(dir, `${safeName}.json`);
}

export function listRegistry({ env } = {}) {
  const dir = registryDir({ env });
  const files = readdirSync(dir).filter(f => f.endsWith('.json')).sort();

  return files.map(file => {
    const name = file.replace(/\.json$/, '');
    const filePath = join(dir, file);
    try {
      const entryState = lstatSync(filePath);
      if (entryState.isSymbolicLink()) {
        return { name, workflows: [], symlink_refused: true };
      }
      if (!entryState.isFile()) {
        return { name, workflows: [], invalid_type_refused: true };
      }
      const manifest = JSON.parse(readFileSync(filePath, 'utf8'));
      const workflows = (manifest.workflows || []).map(w => ({
        id: w.id,
        name: w.name,
        task_count: (w.tasks || []).length,
      }));
      return { name, workflows };
    } catch (_e) {
      return { name, workflows: [], parse_error: true };
    }
  });
}

export function addToRegistry(manifestOrPath, { name, env, cwd = process.cwd() } = {}) {
  let manifest;
  let derivedName;

  if (typeof manifestOrPath === 'string') {
    const resolvedPath = manifestOrPath.startsWith('/')
      ? manifestOrPath
      : join(cwd, manifestOrPath);

    if (!existsSync(resolvedPath)) {
      throw Object.assign(
        new Error(`File not found: ${resolvedPath}`),
        { code: 'invalid_argument' }
      );
    }

    try {
      manifest = JSON.parse(readFileSync(resolvedPath, 'utf8'));
    } catch (error) {
      throw Object.assign(
        new Error(`Invalid JSON in registry source ${resolvedPath}: ${error.message}`),
        { code: 'parse_error' }
      );
    }
    derivedName = basename(resolvedPath, extname(resolvedPath));
  } else {
    manifest = manifestOrPath;
    derivedName = manifest.workflows?.[0]?.id || 'unnamed';
  }

  const validation = validateManifest(manifest);
  if (!validation.ok) {
    throw Object.assign(
      new Error(`Manifest validation failed: ${validation.errors.map(e => e.message).join('; ')}`),
      { code: 'validation_error', validation }
    );
  }

  const entryName = name || derivedName;
  const dir = registryDir({ env });
  const filePath = entryPath(dir, entryName);
  const overwritten = existsSync(filePath);
  if (overwritten) {
    const entryState = lstatSync(filePath);
    if (entryState.isSymbolicLink()) {
      throw Object.assign(
        new Error(`Refusing to overwrite symbolic-link registry entry: "${entryName}"`),
        { code: 'invalid_argument' }
      );
    }
    if (!entryState.isFile()) {
      throw Object.assign(
        new Error(`Refusing to overwrite non-regular registry entry: "${entryName}"`),
        { code: 'invalid_argument' }
      );
    }
  }

  let descriptor;
  try {
    descriptor = openSync(
      filePath,
        fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_TRUNC |
        (fsConstants.O_NONBLOCK || 0) |
        (fsConstants.O_NOFOLLOW || 0),
      0o600
    );
    assertRegularFileDescriptor(descriptor, filePath);
    if (process.platform !== 'win32') fchmodSync(descriptor, 0o600);
    writeFileSync(descriptor, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  return { name: entryName, path: filePath, overwritten };
}

export function showRegistryEntry(name, { env } = {}) {
  const dir = registryDir({ env });
  const filePath = entryPath(dir, name);

  if (!existsSync(filePath)) {
    throw Object.assign(
      new Error(`Registry entry not found: "${name}"`),
      { code: 'invalid_argument' }
    );
  }
  const entryState = lstatSync(filePath);
  if (entryState.isSymbolicLink()) {
    throw Object.assign(
      new Error(`Refusing to read symbolic-link registry entry: "${name}"`),
      { code: 'invalid_argument' }
    );
  }
  if (!entryState.isFile()) {
    throw Object.assign(
      new Error(`Refusing to read non-regular registry entry: "${name}"`),
      { code: 'invalid_argument' }
    );
  }

  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw Object.assign(
      new Error(`Invalid JSON in registry entry "${name}": ${error.message}`),
      { code: 'parse_error' }
    );
  }
}

export function removeFromRegistry(name, { env } = {}) {
  const dir = registryDir({ env });
  const filePath = entryPath(dir, name);

  if (!existsSync(filePath)) {
    throw Object.assign(
      new Error(`Registry entry not found: "${name}"`),
      { code: 'invalid_argument' }
    );
  }

  unlinkSync(filePath);
  return { name, removed: true };
}
