import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join, basename, extname } from 'node:path';
import { validateManifest } from './validate.js';
import { getAgentcliPaths } from './home.js';

function registryDir({ env = process.env } = {}) {
  const paths = getAgentcliPaths({ env });
  if (existsSync(paths.registry) && lstatSync(paths.registry).isSymbolicLink()) {
    throw Object.assign(
      new Error('Refusing to use a registry directory that is a symbolic link'),
      { code: 'invalid_argument' }
    );
  }
  mkdirSync(paths.registry, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') chmodSync(paths.registry, 0o700);
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
      if (lstatSync(filePath).isSymbolicLink()) {
        return { name, workflows: [], parse_error: true, symlink_refused: true };
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
  if (overwritten && lstatSync(filePath).isSymbolicLink()) {
    throw Object.assign(
      new Error(`Refusing to overwrite symbolic-link registry entry: "${entryName}"`),
      { code: 'invalid_argument' }
    );
  }

  let descriptor;
  try {
    descriptor = openSync(
      filePath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_TRUNC |
        (fsConstants.O_NOFOLLOW || 0),
      0o600
    );
    writeFileSync(descriptor, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  if (process.platform !== 'win32') chmodSync(filePath, 0o600);

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
  if (lstatSync(filePath).isSymbolicLink()) {
    throw Object.assign(
      new Error(`Refusing to read symbolic-link registry entry: "${name}"`),
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
