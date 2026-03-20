import { existsSync, readFileSync, writeFileSync, readdirSync, unlinkSync, mkdirSync } from 'node:fs';
import { join, basename, extname } from 'node:path';
import { validateManifest } from './validate.js';
import { getAgentcliPaths } from './home.js';

function registryDir({ env = process.env } = {}) {
  const paths = getAgentcliPaths({ env });
  mkdirSync(paths.registry, { recursive: true });
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

    manifest = JSON.parse(readFileSync(resolvedPath, 'utf8'));
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

  writeFileSync(filePath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');

  return { name: entryName, path: filePath, overwritten: false };
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

  return JSON.parse(readFileSync(filePath, 'utf8'));
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
