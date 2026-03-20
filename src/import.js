import { existsSync, readFileSync } from 'node:fs';
import { join, basename } from 'node:path';
import { addToRegistry } from './registry.js';

const MANIFEST_FILENAME = 'agentcli.json';

function resolveManifestFromDir(dirPath) {
  const direct = join(dirPath, MANIFEST_FILENAME);
  if (existsSync(direct)) {
    return { path: direct, source: 'agentcli.json' };
  }

  const pkgPath = join(dirPath, 'package.json');
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    if (typeof pkg.agentcli === 'string') {
      const refPath = join(dirPath, pkg.agentcli);
      if (existsSync(refPath)) {
        return { path: refPath, source: `package.json "agentcli" field (${pkg.agentcli})` };
      }
      throw Object.assign(
        new Error(`package.json "agentcli" field points to "${pkg.agentcli}" but file not found at ${refPath}`),
        { code: 'invalid_argument' }
      );
    }
  }

  throw Object.assign(
    new Error(
      `No agentcli manifest found in "${dirPath}". ` +
      `Expected ${MANIFEST_FILENAME} or a package.json with an "agentcli" field.`
    ),
    { code: 'invalid_argument' }
  );
}

export function importManifest(source, { name, env, cwd = process.cwd() } = {}) {
  const resolvedSource = source.startsWith('/') ? source : join(cwd, source);

  if (!existsSync(resolvedSource)) {
    throw Object.assign(
      new Error(`Path not found: ${resolvedSource}`),
      { code: 'invalid_argument' }
    );
  }

  const { path: manifestPath, source: discoverySource } = resolveManifestFromDir(resolvedSource);
  const derivedName = name || basename(resolvedSource);

  const result = addToRegistry(manifestPath, { name: derivedName, env });

  return {
    ...result,
    imported_from: resolvedSource,
    discovery: discoverySource,
  };
}
