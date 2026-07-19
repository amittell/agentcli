#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixtureRoot = mkdtempSync(join(tmpdir(), 'agentcli-package-'));
const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    env: options.env ?? process.env,
    encoding: 'utf8',
    stdio: options.stdio ?? ['ignore', 'pipe', 'pipe'],
  });
}

try {
  const packResult = JSON.parse(run(npmCommand, [
    'pack',
    '--json',
    '--pack-destination', fixtureRoot,
  ]));
  if (!Array.isArray(packResult) || typeof packResult[0]?.filename !== 'string') {
    throw new Error('npm pack did not return an artifact filename');
  }

  const tarball = join(fixtureRoot, packResult[0].filename);
  run('tar', ['-xzf', tarball], { cwd: fixtureRoot });
  const packageRoot = join(fixtureRoot, 'package');
  const requiredFiles = [
    'bin/agentcli.js',
    'fixtures/handoff-v4/conformance.json',
    'scripts/verify-package.mjs',
    'src/handoff/index.js',
    'src/handoff/schema-v4.js',
    'src/handoff/v4.js',
    'src/authorization-proof/jwt.js',
    'src/authorization-proof/key-identity.js',
    'src/authorization-proof/detached-signature.js',
    'src/authorization-proof/certificate.js',
  ];
  for (const relativePath of requiredFiles) {
    if (!existsSync(join(packageRoot, relativePath))) {
      throw new Error(`packed artifact is missing ${relativePath}`);
    }
  }

  const forbiddenPaths = [
    '.env',
    '.git',
    '.github',
    '.coordination',
    'test',
  ];
  for (const relativePath of forbiddenPaths) {
    if (existsSync(join(packageRoot, relativePath))) {
      throw new Error(`packed artifact contains forbidden path ${relativePath}`);
    }
  }

  const packedPackage = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
  const sourcePackage = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
  if (packedPackage.version !== sourcePackage.version) {
    throw new Error('packed package version does not match source package version');
  }

  const fixture = JSON.parse(readFileSync(
    join(packageRoot, 'fixtures/handoff-v4/conformance.json'),
    'utf8',
  ));
  if (fixture.fixture_version !== 1
    || !fixture.manifest?.workflows?.[0]?.tasks?.length
    || typeof fixture.expected?.artifact_digest !== 'string'
    || !Array.isArray(fixture.negative_artifact_cases)
    || fixture.negative_artifact_cases.length === 0) {
    throw new Error('packed handoff v4 conformance fixture is incomplete');
  }

  const handoff = await import(pathToFileURL(join(packageRoot, 'src/handoff/index.js')).href);
  for (const exportName of [
    'buildSchedulerHandoffV4Artifact',
    'rebindSchedulerHandoffV4Job',
    'validateSchedulerHandoffV4Artifact',
  ]) {
    if (typeof handoff[exportName] !== 'function') {
      throw new Error(`packed handoff module is missing ${exportName}`);
    }
  }
  if (handoff.HANDOFF_V4_JSON_SCHEMA?.properties?.handoff_version?.const !== 4) {
    throw new Error('packed handoff module is missing the v4 artifact schema');
  }

  const schemaOutput = JSON.parse(run(process.execPath, [
    'bin/agentcli.js',
    'schema',
    'handoff-v4',
    '--json',
  ], { cwd: packageRoot }));
  if (schemaOutput.ok !== true
    || schemaOutput.schema_format !== 'json-schema-draft-2020-12'
    || schemaOutput.schema?.properties?.handoff_version?.const !== 4) {
    throw new Error('packed CLI does not expose the handoff v4 artifact schema');
  }

  const help = run(process.execPath, ['bin/agentcli.js', 'help'], { cwd: packageRoot });
  if (!help.includes('agentcli')) {
    throw new Error('packed CLI help output is invalid');
  }

  process.stdout.write(`Verified @amittell/agentcli ${packedPackage.version} package contract\n`);
} finally {
  rmSync(fixtureRoot, { recursive: true, force: true });
}
