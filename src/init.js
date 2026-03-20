import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { validateManifest } from './validate.js';

const DEFAULT_WORKFLOW_ID = 'default';
const DEFAULT_TASK_ID = 'run';

function toolExistsOnPath(program) {
  const result = spawnSync('which', [program], {
    encoding: 'utf8',
    timeout: 5000,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return result.status === 0;
}

export function createManifestScaffold({
  tool,
  workflowId = DEFAULT_WORKFLOW_ID,
  workflowName,
  taskId = DEFAULT_TASK_ID,
  taskName,
} = {}) {
  const program = tool || 'echo';
  const args = tool ? [] : ['hello from agentcli'];

  const manifest = {
    version: '0.1',
    workflows: [
      {
        id: workflowId,
        name: workflowName || workflowId,
        tasks: [
          {
            id: taskId,
            name: taskName || taskId,
            target: { session_target: 'shell' },
            shell: { program, args },
            schedule: { cron: '0 * * * *' },
          },
        ],
      },
    ],
  };

  const validation = validateManifest(manifest);
  if (!validation.ok) {
    throw Object.assign(
      new Error(`Generated manifest failed validation: ${validation.errors.map(e => e.message).join('; ')}`),
      { code: 'internal_error', validation }
    );
  }

  const warnings = [];

  if (tool && !toolExistsOnPath(tool)) {
    warnings.push(`"${tool}" was not found on PATH; the manifest is valid but exec will fail until the tool is installed`);
  }

  return { manifest, warnings };
}

export function writeManifest(manifest, { output, cwd = process.cwd() } = {}) {
  const filePath = output || join(cwd, 'agentcli.json');

  if (existsSync(filePath)) {
    throw Object.assign(
      new Error(`File already exists: ${filePath}. Use --output to specify a different path or remove the existing file.`),
      { code: 'invalid_argument' }
    );
  }

  writeFileSync(filePath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  return filePath;
}
