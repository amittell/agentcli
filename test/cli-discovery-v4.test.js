import test from 'node:test';
import assert from 'node:assert/strict';

import { runCli } from '../src/cli.js';
import { listInspectableEntities } from '../src/inspect.js';

test('JSON help advertises every inspect entity from the runtime registry', async () => {
  const entities = listInspectableEntities();
  const result = JSON.parse(await runCli(['--json']));

  assert.equal(result.ok, true);
  assert.equal(result.usage.includes(`inspect <${entities.join('|')}>`), true);
});

test('command discovery exposes every inspect entity as structured metadata', async () => {
  const entities = listInspectableEntities();
  const result = JSON.parse(await runCli(['describe', 'commands', '--json']));
  const inspect = result.description.items.find(item => item.command === 'inspect');

  assert.ok(inspect);
  assert.deepEqual(inspect.entities, entities);
  assert.equal(inspect.usage.startsWith(`inspect <${entities.join('|')}>`), true);
});
