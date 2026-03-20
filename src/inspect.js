import { existsSync } from 'node:fs';
import { applyFieldMask } from './fields.js';
import { sanitizeForAgent } from './sanitize.js';

const INSPECT_ENTITIES = {
  jobs: {
    table: 'jobs',
    orderBy: 'created_at DESC'
  },
  runs: {
    table: 'runs',
    orderBy: 'started_at DESC'
  },
  queue: {
    table: 'job_dispatch_queue',
    orderBy: 'created_at DESC'
  },
  approvals: {
    table: 'approvals',
    orderBy: 'requested_at DESC'
  }
};

function integerFlag(value, fallback) {
  if (value == null) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid integer value: ${value}`);
  }
  return parsed;
}

async function openDatabase(dbPath) {
  try {
    const { DatabaseSync } = await import('node:sqlite');
    return new DatabaseSync(dbPath);
  } catch {
    throw new Error(
      'node:sqlite is not available. The inspect command requires Node 23.4.0+ or Node 22.x with --experimental-sqlite.'
    );
  }
}

export async function inspectSchedulerState({
  dbPath,
  entity = 'jobs',
  limit = 20,
  fields = null,
  sanitize = 'none'
}) {
  if (!dbPath) {
    throw Object.assign(
      new Error('Missing scheduler database path. Pass --db or set AGENTCLI_SCHEDULER_DB.'),
      { code: 'invalid_argument' }
    );
  }
  if (!existsSync(dbPath)) {
    throw Object.assign(
      new Error(`Scheduler database not found: ${dbPath}`),
      { code: 'invalid_argument' }
    );
  }

  const target = INSPECT_ENTITIES[entity];
  if (!target) {
    throw Object.assign(
      new Error(`Unsupported inspect entity: ${entity}`),
      { code: 'invalid_argument' }
    );
  }

  const db = await openDatabase(dbPath);
  try {
    const rows = db.prepare(
      `SELECT * FROM ${target.table} ORDER BY ${target.orderBy} LIMIT ?`
    ).all(integerFlag(limit, 20));

    const items = rows.map(row => {
      const masked = applyFieldMask(row, fields);
      return sanitizeForAgent(masked, sanitize);
    });

    return {
      ok: true,
      target: 'openclaw-scheduler',
      entity,
      count: items.length,
      items
    };
  } finally {
    db.close();
  }
}

export function listInspectableEntities() {
  return Object.keys(INSPECT_ENTITIES);
}
