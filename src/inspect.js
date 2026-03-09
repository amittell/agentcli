import { existsSync } from 'fs';
import { DatabaseSync } from 'node:sqlite';
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

export function inspectSchedulerState({
  dbPath,
  entity = 'jobs',
  limit = 20,
  fields = null,
  sanitize = 'none'
}) {
  if (!dbPath) {
    throw new Error('Missing scheduler database path. Pass --db or set AGENTCLI_SCHEDULER_DB.');
  }
  if (!existsSync(dbPath)) {
    throw new Error(`Scheduler database not found: ${dbPath}`);
  }

  const target = INSPECT_ENTITIES[entity];
  if (!target) {
    throw new Error(`Unsupported inspect entity: ${entity}`);
  }

  const db = new DatabaseSync(dbPath);
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
