import { appendFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';

export function generateExecutionId(workflowId, taskId, timestamp) {
  return createHash('sha256')
    .update(`${workflowId}:${taskId}:${timestamp}`)
    .digest('hex')
    .slice(0, 32);
}

export function writeAuditRecord(record, { auditPath }) {
  mkdirSync(dirname(auditPath), { recursive: true });
  appendFileSync(auditPath, JSON.stringify(record) + '\n', 'utf8');
}

export function readAuditLog({ auditPath, limit } = {}) {
  if (!auditPath || !existsSync(auditPath)) return [];
  const content = readFileSync(auditPath, 'utf8').trim();
  if (!content) return [];
  const records = content.split('\n').map(line => JSON.parse(line));
  if (limit) return records.slice(-limit);
  return records;
}
