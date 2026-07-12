import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  writeFileSync,
} from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname } from 'node:path';
import process from 'node:process';
import { assertRegularFileDescriptor, ensurePrivateDirectory } from './home.js';

export function generateExecutionId(_workflowId, _taskId, _timestamp) {
  return randomUUID().replaceAll('-', '');
}

export function writeAuditRecord(record, { auditPath }) {
  const auditDirectory = dirname(auditPath);
  ensurePrivateDirectory(auditDirectory);
  let descriptor;
  try {
    descriptor = openSync(
      auditPath,
      fsConstants.O_RDWR |
        fsConstants.O_APPEND |
        fsConstants.O_CREAT |
        (fsConstants.O_NONBLOCK || 0) |
        (fsConstants.O_NOFOLLOW || 0),
      0o600
    );
    const auditState = assertRegularFileDescriptor(descriptor, auditPath);
    if (process.platform !== 'win32') fchmodSync(descriptor, 0o600);
    let separator = '';
    const existingSize = auditState.size;
    if (existingSize > 0) {
      const finalByte = Buffer.allocUnsafe(1);
      readSync(descriptor, finalByte, 0, 1, existingSize - 1);
      if (finalByte[0] !== 0x0A) separator = '\n';
    }
    writeFileSync(descriptor, separator + JSON.stringify(record) + '\n', 'utf8');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function readAuditLog({ auditPath, limit, onMalformed } = {}) {
  if (!auditPath || !existsSync(auditPath)) return [];
  const auditState = lstatSync(auditPath);
  if (auditState.isSymbolicLink() || !auditState.isFile()) {
    throw Object.assign(new Error(`Refusing to read a non-regular audit file: ${auditPath}`), {
      code: 'invalid_argument',
    });
  }
  const content = readFileSync(auditPath, 'utf8');
  if (!content.trim()) return [];

  const records = [];
  for (const [index, rawLine] of content.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line) continue;
    try {
      const record = JSON.parse(line);
      if (!record || typeof record !== 'object' || Array.isArray(record)) {
        throw new TypeError('audit record must be a JSON object');
      }
      records.push(record);
    } catch (error) {
      if (typeof onMalformed === 'function') {
        onMalformed({ lineNumber: index + 1, line: rawLine, error });
      }
    }
  }

  if (limit) return records.slice(-limit);
  return records;
}
