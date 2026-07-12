#!/usr/bin/env node

import { runCli } from '../src/cli.js';
import { normalizeError } from '../src/errors.js';

try {
  const output = await runCli(process.argv.slice(2), { throwOnValidationFailure: true });
  if (output) {
    process.stdout.write(`${output}\n`);
  }
} catch (err) {
  const normalized = normalizeError(err);
  const code = normalized.validation ? 'validation_error' : normalized.code;
  const errorType = normalized.validation ? 'validation_error' : normalized.error_type;
  process.stderr.write(JSON.stringify({
    ok: false,
    error: normalized.message,
    error_type: errorType,
    code,
    ...(normalized.validation ? { validation: normalized.validation } : {}),
    ...(normalized.cleanup_warnings ? { cleanup_warnings: normalized.cleanup_warnings } : {}),
  }, null, 2) + '\n');
  process.exit(1);
}
