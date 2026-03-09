#!/usr/bin/env node

import { runCli } from '../src/cli.js';

try {
  const output = await runCli(process.argv.slice(2));
  if (output) {
    process.stdout.write(`${output}\n`);
  }
} catch (err) {
  process.stderr.write(JSON.stringify({
    ok: false,
    error: err.message,
    ...(err.validation ? { validation: err.validation } : {})
  }, null, 2) + '\n');
  process.exit(1);
}
