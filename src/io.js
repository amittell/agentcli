import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, relative, resolve } from 'path';
import { isatty } from 'tty';
import { resolveManifestCandidate } from './home.js';

function looksLikeJsonLiteral(input) {
  if (typeof input !== 'string') return false;
  const trimmed = input.trim();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

export async function loadJsonInput(
  input,
  { cwd = process.cwd(), env = process.env, stdin = process.stdin } = {}
) {
  if (!input) {
    throw new Error('Missing input. Pass a file path or JSON string.');
  }
  const resolvedPath = resolveManifestCandidate(input, { cwd, env });
  if (input === '-' && (stdin?.isTTY ?? isatty(0))) {
    throw new Error('stdin is a TTY. Pipe JSON data or pass a file path.');
  }
  const raw = input === '-'
    ? await readStdinText(stdin)
    : resolvedPath
      ? readFileSync(resolvedPath, 'utf8')
      : existsSync(input)
        ? readFileSync(input, 'utf8')
        : looksLikeJsonLiteral(input)
          ? input
          : (() => {
              throw new Error(`Input not found: ${input}. Pass a file path, a manifest name from AGENTCLI_HOME/manifests, or a JSON string.`);
            })();
  return JSON.parse(raw);
}

async function readStdinText(stream) {
  if (!stream || typeof stream[Symbol.asyncIterator] !== 'function') {
    throw new Error('stdin is not readable. Pipe JSON data or pass a file path.');
  }

  let raw = '';
  for await (const chunk of stream) {
    raw += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
  }
  return raw;
}

export function resolveSafeOutputPath(outputPath, cwd = process.cwd()) {
  if (!outputPath) {
    throw new Error('Missing output path.');
  }

  const baseDir = resolve(cwd);
  const resolvedPath = resolve(baseDir, outputPath);
  const relativePath = relative(baseDir, resolvedPath);

  if (relativePath === '' || relativePath === '.') {
    throw new Error('Output path must point to a file inside the current working directory.');
  }

  if (relativePath.startsWith('..')) {
    throw new Error('Refusing to write outside the current working directory.');
  }

  return resolvedPath;
}

export function writeJsonOutput(outputPath, payload, { cwd = process.cwd() } = {}) {
  const resolvedPath = resolveSafeOutputPath(outputPath, cwd);
  mkdirSync(dirname(resolvedPath), { recursive: true });
  writeFileSync(resolvedPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  return resolvedPath;
}
