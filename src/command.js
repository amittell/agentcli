import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import process from 'node:process';

const VALUE_FROM_SOURCES = ['env', 'file', 'literal', 'command'];

function invalidValueFrom(message, cause) {
  return Object.assign(new Error(message, cause ? { cause } : undefined), {
    code: 'invalid_argument',
  });
}

export function shellCommandInvocation(command, platform = process.platform) {
  if (platform === 'win32') {
    return {
      program: 'cmd.exe',
      args: ['/d', '/s', '/c', command],
    };
  }
  return {
    program: 'sh',
    args: ['-c', command],
  };
}

export function resolveCommandValue(
  command,
  {
    cwd = process.cwd(),
    env = process.env,
    commandEnv = env,
    timeoutMs = 30000,
    runner = spawnSync,
    platform = process.platform,
  } = {}
) {
  try {
    const invocation = shellCommandInvocation(command, platform);
    const result = runner(invocation.program, invocation.args, {
      cwd,
      env: commandEnv,
      encoding: 'utf8',
      timeout: timeoutMs,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    if (result.status === 0 && result.stdout) {
      return result.stdout.trim();
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Resolve a value_from descriptor without accidentally executing a command.
 *
 * A descriptor must contain exactly one of env, file, literal, or command.
 * Command sources are disabled by default because resolution is otherwise a
 * side-effectful operation hidden behind what appears to be a data lookup.
 * Callers that have already crossed their approval boundary must opt in with
 * allowCommand: true.
 *
 * @param {object} valueFrom
 * @param {object} options
 * @param {object} [options.env]
 * @param {object} [options.commandEnv]
 * @param {string} [options.cwd]
 * @param {boolean} [options.allowCommand]
 * @param {number} [options.timeoutMs]
 * @param {Function} [options.runner]
 * @param {string} [options.platform]
 * @param {Function} [options.fileReader]
 * @returns {string}
 */
export function resolveValueFrom(
  valueFrom,
  {
    env = process.env,
    commandEnv = env,
    cwd = process.cwd(),
    allowCommand = false,
    timeoutMs = 30000,
    runner = spawnSync,
    platform = process.platform,
    fileReader = readFileSync,
  } = {}
) {
  if (!valueFrom || typeof valueFrom !== 'object' || Array.isArray(valueFrom)) {
    throw invalidValueFrom('value_from must be an object');
  }

  const sources = VALUE_FROM_SOURCES.filter(source => valueFrom[source] !== undefined);
  if (sources.length !== 1) {
    throw invalidValueFrom(
      `value_from must specify exactly one source (${VALUE_FROM_SOURCES.join(', ')})`
    );
  }

  const source = sources[0];
  const configuredValue = valueFrom[source];
  if (typeof configuredValue !== 'string' || configuredValue.length === 0) {
    throw invalidValueFrom(`value_from.${source} must be a non-empty string`);
  }

  if (source === 'literal') return configuredValue;

  if (source === 'env') {
    if (!Object.prototype.hasOwnProperty.call(env, configuredValue)) {
      throw invalidValueFrom(`Environment variable "${configuredValue}" is not set`);
    }
    const value = env[configuredValue];
    if (typeof value !== 'string' || value.length === 0) {
      throw invalidValueFrom(`Environment variable "${configuredValue}" is empty`);
    }
    return value;
  }

  if (source === 'file') {
    const filePath = isAbsolute(configuredValue)
      ? configuredValue
      : resolve(cwd, configuredValue);
    try {
      const value = fileReader(filePath, 'utf8').trim();
      if (!value) {
        throw invalidValueFrom(`value_from.file resolved to an empty file: ${filePath}`);
      }
      return value;
    } catch (error) {
      if (error?.code === 'invalid_argument') throw error;
      throw invalidValueFrom(`Unable to read value_from.file: ${filePath}`, error);
    }
  }

  if (!allowCommand) {
    throw invalidValueFrom(
      'value_from.command is disabled until the caller explicitly opts in after approval'
    );
  }

  const value = resolveCommandValue(configuredValue, {
    cwd,
    env,
    commandEnv,
    timeoutMs,
    runner,
    platform,
  });
  if (!value) {
    throw invalidValueFrom('value_from.command failed or produced no output');
  }
  return value;
}

export { VALUE_FROM_SOURCES };
