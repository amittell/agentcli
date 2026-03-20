import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { MANIFEST_SCHEMA, MANIFEST_VERSION } from './schema.js';
import { describeTarget } from './describe.js';
import { validateManifest } from './validate.js';
import { getTarget } from './targets.js';
import { parseFieldMask } from './fields.js';
import { inspectSchedulerState, listInspectableEntities } from './inspect.js';
import { applyManifestToScheduler } from './apply.js';

const require = createRequire(import.meta.url);
const { version: PACKAGE_VERSION } = require('../package.json');

function responseResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function responseError(id, code, message, data) {
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code,
      message,
      ...(data === undefined ? {} : { data })
    }
  };
}

class InvalidParamsError extends Error {
  constructor(message, data) {
    super(message);
    this.name = 'InvalidParamsError';
    this.data = data;
  }
}

function invalidParams(message, data) {
  return new InvalidParamsError(message, data);
}

function paramsObject(rawParams) {
  if (rawParams == null) {
    return {};
  }
  if (typeof rawParams !== 'object' || Array.isArray(rawParams)) {
    throw invalidParams('Params must be an object');
  }
  return rawParams;
}

function schemaByName(name = 'manifest') {
  const aliases = {
    'scheduler-job': 'schedulerJob',
    'standalone-plan': 'standalonePlan',
    'rpc-request': 'rpcRequest',
    'rpc-response': 'rpcResponse'
  };
  const schema = MANIFEST_SCHEMA[aliases[name] || name];
  if (!schema) {
    throw invalidParams(`Unknown schema target: ${name}`);
  }
  return schema;
}

function describedTarget(name = 'commands') {
  try {
    return describeTarget(name);
  } catch (err) {
    throw invalidParams(err.message);
  }
}

function compileTarget(name) {
  try {
    return getTarget(name);
  } catch (err) {
    throw invalidParams(err.message);
  }
}

function inspectFields(fields) {
  if (fields == null) {
    return null;
  }
  if (typeof fields === 'string') {
    return parseFieldMask(fields);
  }
  if (!Array.isArray(fields)) {
    throw invalidParams('inspect fields must be a comma-delimited string or an array of field names');
  }

  return fields.map((field, index) => {
    if (typeof field !== 'string' || field.trim() === '') {
      throw invalidParams(`inspect fields[${index}] must be a non-empty string`);
    }
    return field.trim();
  });
}

function inspectLimit(limit) {
  if (limit == null) {
    return undefined;
  }
  if (typeof limit === 'number' && Number.isInteger(limit) && limit > 0) {
    return limit;
  }
  if (typeof limit === 'string' && /^[1-9][0-9]*$/.test(limit)) {
    return Number.parseInt(limit, 10);
  }
  throw invalidParams('inspect limit must be a positive integer');
}

function inspectParams(params, defaults) {
  const entity = params.entity || 'jobs';
  if (!listInspectableEntities().includes(entity)) {
    throw invalidParams(`Unsupported inspect entity: ${entity}`);
  }

  const sanitize = params.sanitize || 'none';
  if (sanitize !== 'none' && sanitize !== 'basic') {
    throw invalidParams(`Unsupported sanitize mode: ${sanitize}`);
  }

  const dbPath = params.dbPath || defaults.dbPath;
  if (!dbPath) {
    throw invalidParams('Missing scheduler database path. Pass dbPath or configure a default.');
  }
  if (!existsSync(dbPath)) {
    throw invalidParams(`Scheduler database not found: ${dbPath}`);
  }

  return {
    dbPath,
    entity,
    limit: inspectLimit(params.limit),
    fields: inspectFields(params.fields),
    sanitize
  };
}

export async function handleJsonRpcRequest(message, defaults = {}) {
  if (Array.isArray(message)) {
    return responseError(null, -32600, 'Batch requests are not supported');
  }
  if (!message || typeof message !== 'object') {
    return responseError(null, -32600, 'Invalid Request');
  }

  const { id = null, method, params: rawParams } = message;
  if (message.jsonrpc !== '2.0' || typeof method !== 'string') {
    return responseError(id, -32600, 'Invalid Request');
  }

  try {
    const params = paramsObject(rawParams);
    switch (method) {
      case 'agentcli.ping':
        return responseResult(id, { ok: true, pong: true });
      case 'agentcli.version':
        return responseResult(id, {
          ok: true,
          package_version: PACKAGE_VERSION,
          manifest_version: MANIFEST_VERSION
        });
      case 'agentcli.schema':
        return responseResult(id, { ok: true, schema: schemaByName(params.target) });
      case 'agentcli.describe':
        return responseResult(id, { ok: true, description: describedTarget(params.target) });
      case 'agentcli.validate':
        return responseResult(id, validateManifest(params.manifest));
      case 'agentcli.compile': {
        const target = compileTarget(params.target || defaults.target || 'standalone');
        return responseResult(
          id,
          {
            ok: true,
            target: target.name,
            output: target.compile(params.manifest, { includeExplain: Boolean(params.explain) })
          }
        );
      }
      case 'agentcli.apply': {
        const adoptBy = params.adoptBy || 'id';
        if (adoptBy !== 'id' && adoptBy !== 'name') {
          throw invalidParams(`Invalid adoptBy value: ${adoptBy}. Accepted values: id, name`);
        }
        return responseResult(
          id,
          applyManifestToScheduler(params.manifest, {
            dryRun: Boolean(params.dryRun),
            includeExplain: Boolean(params.explain),
            adoptBy,
            dbPath: params.dbPath || defaults.dbPath,
            schedulerPrefix: params.schedulerPrefix || defaults.schedulerPrefix || '',
            schedulerBin: params.schedulerBin || defaults.schedulerBin || '',
            runner: defaults.schedulerRunner || null
          })
        );
      }
      case 'agentcli.inspect':
        return responseResult(
          id,
          await inspectSchedulerState(inspectParams(params, defaults))
        );
      default:
        return responseError(id, -32601, `Method not found: ${method}`);
    }
  } catch (err) {
    if (err instanceof InvalidParamsError) {
      return responseError(id, -32602, err.message, err.data);
    }
    if (err.validation) {
      return responseError(id, -32602, err.message, err.validation);
    }
    return responseError(id, -32000, err?.message || 'Internal error');
  }
}

function safeLine(stream, data) {
  if (stream.writable !== false) {
    try {
      stream.write(`${JSON.stringify(data)}\n`);
    } catch {
      // stream destroyed mid-write; ignore
    }
  }
}

export async function serveJsonRpc({ input = process.stdin, output = process.stdout, defaults = {} } = {}) {
  const lines = createInterface({
    input,
    crlfDelay: Infinity
  });

  output.on('error', () => {});

  safeLine(output, {
    jsonrpc: '2.0',
    method: 'agentcli.ready',
    params: {
      ok: true,
      manifest_version: MANIFEST_VERSION
    }
  });

  for await (const line of lines) {
    if (!line.trim()) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (err) {
      safeLine(output, responseError(null, -32700, 'Parse error', err.message));
      continue;
    }

    const isNotification = parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !('id' in parsed);
    const response = await handleJsonRpcRequest(parsed, defaults);

    if (!isNotification) {
      safeLine(output, response);
    }
  }
}
