import { createInterface } from 'node:readline';
import { MANIFEST_SCHEMA, MANIFEST_VERSION } from './schema.js';
import { describeTarget } from './describe.js';
import { validateManifest } from './validate.js';
import { getTarget } from './targets.js';
import { inspectSchedulerState } from './inspect.js';
import { applyManifestToScheduler } from './apply.js';

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

function schemaByName(name = 'manifest') {
  const aliases = {
    'scheduler-job': 'schedulerJob',
    'standalone-plan': 'standalonePlan',
    'rpc-request': 'rpcRequest',
    'rpc-response': 'rpcResponse'
  };
  const schema = MANIFEST_SCHEMA[aliases[name] || name];
  if (!schema) {
    throw new Error(`Unknown schema target: ${name}`);
  }
  return schema;
}

export async function handleJsonRpcRequest(message, defaults = {}) {
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    return responseError(null, -32600, 'Invalid Request');
  }

  const { id = null, method, params: rawParams } = message;
  const params = (rawParams != null && typeof rawParams === 'object' && !Array.isArray(rawParams)) ? rawParams : {};
  if (message.jsonrpc !== '2.0' || typeof method !== 'string') {
    return responseError(id, -32600, 'Invalid Request');
  }

  try {
    switch (method) {
      case 'agentcli.ping':
        return responseResult(id, { ok: true, pong: true });
      case 'agentcli.schema':
        return responseResult(id, { ok: true, schema: schemaByName(params.target) });
      case 'agentcli.describe':
        return responseResult(id, { ok: true, description: describeTarget(params.target) });
      case 'agentcli.validate':
        return responseResult(id, validateManifest(params.manifest));
      case 'agentcli.compile': {
        const target = getTarget(params.target || defaults.target || 'standalone');
        return responseResult(
          id,
          {
            ok: true,
            output: target.compile(params.manifest, { includeExplain: Boolean(params.explain) })
          }
        );
      }
      case 'agentcli.apply': {
        const adoptBy = params.adoptBy || 'id';
        if (adoptBy !== 'id' && adoptBy !== 'name') {
          return responseError(id, -32602, `Invalid adoptBy value: ${adoptBy}. Accepted values: id, name`);
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
          await inspectSchedulerState({
            dbPath: params.dbPath || defaults.dbPath,
            entity: params.entity,
            limit: params.limit,
            fields: params.fields || null,
            sanitize: params.sanitize || 'none'
          })
        );
      default:
        return responseError(id, -32601, `Method not found: ${method}`);
    }
  } catch (err) {
    if (err.validation) {
      return responseError(id, -32602, err.message, err.validation);
    }
    return responseError(id, -32000, err.message);
  }
}

export async function serveJsonRpc({ input = process.stdin, output = process.stdout, defaults = {} } = {}) {
  const lines = createInterface({
    input,
    crlfDelay: Infinity
  });

  output.write(`${JSON.stringify({
    jsonrpc: '2.0',
    method: 'agentcli.ready',
    params: {
      ok: true,
      manifest_version: MANIFEST_VERSION
    }
  })}\n`);

  for await (const line of lines) {
    if (!line.trim()) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (err) {
      output.write(`${JSON.stringify(responseError(null, -32700, 'Parse error', err.message))}\n`);
      continue;
    }

    const isNotification = parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !('id' in parsed);
    const response = await handleJsonRpcRequest(parsed, defaults);

    if (!isNotification) {
      output.write(`${JSON.stringify(response)}\n`);
    }
  }
}
