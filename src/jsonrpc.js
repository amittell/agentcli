import { createInterface } from 'node:readline';
import { MANIFEST_SCHEMA } from './schema.js';
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

  const { id = null, method, params = {} } = message;
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
      case 'agentcli.apply':
        return responseResult(
          id,
          applyManifestToScheduler(params.manifest, {
            dryRun: Boolean(params.dryRun),
            includeExplain: Boolean(params.explain),
            dbPath: params.dbPath || defaults.dbPath,
            schedulerPrefix: params.schedulerPrefix || defaults.schedulerPrefix || '',
            schedulerBin: params.schedulerBin || defaults.schedulerBin || '',
            runner: defaults.schedulerRunner || null
          })
        );
      case 'agentcli.inspect':
        return responseResult(
          id,
          inspectSchedulerState({
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
    return responseError(id, -32000, err.message);
  }
}

export async function serveJsonRpc({ input = process.stdin, output = process.stdout, defaults = {} } = {}) {
  const lines = createInterface({
    input,
    crlfDelay: Infinity
  });

  for await (const line of lines) {
    if (!line.trim()) continue;

    let response;
    try {
      response = await handleJsonRpcRequest(JSON.parse(line), defaults);
    } catch (err) {
      response = responseError(null, -32700, 'Parse error', err.message);
    }

    if (response?.id !== undefined && response.id !== null) {
      output.write(`${JSON.stringify(response)}\n`);
    }
  }
}
