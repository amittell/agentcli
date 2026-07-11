import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { JSON_SCHEMAS, MANIFEST_SCHEMA, MANIFEST_VERSION } from './schema.js';
import { describeTarget } from './describe.js';
import { validateManifest } from './validate.js';
import { getTarget, listTargets } from './targets.js';
import { parseFieldMask } from './fields.js';
import { inspectSchedulerState, listInspectableEntities } from './inspect.js';
import { applyManifestToScheduler } from './apply.js';
import { normalizeError } from './errors.js';
import { getAgentcliPaths } from './home.js';
import { readAuditLog } from './audit.js';
import { listApprovals } from './approvals.js';
import { listRegistry, showRegistryEntry } from './registry.js';

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
  constructor(message, data, code = 'invalid_argument') {
    super(message);
    this.name = 'InvalidParamsError';
    this.data = data;
    this.code = code;
  }
}

function invalidParams(message, data, code) {
  return new InvalidParamsError(message, data, code);
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

function schemaByName(name = 'manifest', { legacy = false } = {}) {
  const aliases = {
    'scheduler-job': 'schedulerJob',
    'standalone-plan': 'standalonePlan',
    'rpc-request': 'rpcRequest',
    'rpc-response': 'rpcResponse'
  };
  const schemas = legacy ? MANIFEST_SCHEMA : JSON_SCHEMAS;
  const schema = schemas[aliases[name] || name];
  if (!schema) {
    throw invalidParams(`Unknown schema target: ${name}`);
  }
  return schema;
}

function rpcErrorData(code, errorType, extra) {
  return {
    code,
    error_type: errorType,
    ...(extra === undefined ? {} : { details: extra }),
  };
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
    return responseError(
      null,
      -32600,
      'Batch requests are not supported',
      rpcErrorData('invalid_argument', 'invalid_argument')
    );
  }
  if (!message || typeof message !== 'object') {
    return responseError(
      null,
      -32600,
      'Invalid Request',
      rpcErrorData('invalid_argument', 'invalid_argument')
    );
  }

  const { id = null, method, params: rawParams } = message;
  if (message.jsonrpc !== '2.0' || typeof method !== 'string') {
    return responseError(
      id,
      -32600,
      'Invalid Request',
      rpcErrorData('invalid_argument', 'invalid_argument')
    );
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
      case 'agentcli.schema': {
        if (params.legacy != null && typeof params.legacy !== 'boolean') {
          throw invalidParams('legacy must be a boolean');
        }
        return responseResult(id, {
          ok: true,
          schema_format: params.legacy ? 'agentcli-legacy' : 'json-schema-draft-2020-12',
          schema: schemaByName(params.target, { legacy: Boolean(params.legacy) }),
        });
      }
      case 'agentcli.describe':
        return responseResult(id, { ok: true, description: describedTarget(params.target) });
      case 'agentcli.targets':
        return responseResult(id, { ok: true, targets: listTargets() });
      case 'agentcli.paths':
        return responseResult(id, {
          ok: true,
          paths: getAgentcliPaths({ env: defaults.env || process.env }),
        });
      case 'agentcli.validate':
        if (!Object.hasOwn(params, 'manifest')) throw invalidParams('manifest is required');
        return responseResult(id, validateManifest(params.manifest));
      case 'agentcli.compile': {
        if (!Object.hasOwn(params, 'manifest')) throw invalidParams('manifest is required');
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
        if (!Object.hasOwn(params, 'manifest')) throw invalidParams('manifest is required');
        if (params.allowProofCommand != null && typeof params.allowProofCommand !== 'boolean') {
          throw invalidParams('allowProofCommand must be a boolean');
        }
        const adoptBy = params.adoptBy || 'id';
        if (adoptBy !== 'id' && adoptBy !== 'name') {
          throw invalidParams(`Invalid adoptBy value: ${adoptBy}. Accepted values: id, name`);
        }
        return responseResult(
          id,
          await applyManifestToScheduler(params.manifest, {
            dryRun: Boolean(params.dryRun),
            includeExplain: Boolean(params.explain),
            adoptBy,
            dbPath: params.dbPath || defaults.dbPath,
            schedulerPrefix: params.schedulerPrefix || defaults.schedulerPrefix || '',
            schedulerBin: params.schedulerBin || defaults.schedulerBin || '',
            runner: defaults.schedulerRunner || null,
            allowValueFromCommand: Boolean(params.allowProofCommand),
          })
        );
      }
      case 'agentcli.inspect':
        return responseResult(
          id,
          await inspectSchedulerState(inspectParams(params, defaults))
        );
      case 'agentcli.audit': {
        const limit = inspectLimit(params.limit);
        const paths = getAgentcliPaths({ env: defaults.env || process.env });
        const warnings = [];
        const records = readAuditLog({
          auditPath: paths.audit,
          limit,
          onMalformed: ({ lineNumber }) => warnings.push({
            line_number: lineNumber,
            message: 'malformed audit record skipped',
          }),
        });
        return responseResult(id, { ok: true, count: records.length, records, warnings });
      }
      case 'agentcli.approvals.list': {
        const records = listApprovals({
          env: defaults.env || process.env,
          status: params.status,
          workflowId: params.workflowId,
          taskId: params.taskId,
        });
        return responseResult(id, { ok: true, count: records.length, records });
      }
      case 'agentcli.registry.list': {
        const entries = listRegistry({ env: defaults.env || process.env });
        return responseResult(id, { ok: true, entries });
      }
      case 'agentcli.registry.show': {
        if (typeof params.name !== 'string' || params.name.trim() === '') {
          throw invalidParams('name is required');
        }
        const manifest = showRegistryEntry(params.name, { env: defaults.env || process.env });
        return responseResult(id, { ok: true, name: params.name, manifest });
      }
      case 'agentcli.convert': {
        const p = paramsObject(rawParams);
        if (!p.manifest) throw invalidParams('manifest is required');
        const { convertManifestV1toV2 } = await import('./convert.js');
        return responseResult(id, { ok: true, manifest: convertManifestV1toV2(p.manifest) });
      }
      case 'agentcli.authorizationProof.methods': {
        const { listVerifiers } = await import('./authorization-proof/index.js');
        await import('./authorization-proof/none.js');
        await import('./authorization-proof/jwt.js');
        await import('./authorization-proof/detached-signature.js');
        await import('./authorization-proof/certificate.js');
        return responseResult(id, { ok: true, methods: listVerifiers() });
      }
      case 'agentcli.authorizationProof.schema': {
        const p = paramsObject(rawParams);
        if (!p.method) throw invalidParams('method is required');
        const { getVerifier } = await import('./authorization-proof/index.js');
        await import('./authorization-proof/none.js');
        await import('./authorization-proof/jwt.js');
        await import('./authorization-proof/detached-signature.js');
        await import('./authorization-proof/certificate.js');
        const verifier = getVerifier(p.method);
        if (!verifier) throw invalidParams(`Unknown verifier method: ${p.method}`);
        return responseResult(id, { ok: true, method: p.method, verifier: verifier.name });
      }
      case 'agentcli.authorizationProof.verify': {
        const p = paramsObject(rawParams);
        if (!p.manifest) throw invalidParams('manifest is required');
        if (!p.taskId) throw invalidParams('taskId is required');
        const { verifyTaskAuthorizationProof } = await import('./exec.js');
        const result = await verifyTaskAuthorizationProof(p.manifest, {
          workflowId: p.workflowId,
          taskId: p.taskId,
          cwd: defaults.cwd || process.cwd(),
          env: defaults.env || process.env,
        });
        return responseResult(id, {
          ok: true,
          authorization_proof: result.authorization_proof || null,
          effective_task_hash: result.effective_task_hash,
          manifest_digest: result.manifest_digest,
        });
      }
      case 'agentcli.identity.providers': {
        const { listProviders, listProviderCapabilities } = await import('./identity/index.js');
        await import('./identity/none.js');
        await import('./identity/env-bearer.js');
        await import('./identity/file-bearer.js');
        await import('./identity/oidc-client-credentials.js');
        await import('./identity/oidc-token-exchange.js');
        await import('./identity/azure-managed-identity.js');
        await import('./identity/aws-sts-assume-role.js');
        await import('./identity/gcp-workload-identity.js');
        await import('./identity/spiffe-jwt-svid.js');
        await import('./identity/entra-agent-id.js');
        const providers = listProviders();
        const capabilities = listProviderCapabilities();
        return responseResult(id, { ok: true, providers: providers.map(name => ({ name, capabilities: capabilities.get(name) || null })) });
      }
      case 'agentcli.identity.schema': {
        const p = paramsObject(rawParams);
        if (!p.provider) throw invalidParams('provider is required');
        const { getProvider } = await import('./identity/index.js');
        await import('./identity/none.js');
        await import('./identity/env-bearer.js');
        await import('./identity/file-bearer.js');
        await import('./identity/oidc-client-credentials.js');
        await import('./identity/oidc-token-exchange.js');
        await import('./identity/azure-managed-identity.js');
        await import('./identity/aws-sts-assume-role.js');
        await import('./identity/gcp-workload-identity.js');
        await import('./identity/spiffe-jwt-svid.js');
        await import('./identity/entra-agent-id.js');
        const idProvider = getProvider(p.provider);
        if (!idProvider) throw invalidParams(`Unknown identity provider: ${p.provider}`);
        return responseResult(id, { ok: true, provider: p.provider, capabilities: idProvider.capabilities });
      }
      case 'agentcli.identity.resolve': {
        const p = paramsObject(rawParams);
        if (!p.manifest) throw invalidParams('manifest is required');
        if (!p.taskId) throw invalidParams('taskId is required');
        const { inspectTaskIdentity } = await import('./exec.js');
        const result = await inspectTaskIdentity(p.manifest, {
          workflowId: p.workflowId,
          taskId: p.taskId,
          identityDebug: true,
          cwd: defaults.cwd || process.cwd(),
          env: defaults.env || process.env,
        });
        return responseResult(id, { ok: true, declared_identity: result.declared_identity || result.identity, resolved_identity: result.resolved_identity || null, principal_used: result.principal_used });
      }
      case 'agentcli.identity.validateDelegation': {
        const p = paramsObject(rawParams);
        if (!p.manifest) throw invalidParams('manifest is required');
        if (!p.taskId) throw invalidParams('taskId is required');
        const { validateTaskDelegation } = await import('./exec.js');
        const result = await validateTaskDelegation(p.manifest, {
          workflowId: p.workflowId,
          taskId: p.taskId,
          identityDebug: true,
          cwd: defaults.cwd || process.cwd(),
          env: defaults.env || process.env,
        });
        return responseResult(id, { ok: true, delegation: result.delegation || null });
      }
      case 'agentcli.authorization.providers': {
        const { listAuthorizationProviders } = await import('./authorization/index.js');
        await import('./authorization/none.js');
        await import('./authorization/opa.js');
        return responseResult(id, { ok: true, providers: listAuthorizationProviders() });
      }
      case 'agentcli.authorization.schema': {
        const p = paramsObject(rawParams);
        if (!p.provider) throw invalidParams('provider is required');
        const { getAuthorizationProvider } = await import('./authorization/index.js');
        await import('./authorization/none.js');
        await import('./authorization/opa.js');
        const authzProvider = getAuthorizationProvider(p.provider);
        if (!authzProvider) throw invalidParams(`Unknown authorization provider: ${p.provider}`);
        return responseResult(id, { ok: true, provider: p.provider, capabilities: authzProvider.capabilities });
      }
      case 'agentcli.authorization.evaluate': {
        const p = paramsObject(rawParams);
        if (!p.manifest) throw invalidParams('manifest is required');
        if (!p.taskId) throw invalidParams('taskId is required');
        const { evaluateTaskAuthorization } = await import('./exec.js');
        const result = await evaluateTaskAuthorization(p.manifest, {
          workflowId: p.workflowId,
          taskId: p.taskId,
          cwd: defaults.cwd || process.cwd(),
          env: defaults.env || process.env,
        });
        return responseResult(id, { ok: true, authorization: result.authorization || null });
      }
      case 'agentcli.evidence.providers': {
        const { listEvidenceProviders } = await import('./evidence/index.js');
        await import('./evidence/none.js');
        await import('./evidence/ssh.js');
        return responseResult(id, { ok: true, providers: listEvidenceProviders() });
      }
      case 'agentcli.evidence.schema': {
        const p = paramsObject(rawParams);
        if (!p.provider) throw invalidParams('provider is required');
        const { getEvidenceProvider } = await import('./evidence/index.js');
        await import('./evidence/none.js');
        await import('./evidence/ssh.js');
        const evProvider = getEvidenceProvider(p.provider);
        if (!evProvider) throw invalidParams(`Unknown evidence provider: ${p.provider}`);
        return responseResult(id, { ok: true, provider: p.provider, methods: evProvider.methods || [] });
      }
      default:
        return responseError(
          id,
          -32601,
          `Method not found: ${method}`,
          rpcErrorData('unknown_command', 'unknown_command')
        );
    }
  } catch (err) {
    if (err instanceof InvalidParamsError) {
      return responseError(
        id,
        -32602,
        err.message,
        rpcErrorData(err.code, 'invalid_argument', err.data)
      );
    }
    const normalized = normalizeError(err);
    if (normalized.validation) {
      return responseError(id, -32602, normalized.message, {
        code: 'validation_error',
        error_type: 'validation_error',
        validation: normalized.validation,
      });
    }
    if (normalized.error_type === 'invalid_argument' || normalized.error_type === 'parse_error') {
      return responseError(
        id,
        -32602,
        normalized.message,
        rpcErrorData(normalized.code, normalized.error_type)
      );
    }
    if (normalized.error_type === 'internal_error') {
      return responseError(
        id,
        -32603,
        'Internal error',
        rpcErrorData(normalized.code, normalized.error_type)
      );
    }
    return responseError(
      id,
      -32000,
      normalized.message,
      rpcErrorData(normalized.code, normalized.error_type)
    );
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
      safeLine(output, responseError(
        null,
        -32700,
        'Parse error',
        rpcErrorData('parse_error', 'parse_error', err.message)
      ));
      continue;
    }

    const isNotification = parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !('id' in parsed);
    const response = await handleJsonRpcRequest(parsed, defaults);

    if (!isNotification) {
      safeLine(output, response);
    }
  }
}
