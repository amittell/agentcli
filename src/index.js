export { runCli } from './cli.js';
export { handleJsonRpcRequest, serveJsonRpc } from './jsonrpc.js';
export { validateManifest } from './validate.js';
export { compileManifestToStandalone } from './compiler/standalone.js';
export { compileManifestToScheduler } from './compiler/openclaw-scheduler.js';
export {
  applyManifestToScheduler,
  createSchedulerCliRunner,
  resolveSchedulerInvocation,
  requiredSchedulerFieldVersion,
  negotiateSchedulerFieldVersion,
} from './apply.js';
export { querySchedulerCapabilities, resolveEffectiveFeatures, validateManifestCapabilities } from './capabilities.js';
export {
  MANIFEST_SCHEMA,
  MANIFEST_JSON_SCHEMA,
  JSON_SCHEMAS,
  MANIFEST_VERSION,
} from './schema.js';
export { TARGETS, getTarget, listTargets, registerTarget } from './targets.js';
export { ensureAgentcliHome, getAgentcliPaths, resolveAgentcliHome, resolveManifestCandidate } from './home.js';
export { normalizeShellExecution, renderShellExecution } from './shell.js';
export { resolveCommandValue, resolveValueFrom, shellCommandInvocation } from './command.js';
export {
  resolveSandboxSupport,
  needsSandboxEnforcement,
  buildMacOSSandboxProfile,
  prepareSandboxedShellCommand,
} from './sandbox.js';
export { inspectSchedulerState, listInspectableEntities } from './inspect.js';
export { describeTarget } from './describe.js';
export { sanitizeForAgent } from './sanitize.js';
export { sortKeysDeep, canonicalStringify, canonicalDigest, hashString, hashNullableString } from './canonical.js';
export { AgentcliError, ERROR_CODES, ERROR_TYPES, makeError, normalizeError, errorTypeForCode } from './errors.js';
export { expandManifestShorthands } from './shorthand.js';
export { applyFieldMask, parseFieldMask } from './fields.js';
export { loadJsonInput, writeJsonOutput, resolveSafeOutputPath } from './io.js';
export {
  executeTask,
  inspectTaskIdentity,
  validateTaskDelegation,
  evaluateTaskAuthorization,
  verifyTaskAuthorizationProof,
} from './exec.js';
export { runWorkflow } from './run.js';
export {
  registerRuntimeAdapter,
  getRuntimeAdapter,
  resolveRuntimeAdapter,
  listRuntimeAdapters,
} from './runtime/index.js';
export { generateExecutionId, writeAuditRecord, readAuditLog } from './audit.js';
export {
  grantApproval,
  listApprovals,
  findValidApproval,
  consumeApproval,
  claimApproval,
  revokeApproval,
  computeTaskApprovalHash,
  approvalPolicyRequiresApproval,
  approvalPolicyAutoRejects,
  verifyApprovalSignature,
} from './approvals.js';
export {
  resolveIdentity,
  resolveIdentityV2,
  resolveContract,
  resolveAuthorizationProof,
  resolveAuthorization,
  resolveEvidence,
  buildEffectiveExecutionBinding,
  computeEffectiveTaskHash,
  commandBindingForShell,
  canonicalExecutionBindingString,
} from './compiler/shared.js';
export { buildAttestationPayload, commandHash } from './attestation.js';
export { createManifestScaffold, writeManifest } from './init.js';
export { listRegistry, addToRegistry, showRegistryEntry, removeFromRegistry } from './registry.js';
export { importManifest } from './import.js';
export { mergeManifests } from './merge.js';
export { convertManifestV1toV2 } from './convert.js';
export {
  registerProvider,
  getProvider,
  listProviders,
  resolveProvider,
  resolveProviderForMethod,
} from './signing/index.js';
export {
  resolveSigningKey,
  getKeyFingerprint,
  signPayload,
  verifySignature,
  resolveAllowedSigners,
  generateAllowedSigners,
} from './signing/ssh.js';

// -- Identity providers (v0.2) --
export {
  registerProvider as registerIdentityProvider,
  getProvider as getIdentityProvider,
  listProviders as listIdentityProviders,
  resolveProvider as resolveIdentityProvider,
  listProviderCapabilities as listIdentityProviderCapabilities,
} from './identity/index.js';
export {
  TRUST_LEVELS,
  resolveSourcePath,
  redactSession,
  buildCredentialSummary,
  isSessionExpired,
  formatMaterializationValue,
  validateTrustLevel,
  compareTrustLevels,
} from './identity/session.js';

// -- Evidence providers (v0.2) --
export {
  registerEvidenceProvider,
  getEvidenceProvider,
  listEvidenceProviders,
  resolveEvidenceProvider,
  resolveEvidenceProviderForMethod,
} from './evidence/index.js';
export {
  buildEvidencePayload,
  buildCompleteEvidencePayload,
  validateCompleteEvidencePayload,
  validateEvidenceRecordBinding,
  EVIDENCE_PAYLOAD_SCHEMA,
  EVIDENCE_PAYLOAD_VERSION,
  serializePayload,
  collectComplianceContext,
} from './evidence/payload.js';
export { verifyEvidenceEnvelope } from './evidence/index.js';
export { EVIDENCE_ENVELOPE_SCHEMA, EVIDENCE_ENVELOPE_VERSION } from './evidence/ssh.js';

// -- Authorization proof verifiers (v0.2) --
export {
  registerVerifier,
  getVerifier,
  listVerifiers,
  resolveVerifier,
  validateAuthorizationProofProfile,
  assertValidAuthorizationProofProfile,
  verifyAuthorizationProof,
} from './authorization-proof/index.js';

// -- Authorization providers (v0.2) --
export {
  registerAuthorizationProvider,
  getAuthorizationProvider,
  listAuthorizationProviders,
  resolveAuthorizationProvider,
  normalizeAuthorizationRequest,
  normalizeDecision,
} from './authorization/index.js';

// -- Schema v0.2 field definitions --
export {
  identityFieldV1,
  identityFieldV2,
  identityProfileField,
  authorizationProofProfileField,
  authorizationProfileField,
  evidenceProfileField,
  trustField,
  subjectField,
  authField,
  presentationField,
  delegationPolicyField,
  valueFromField,
  authorizationProofRefField,
  authorizationRefField,
  evidenceRefField,
} from './schema.js';
