function safeObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value
    : {};
}

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return null;
}

export function buildStepUpContext(authorizationProofSummary = null) {
  const summary = safeObject(authorizationProofSummary);
  const claims = safeObject(summary.decoded_claims);
  const hasStepUpData =
    authorizationProofSummary != null ||
    Object.keys(claims).length > 0;

  if (!hasStepUpData) {
    return null;
  }

  return {
    verified: firstDefined(summary.verified, null),
    method: firstDefined(summary.method, null),
    issuer: firstDefined(summary.issuer, null),
    verified_at: firstDefined(summary.verified_at, claims.verification_verified_at, null),
    step_up_policy: firstDefined(claims.step_up_policy, null),
    verification_ref: firstDefined(claims.verification_ref, null),
    verification_level: firstDefined(claims.verification_level, null),
    claims: Object.keys(claims).length > 0 ? claims : null,
    reason: firstDefined(summary.reason, null),
  };
}

export function buildActorContext({
  identityDeclaration = null,
  declaredIdentity = null,
  resolvedIdentity = null,
  authorizationProofSummary = null,
  principal = null,
  target = null,
} = {}) {
  const declarationSubject = safeObject(identityDeclaration?.subject);
  const declaredSubject = safeObject(declaredIdentity?.subject);
  const resolvedSubject = safeObject(resolvedIdentity?.subject);
  const attributes = safeObject(declarationSubject.attributes);
  const claims = safeObject(authorizationProofSummary?.decoded_claims);

  const actor = {
    principal: firstDefined(
      principal,
      resolvedSubject.principal,
      declaredSubject.principal,
      declarationSubject.principal,
      null,
    ),
    kind: firstDefined(
      declaredSubject.kind,
      declarationSubject.kind,
      null,
    ),
    display_name: firstDefined(declarationSubject.display_name, null),
  };

  return {
    actor,
    org_id: firstDefined(claims.org_id, attributes.org_id, null),
    on_behalf_of_user_id: firstDefined(
      claims.on_behalf_of_user_id,
      attributes.on_behalf_of_user_id,
      null,
    ),
    delegation_grant_id: firstDefined(
      claims.delegation_grant_id,
      attributes.delegation_grant_id,
      null,
    ),
    run_id: firstDefined(claims.run_id, attributes.run_id, null),
    agent_id: firstDefined(
      target?.agent_id,
      claims.agent_id,
      attributes.agent_id,
      null,
    ),
    verification: {
      ref: firstDefined(claims.verification_ref, attributes.verification_ref, null),
      level: firstDefined(claims.verification_level, attributes.verification_level, null),
      verified_at: firstDefined(
        claims.verification_verified_at,
        attributes.verification_verified_at,
        null,
      ),
      step_up_policy: firstDefined(claims.step_up_policy, attributes.step_up_policy, null),
      proof_verified: firstDefined(authorizationProofSummary?.verified, null),
      proof_method: firstDefined(authorizationProofSummary?.method, null),
      proof_issuer: firstDefined(authorizationProofSummary?.issuer, null),
    },
  };
}
