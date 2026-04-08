package agentcli.authz

default allow = false

document_level_verified {
  input.step_up.verification_level == "document"
}

document_level_verified {
  input.step_up.verification_level == "selfie+document"
}

allow {
  input.actor.org_id == "org_demo"
  input.actor.actor.principal == "agent://acme/ops-bot"
  input.actor.on_behalf_of_user_id != null
  input.actor.delegation_grant_id != null
  input.step_up.verified == true
  input.step_up.step_up_policy == "stripe_identity_sensitive_ops"
  document_level_verified
}
