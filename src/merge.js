import { validateManifest } from './validate.js';
import { canonicalStringify } from './canonical.js';

const PROFILE_COLLECTIONS = [
  'identity_profiles',
  'authorization_proof_profiles',
  'authorization_profiles',
  'evidence_profiles',
];

export function mergeManifests(manifests) {
  if (!Array.isArray(manifests) || manifests.length < 2) {
    throw Object.assign(
      new Error('merge requires at least two manifests'),
      { code: 'invalid_argument' }
    );
  }

  for (const [index, manifest] of manifests.entries()) {
    const validation = validateManifest(manifest);
    if (!validation.ok) {
      throw Object.assign(
        new Error(`Manifest ${index + 1} failed validation: ${validation.errors.map(e => e.message).join('; ')}`),
        { code: 'validation_error', validation, manifest_index: index }
      );
    }
  }

  const seenWorkflowIds = new Map();
  const mergedWorkflows = [];
  const mergedProfiles = Object.fromEntries(PROFILE_COLLECTIONS.map(key => [key, []]));
  const seenProfiles = Object.fromEntries(PROFILE_COLLECTIONS.map(key => [key, new Map()]));

  for (const [index, manifest] of manifests.entries()) {
    for (const workflow of manifest.workflows) {
      if (seenWorkflowIds.has(workflow.id)) {
        throw Object.assign(
          new Error(
            `Duplicate workflow id "${workflow.id}": appears in manifest ${seenWorkflowIds.get(workflow.id) + 1} and manifest ${index + 1}`
          ),
          { code: 'validation_error' }
        );
      }
      seenWorkflowIds.set(workflow.id, index);
      mergedWorkflows.push(structuredClone(workflow));
    }

    for (const collection of PROFILE_COLLECTIONS) {
      for (const profile of manifest[collection] || []) {
        const existing = seenProfiles[collection].get(profile.id);
        if (existing) {
          if (canonicalStringify(existing.profile) !== canonicalStringify(profile)) {
            throw Object.assign(
              new Error(
                `Conflicting ${collection} id "${profile.id}": appears with different definitions in manifest ${existing.index + 1} and manifest ${index + 1}`
              ),
              { code: 'validation_error' }
            );
          }
          continue;
        }
        const cloned = structuredClone(profile);
        seenProfiles[collection].set(profile.id, { profile: cloned, index });
        mergedProfiles[collection].push(cloned);
      }
    }
  }

  const merged = {
    version: '0.2',
    ...Object.fromEntries(
      Object.entries(mergedProfiles).filter(([, profiles]) => profiles.length > 0)
    ),
    workflows: mergedWorkflows,
  };

  const validation = validateManifest(merged);
  if (!validation.ok) {
    throw Object.assign(
      new Error(`Merged manifest failed validation: ${validation.errors.map(e => e.message).join('; ')}`),
      { code: 'validation_error', validation }
    );
  }

  return merged;
}
