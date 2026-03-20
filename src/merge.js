import { validateManifest } from './validate.js';

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
  }

  const merged = {
    version: '0.1',
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
