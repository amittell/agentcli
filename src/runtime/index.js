/**
 * Runtime adapter registry.
 *
 * Adapters declare which session_targets they can handle so that exec.js
 * can delegate non-shell tasks to the appropriate runtime instead of
 * throwing an error.
 */

const adapters = new Map();

/**
 * Register a runtime adapter.
 *
 * @param {object} adapter - Must have a string `name` and a `dispatch` function.
 */
export function registerRuntimeAdapter(adapter) {
  if (!adapter || typeof adapter.name !== 'string') {
    throw new Error('Adapter must have a string name');
  }
  if (typeof adapter.dispatch !== 'function') {
    throw new Error(`Adapter "${adapter.name}" must implement dispatch()`);
  }
  adapters.set(adapter.name, adapter);
}

/**
 * Look up an adapter by exact name.
 *
 * @param {string} name
 * @returns {object|null}
 */
export function getRuntimeAdapter(name) {
  return adapters.get(name) || null;
}

/**
 * Find the first adapter whose declared session_targets include the given value.
 *
 * @param {string} sessionTarget - e.g. 'main', 'isolated', 'shell'
 * @returns {object|null}
 */
export function resolveRuntimeAdapter(sessionTarget) {
  for (const adapter of adapters.values()) {
    if (adapter.capabilities?.session_targets?.includes(sessionTarget)) {
      return adapter;
    }
  }
  return null;
}

/**
 * Return a summary of every registered adapter.
 *
 * @returns {Array<{name: string, capabilities: object}>}
 */
export function listRuntimeAdapters() {
  return Array.from(adapters.values()).map(a => ({
    name: a.name,
    capabilities: a.capabilities || {},
  }));
}

// -- Auto-register built-in adapters on first import --

import { shellAdapter } from './shell.js';
import { schedulerAdapter } from './openclaw-scheduler.js';

registerRuntimeAdapter(shellAdapter);
registerRuntimeAdapter(schedulerAdapter);
