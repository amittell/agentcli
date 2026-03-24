/**
 * No-op evidence provider -- explicit opt-out from evidence generation.
 */

import { registerEvidenceProvider } from './index.js';

const noneEvidenceProvider = {
  name: 'none',
  methods: [],

  resolve() {
    return {};
  },

  attest() {
    return { attested: false, reason: 'evidence generation disabled (provider: none)' };
  },

  verify() {
    return { verified: false, reason: 'no evidence was generated (provider: none)' };
  },

  describe() {
    return { provider: 'none', method: null, attested: false };
  },
};

registerEvidenceProvider(noneEvidenceProvider);

export { noneEvidenceProvider };
