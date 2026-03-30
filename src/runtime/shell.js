/**
 * Shell runtime adapter stub.
 *
 * Declares that the shell adapter handles session_target "shell" so the
 * registry knows about it.  Actual shell execution stays in exec.js --
 * calling dispatch() on this adapter is a programming error.
 */

export const shellAdapter = {
  name: 'shell',
  capabilities: { session_targets: ['shell'], stateless: true },

  canExecute(task) {
    return { supported: task.target?.session_target === 'shell' };
  },

  dispatch() {
    throw new Error('Shell tasks are executed directly via exec.js, not via adapter dispatch');
  },
};
