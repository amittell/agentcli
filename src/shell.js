function quotePosix(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

export function normalizeShellExecution(shell) {
  if (!shell || typeof shell !== 'object' || Array.isArray(shell)) {
    throw new TypeError('shell execution must be an object');
  }
  if (!shell.program || typeof shell.program !== 'string') {
    throw new TypeError('shell.program is required and must be a non-empty string');
  }

  return {
    program: shell.program,
    args: Array.isArray(shell.args) ? [...shell.args] : [],
    env: shell.env && typeof shell.env === 'object' && !Array.isArray(shell.env)
      ? { ...shell.env }
      : {},
    cwd: shell.cwd ?? null,
    stdin: shell.stdin ?? null
  };
}

export function renderShellExecution(shell) {
  const normalized = normalizeShellExecution(shell);
  const argv = [normalized.program, ...normalized.args].map(quotePosix).join(' ');
  const envPrefix = Object.keys(normalized.env)
    .sort()
    .map(name => `${name}=${quotePosix(normalized.env[name])}`)
    .join(' ');

  let command = [envPrefix, argv].filter(Boolean).join(' ');
  if (normalized.stdin != null) {
    command = `printf %s ${quotePosix(normalized.stdin)} | ${command}`;
  }
  if (normalized.cwd) {
    command = `cd ${quotePosix(normalized.cwd)} && ${command}`;
  }
  return command;
}
