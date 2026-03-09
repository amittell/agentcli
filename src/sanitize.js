const ESC = String.fromCharCode(27);
const ANSI_ESCAPE_RE = new RegExp(`${ESC}\\[[0-9;]*[A-Za-z]`, 'g');

function stripControlCharacters(value) {
  let result = '';
  for (const char of value) {
    const code = char.charCodeAt(0);
    const isUnsupportedControl =
      (code >= 0x00 && code <= 0x08) ||
      code === 0x0B ||
      code === 0x0C ||
      (code >= 0x0E && code <= 0x1F) ||
      code === 0x7F;
    if (!isUnsupportedControl) {
      result += char;
    }
  }
  return result;
}

function sanitizeString(value) {
  return stripControlCharacters(
    value.replace(ANSI_ESCAPE_RE, '')
  ).replace(/```/g, '``\u2060`');
}

export function sanitizeForAgent(value, mode = 'basic') {
  if (!mode || mode === 'none') return value;
  if (mode !== 'basic') {
    throw new Error(`Unsupported sanitize mode: ${mode}`);
  }

  if (Array.isArray(value)) {
    return value.map(item => sanitizeForAgent(item, mode));
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, entryValue]) => [key, sanitizeForAgent(entryValue, mode)])
    );
  }

  if (typeof value === 'string') {
    return sanitizeString(value);
  }

  return value;
}
