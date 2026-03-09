function getPathValue(value, segments) {
  let cursor = value;
  for (const segment of segments) {
    if (cursor == null || typeof cursor !== 'object') {
      return undefined;
    }
    cursor = cursor[segment];
  }
  return cursor;
}

function setPathValue(target, segments, value) {
  let cursor = target;
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (index === segments.length - 1) {
      cursor[segment] = value;
      return;
    }
    if (!cursor[segment] || typeof cursor[segment] !== 'object' || Array.isArray(cursor[segment])) {
      cursor[segment] = {};
    }
    cursor = cursor[segment];
  }
}

export function parseFieldMask(rawValue) {
  if (!rawValue) return null;
  const fields = rawValue
    .split(',')
    .map(field => field.trim())
    .filter(Boolean);
  return fields.length > 0 ? fields : null;
}

export function applyFieldMask(value, fields) {
  if (!fields || fields.length === 0) return value;
  if (Array.isArray(value)) return value.map(item => applyFieldMask(item, fields));
  if (value == null || typeof value !== 'object') return value;

  const result = {};
  for (const field of fields) {
    const segments = field.split('.').filter(Boolean);
    if (segments.length === 0) continue;
    const fieldValue = getPathValue(value, segments);
    if (fieldValue !== undefined) {
      setPathValue(result, segments, fieldValue);
    }
  }
  return result;
}
