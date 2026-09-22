/**
 * Remediated slice of lodash (CVE-2020-28500)
 * Fixed in lodash 4.17.21 by replacing regex with index-based loop trimming.
 */
function trimmedEnd(string) {
  let index = string.length;
  while (index-- && string.charCodeAt(index) <= 32) {}
  return string.slice(0, index + 1);
}

function trimmedStart(string) {
  let index = -1;
  const length = string.length;
  while (++index < length && string.charCodeAt(index) <= 32) {}
  return string.slice(index);
}

export function toNumber(value) {
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string') {
    const trimmed = trimmedStart(trimmedEnd(value));
    return parseFloat(trimmed);
  }
  return Number(value);
}
