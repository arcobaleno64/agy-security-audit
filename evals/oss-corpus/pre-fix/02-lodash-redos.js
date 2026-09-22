/**
 * Authentic slice of lodash (CVE-2020-28500)
 * ReDoS in lodash before 4.17.21 via whitespace trimming regex.
 */
const reTrim = /^\s+|\s+$/g;

export function toNumber(value) {
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string') {
    // Vulnerable: catastrophic backtracking when value ends with many spaces
    const trimmed = value.replace(reTrim, '');
    return parseFloat(trimmed);
  }
  return Number(value);
}
