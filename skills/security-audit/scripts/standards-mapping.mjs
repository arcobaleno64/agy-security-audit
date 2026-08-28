/**
 * Standards Mapping Layer (R2-P1-01) & Dependency Boundary Detection (R2-P1-07)
 * Maps CWE weaknesses to OWASP ASVS 5.0.0, OWASP Top 10 2021, and NIST SSDF v1.1,
 * filtered according to repository applicability profiles.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const STANDARDS_DIR = path.resolve(__dirname, '../standards');
const STANDARDS_MAP_FILE = path.join(STANDARDS_DIR, 'standards-map.json');
const APPLICABILITY_FILE = path.join(STANDARDS_DIR, 'applicability-profiles.json');

let cachedStandardsMap = null;
let cachedProfiles = null;

function loadStandardsMap() {
  if (!cachedStandardsMap && fs.existsSync(STANDARDS_MAP_FILE)) {
    try {
      cachedStandardsMap = JSON.parse(fs.readFileSync(STANDARDS_MAP_FILE, 'utf8'));
    } catch {
      cachedStandardsMap = { mappings: {} };
    }
  }
  return cachedStandardsMap || { mappings: {} };
}

function loadApplicabilityProfiles() {
  if (!cachedProfiles && fs.existsSync(APPLICABILITY_FILE)) {
    try {
      cachedProfiles = JSON.parse(fs.readFileSync(APPLICABILITY_FILE, 'utf8'));
    } catch {
      cachedProfiles = { profiles: {} };
    }
  }
  return cachedProfiles || { profiles: {} };
}

/**
 * Extracts a canonical CWE identifier from rule ID or string (e.g. "CWE-89").
 */
export function extractCweId(identifier) {
  if (!identifier || typeof identifier !== 'string') return null;
  const match = identifier.match(/\bCWE[-_]?(\d+)\b/i);
  return match ? `CWE-${match[1]}` : null;
}

/**
 * Resolves comprehensive standards taxonomy mapping for a weakness under target profile.
 * Applies profile-aware filtering so non-web profiles (CLI, library, native) do not get ASVS.
 */
export function resolveStandardsMapping(ruleIdOrCwe, targetProfile = 'web-api') {
  const cweId = extractCweId(ruleIdOrCwe);
  const standardsData = loadStandardsMap();
  const profilesData = loadApplicabilityProfiles();

  const profileConfig = profilesData.profiles?.[targetProfile] || profilesData.profiles?.['web-api'] || {
    applicableStandards: ['CWE', 'NIST_SSDF_1_1']
  };

  const isAsvsApplicable = profileConfig.applicableStandards.includes('OWASP_ASVS_5_0');
  const isOwaspTop10Applicable = profileConfig.applicableStandards.includes('OWASP_TOP_10_2021');
  const isSsdfApplicable = profileConfig.applicableStandards.includes('NIST_SSDF_1_1');

  if (cweId && standardsData.mappings?.[cweId]) {
    const raw = standardsData.mappings[cweId];
    return {
      cwe: [cweId],
      securityProperty: raw.securityProperty || 'SECURITY_PROPERTY_UNSPECIFIED',
      asvs: isAsvsApplicable ? (raw.asvs || []) : [],
      owaspTop10: isOwaspTop10Applicable ? (raw.owaspTop10 || []) : [],
      ssdf: isSsdfApplicable ? (raw.ssdf || []) : []
    };
  }

  // Fallback if CWE is not in dictionary
  return {
    cwe: cweId ? [cweId] : [],
    securityProperty: 'SECURITY_PROPERTY_UNSPECIFIED',
    asvs: [],
    owaspTop10: [],
    ssdf: isSsdfApplicable ? ['PW.7.1'] : []
  };
}

/**
 * Inventories package manifests and lockfiles to establish the dependency boundary (R2-P1-07).
 */
export function detectDependencyBoundary(repoRoot = process.cwd()) {
  const knownManifests = [
    { file: 'package.json', ecosystem: 'npm', type: 'manifest' },
    { file: 'package-lock.json', ecosystem: 'npm', type: 'lockfile' },
    { file: 'pnpm-lock.yaml', ecosystem: 'pnpm', type: 'lockfile' },
    { file: 'yarn.lock', ecosystem: 'yarn', type: 'lockfile' },
    { file: 'Cargo.toml', ecosystem: 'cargo', type: 'manifest' },
    { file: 'Cargo.lock', ecosystem: 'cargo', type: 'lockfile' },
    { file: 'go.mod', ecosystem: 'go', type: 'manifest' },
    { file: 'go.sum', ecosystem: 'go', type: 'lockfile' },
    { file: 'requirements.txt', ecosystem: 'pip', type: 'manifest' },
    { file: 'pyproject.toml', ecosystem: 'python', type: 'manifest' },
    { file: 'poetry.lock', ecosystem: 'poetry', type: 'lockfile' },
    { file: 'Pipfile.lock', ecosystem: 'pipenv', type: 'lockfile' },
    { file: 'Gemfile', ecosystem: 'rubygems', type: 'manifest' },
    { file: 'Gemfile.lock', ecosystem: 'rubygems', type: 'lockfile' },
    { file: 'composer.json', ecosystem: 'composer', type: 'manifest' },
    { file: 'composer.lock', ecosystem: 'composer', type: 'lockfile' }
  ];

  const presentManifests = [];
  for (const item of knownManifests) {
    const fullPath = path.resolve(repoRoot, item.file);
    if (fs.existsSync(fullPath)) {
      presentManifests.push({ file: item.file, ecosystem: item.ecosystem, type: item.type, path: item.file });
    }
  }

  const hasLockfile = presentManifests.some(m => m.type === 'lockfile');

  return {
    hasDependencyEvidence: presentManifests.length > 0,
    hasLockfile,
    manifests: presentManifests,
    lockfiles: presentManifests.filter(m => m.type === 'lockfile'),
    count: presentManifests.length
  };
}
