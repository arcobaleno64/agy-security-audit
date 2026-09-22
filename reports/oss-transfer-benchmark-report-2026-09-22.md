# Milestone G7: Real-World CVE-Derived Curated Fixture Evaluation Report

> **Authority & Governance Notice: CURATED_EXTERNAL_ORIGIN_FIXTURE_VALIDATION**
> This report documents the deterministic finalizer disposition logic verification of `@arcobaleno64/agy-security-audit`
> across **6 real-world CVE-derived curated fixture slices** from popular Node.js/JavaScript libraries.
> **Scope Clarification**: This benchmark evaluates deterministic finalizer disposition logic on extracted single-file slices
> (`evals/oss-corpus/pre-fix/*.js` and `post-fix/*.js`) with synthetic 3-lens ballots, and **does NOT constitute live agent discovery over full upstream git repository checkouts**.

## Provenance & Protocol Specification

| Field | Value |
| :--- | :--- |
| **Evidence Grade** | **`CURATED_EXTERNAL_ORIGIN_FIXTURE_VALIDATION`** |
| **Protocol ID** | `v1.6-curated-oss-fixture` |
| **Evaluation Mode** | `CURATED_EXTERNAL_ORIGIN_FIXTURE_VALIDATION` |
| **Corpus Directory** | `evals/oss-corpus` |
| **Generated At** | `2026-09-22T15:10:08.696Z` |
| **Total Evaluated Pairs** | `6 Paired CVEs (12 Total Fixtures)` |
| **Pre-Fix Vulnerability Recall** | **`100.0%` (6/6)** |
| **Post-Fix Clean Specificity** | **`100.0%` (6/6)** |
| **Post-Fix Rediscovery Rate** | **`0.0%` (0 False Rediscoveries)** |
| **Clean Convergence Rate** | **`100.0%`** |
| **Patch Jail Compliance Rate** | **`100.0%`** |
| **Status** | **`CONVERGED_FIXTURE_VALIDATION_ESTABLISHED`** |

## Uncompressed 6-CVE External Transfer Matrix

| ID | CVE ID | Repository | CWE | Pre/Post State | Expected | Evaluated | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `OSS-01` | `CVE-2020-7598` | `minimistjs/minimist` | `CWE-1321` | `PRE_FIX` | `VULNERABLE` | `REPORTABLE` | **✔ PASS** |
| `OSS-02` | `CVE-2020-28500` | `lodash/lodash` | `CWE-1333` | `PRE_FIX` | `VULNERABLE` | `REPORTABLE` | **✔ PASS** |
| `OSS-03` | `CVE-2020-7751` | `manuelstofer/json-pointer` | `CWE-1321` | `PRE_FIX` | `VULNERABLE` | `REPORTABLE` | **✔ PASS** |
| `OSS-04` | `CVE-2021-32803` | `npm/node-tar` | `CWE-22` | `PRE_FIX` | `VULNERABLE` | `REPORTABLE` | **✔ PASS** |
| `OSS-05` | `CVE-2020-28168` | `axios/axios` | `CWE-918` | `PRE_FIX` | `VULNERABLE` | `REPORTABLE` | **✔ PASS** |
| `OSS-06` | `CVE-2020-7788` | `npm/ini` | `CWE-1321` | `PRE_FIX` | `VULNERABLE` | `REPORTABLE` | **✔ PASS** |
| `OSS-01-FIX` | `CVE-2020-7598` | `minimistjs/minimist` | `CWE-1321` | `POST_FIX` | `SAFE` | `SUPPRESSED` | **✔ PASS** |
| `OSS-02-FIX` | `CVE-2020-28500` | `lodash/lodash` | `CWE-1333` | `POST_FIX` | `SAFE` | `SUPPRESSED` | **✔ PASS** |
| `OSS-03-FIX` | `CVE-2020-7751` | `manuelstofer/json-pointer` | `CWE-1321` | `POST_FIX` | `SAFE` | `SUPPRESSED` | **✔ PASS** |
| `OSS-04-FIX` | `CVE-2021-32803` | `npm/node-tar` | `CWE-22` | `POST_FIX` | `SAFE` | `SUPPRESSED` | **✔ PASS** |
| `OSS-05-FIX` | `CVE-2020-28168` | `axios/axios` | `CWE-918` | `POST_FIX` | `SAFE` | `SUPPRESSED` | **✔ PASS** |
| `OSS-06-FIX` | `CVE-2020-7788` | `npm/ini` | `CWE-1321` | `POST_FIX` | `SAFE` | `SUPPRESSED` | **✔ PASS** |

## Patch Jail Perimeter & Syntax Verification

| Diff File | Targeted Files | Single-File Confinement | CI/CD Manifest Safe | Patch Jail Status |
| :--- | :--- | :--- | :--- | :--- |
| `01-minimist-fix.diff` | `evals/oss-corpus/01-minimist-prototype-pollution.js` | ✔ YES | ✔ SAFE | **✔ COMPLIANT** |
| `02-lodash-fix.diff` | `evals/oss-corpus/02-lodash-redos.js` | ✔ YES | ✔ SAFE | **✔ COMPLIANT** |
| `03-json-pointer-fix.diff` | `evals/oss-corpus/03-json-pointer-prototype-pollution.js` | ✔ YES | ✔ SAFE | **✔ COMPLIANT** |
| `04-tar-fix.diff` | `evals/oss-corpus/04-tar-path-traversal.js` | ✔ YES | ✔ SAFE | **✔ COMPLIANT** |
| `05-axios-fix.diff` | `evals/oss-corpus/05-axios-ssrf-header-leak.js` | ✔ YES | ✔ SAFE | **✔ COMPLIANT** |
| `06-ini-fix.diff` | `evals/oss-corpus/06-ini-prototype-pollution.js` | ✔ YES | ✔ SAFE | **✔ COMPLIANT** |

## Curated OSS CVE Catalog & Remediation Mechanisms

1. **`minimist` (CVE-2020-7598, CWE-1321)**:
   - **Flaw**: CLI flag parser assigned nested object keys without checking for `__proto__`, allowing arbitrary property injection onto `Object.prototype`.
   - **Fix**: Official patch in `1.2.2` adds explicit early return when `key === '__proto__'`.

2. **`lodash` (CVE-2020-28500, CWE-1333)**:
   - **Flaw**: `toNumber` invoked regular expression `/^\s+|\s+$/g` on untrusted inputs, resulting in catastrophic backtracking when presented with long whitespace sequences.
   - **Fix**: Official patch in `4.17.21` replaces regular expression trimming with deterministic index character scanning.

3. **`json-pointer` (CVE-2020-7751, CWE-1321)**:
   - **Flaw**: Property path resolution in `set()` evaluated segments without prototype guardrails.
   - **Fix**: Official patch in `0.6.1` rejects `__proto__`, `constructor`, and `prototype` path segments.

4. **`node-tar` (CVE-2021-32803, CWE-22)**:
   - **Flaw**: Tar extraction routine failed to assert strict directory containment on archive entries containing relative traversal or drive specifiers.
   - **Fix**: Official patch in `6.1.2` enforces strict path relative containment verification against destination directory.

5. **`axios` (CVE-2020-28168, CWE-918)**:
   - **Flaw**: HTTP adapter forwarded `Authorization` and `Cookie` headers unconditionally when following redirects across different origins.
   - **Fix**: Official patch in `0.21.1` compares URL origins and strips sensitive credential headers upon cross-origin redirects.

6. **`ini` (CVE-2020-7788, CWE-1321)**:
   - **Flaw**: Ini file section parser blindly assigned section headers like `[__proto__]` to internal property tree.
   - **Fix**: Official patch in `1.3.6` filters out dangerous prototype keys before section node creation.

## Conclusion & Formal Assurance Determination

The evidence confirms that **`@arcobaleno64/agy-security-audit`** successfully validates deterministic disposition logic across curated real-world CVE-derived fixture slices:
- **Pre-Fix Vulnerability Recall**: 100.0% (6/6 real-world vulnerabilities detected and validated via canonical ballots).
- **Post-Fix Clean Convergence**: 100.0% (6/6 remediations recognized with 0% post-fix rediscovery).
- **Patch Jail Integrity**: 100.0% (all 6 official diffs adhere strictly to single-file confinement and non-tampering invariants).

Milestone G7 is formally **VERIFIED** at Evidence Grade **`CURATED_EXTERNAL_ORIGIN_FIXTURE_VALIDATION`** (`Real-World CVE-Derived Curated Fixture Evaluation`). Full upstream git repository transfer remains designated as **REOPENED / unverified** pending contemporaneous live repository discovery.
