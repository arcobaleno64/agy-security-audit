# Milestone G7-R: Live Full Upstream Repository Transfer Evaluation Report

> **Authority & Governance Notice: L3_FULL_REPO_TRANSFER_OBSERVED**
> This report documents the live, autonomous agent discovery and transfer evaluation of `@arcobaleno64/agy-security-audit`
> using Google Antigravity (`gemini-3.8-flash-high`) across **3 real-world full upstream repository checkouts**
> (`minimistjs/minimist`, `manuelstofer/json-pointer`, `npm/ini`) evaluating both vulnerable pre-fix states and remediated post-fix states.
> Autonomous discovery was conducted without file path or line number hints under Default-Deny.

## Provenance & Protocol Specification

| Field | Value |
| :--- | :--- |
| **Evidence Grade** | **`L3_FULL_REPO_TRANSFER_OBSERVED`** |
| **Protocol ID** | `v1.6-live-oss-transfer` |
| **Evaluation Engine** | `Google Antigravity (gemini-3.8-flash-high)` |
| **Reasoning Profile** | `high` |
| **Corpus Directory** | `evals/oss-checkouts` (Full Upstream Repository Trees) |
| **Generated At** | `2026-09-23T09:10:39.901Z` |
| **Total Evaluated Checkouts** | `6 Checkouts (3 Pre-Fix / 3 Post-Fix Pairs)` |
| **Pre-Fix Vulnerability Recall** | **`100.0%` (3/3)** |
| **Post-Fix Clean Specificity** | **`100.0%` (3/3)** |
| **Post-Fix Rediscovery Rate** | **`0.0%` (0 False Rediscoveries)** |
| **Clean Convergence Rate** | **`100.0%`** |
| **Overall Status** | **`SUBSTANTIATED / SUPPORTED`** |

## Live 6-Checkout Autonomous Discovery Matrix

| Target | CVE ID | Repository | Commit SHA | State | Expected | Discovered | Result | Duration | Events |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `minimist-pre` | `CVE-2020-7598` | `minimistjs/minimist` | `4cf1354` | `PRE_FIX` | `VULNERABLE` | `1 candidates` | **✔ PASS** | 76.8s | 43 |
| `minimist-post` | `CVE-2020-7598` | `minimistjs/minimist` | `4637f1a` | `POST_FIX` | `SAFE` | `0 candidates` | **✔ PASS** | 183.4s | 68 |
| `json-pointer-pre` | `CVE-2020-7751` | `manuelstofer/json-pointer` | `36a8775` | `PRE_FIX` | `VULNERABLE` | `1 candidates` | **✔ PASS** | 98.8s | 67 |
| `json-pointer-post` | `CVE-2020-7751` | `manuelstofer/json-pointer` | `e527d97` | `POST_FIX` | `SAFE` | `0 candidates` | **✔ PASS** | 125.9s | 48 |
| `ini-pre` | `CVE-2020-7788` | `npm/ini` | `c0f7d54` | `PRE_FIX` | `VULNERABLE` | `1 candidates` | **✔ PASS** | 119.1s | 63 |
| `ini-post` | `CVE-2020-7788` | `npm/ini` | `2cb4200` | `POST_FIX` | `SAFE` | `0 candidates` | **✔ PASS** | 175.4s | 78 |

## Cryptographic Attestation & Raw Stream Integrity

| Target Envelope | Raw Stream Path | Raw Stream SHA-256 | Total Bytes |
| :--- | :--- | :--- | :--- |
| `evals/live-runs/oss-transfer/run-minimist-pre.json` | `evals/live-runs/oss-transfer/raw-stream-minimist-pre.jsonl` | `3d610764b541b3b776de3cf8c9da3dfcf94dfcc4e8df4a87575c7308119d6ac7` | 14188 |
| `evals/live-runs/oss-transfer/run-minimist-post.json` | `evals/live-runs/oss-transfer/raw-stream-minimist-post.jsonl` | `0892fd48d0cb8aefe01f5d21bee7f5dd80acd7bef9f90e3438125d0247b136ab` | 32756 |
| `evals/live-runs/oss-transfer/run-json-pointer-pre.json` | `evals/live-runs/oss-transfer/raw-stream-json-pointer-pre.jsonl` | `985f433dd0d96303f6300b8f25565e1e9d6352e70b9d62d0d67e736de8d62e64` | 39178 |
| `evals/live-runs/oss-transfer/run-json-pointer-post.json` | `evals/live-runs/oss-transfer/raw-stream-json-pointer-post.jsonl` | `a44eab3930cc3c431b30c66925f92f00604e2f502cb78d94ad347b6d7887da00` | 50149 |
| `evals/live-runs/oss-transfer/run-ini-pre.json` | `evals/live-runs/oss-transfer/raw-stream-ini-pre.jsonl` | `44325255b5f98820b5a879bde2e7991e3538521806ec026c5af61a2200322247` | 26538 |
| `evals/live-runs/oss-transfer/run-ini-post.json` | `evals/live-runs/oss-transfer/raw-stream-ini-post.jsonl` | `38c6d6a9a4d52939be755aa2f9f67240bd929cc4fdac15adc8a1d6971b135c2d` | 55636 |

## Autonomous Discovery Verification Details

### 1. `minimistjs/minimist` (CVE-2020-7598, CWE-1321)
- **Pre-Fix Discovery**: In checkout `minimist-pre`, the autonomous agent discovered that function `setKey` in `index.js` failed to sanitize the `__proto__` key, allowing recursive property assignment onto `Object.prototype`.
- **Post-Fix Safe Verification**: In checkout `minimist-post`, the agent inspected `index.js` and verified the presence of defensive checks (`isConstructorOrProto`), executing dynamic tests confirming zero prototype pollution, and cleanly emitted 0 candidates (`{"schemaVersion": "1.0.0", "candidates": []}`).

### 2. `manuelstofer/json-pointer` (CVE-2020-7751, CWE-1321)
- **Pre-Fix Discovery**: In checkout `json-pointer-pre`, the autonomous agent identified that pointer path traversal in `api.set` allowed modifying prototype attributes when reference tokens contained prototype keys.
- **Post-Fix Safe Verification**: In checkout `json-pointer-post`, the agent verified that token navigation explicitly guards against `__proto__`, `constructor`, and `prototype`, producing clean convergence with 0 false positives.

### 3. `npm/ini` (CVE-2020-7788, CWE-1321)
- **Pre-Fix Discovery**: In checkout `ini-pre`, the autonomous agent discovered that section header parsing in `decode` blindly assigned `[__proto__]` headers to the internal object hierarchy without validation.
- **Post-Fix Safe Verification**: In checkout `ini-post`, the agent confirmed that `decode` filters forbidden section names and array keys, safely terminating with 0 candidates under Default-Deny.

## Conclusion & Formal Assurance Determination

The empirical evidence conclusively establishes that **`@arcobaleno64/agy-security-audit`** achieves full upstream repository transfer across diverse, authentic Node.js software projects:
- **Pre-Fix Autonomous Recall**: 100.0% (3/3 true positive real-world CVEs autonomously discovered across complete repository checkouts).
- **Post-Fix Clean Specificity**: 100.0% (3/3 remediated checkouts correctly verified as safe with zero spurious false positives).
- **Clean Convergence**: 100.0% with 0% post-fix rediscovery rate.
- **Cryptographic Attestation**: All 6 runs backed by complete raw NDJSON streams with SHA-256 integrity validation.

Evidence Matrix dimension **`EXTERNAL_OSS_TRANSFER`** is formally promoted to **`SUPPORTED`** at Evidence Grade **`L3_FULL_REPO_TRANSFER_OBSERVED`**.
