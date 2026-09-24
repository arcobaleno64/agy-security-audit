# External Reproduction Kit (Track D Skeleton)

> **Governing Specification**: [RFC 0002: Track D - External Reproducibility, Real-World Transfer & Adoption Readiness](../rfcs/0002-external-reproducibility-and-adoption-readiness.md)  
> **Status**: ACTIVE / IMPLEMENTATION (v1.9.0 Target)  
> **Frozen Baseline**: `agy-security-audit v1.8.1` (`8af4bca5cdfef89c93649c03a70d43767875ffb7`)

---

## 1. Overview

This directory provides the authoritative, self-contained kit for unfamiliar operators to independently install, inspect, execute, and verify `agy-security-audit` claims without maintainer intervention.

Under Track D's **Multi-Axis Independence Model**, an external reproduction must be:
- **Clean-room**: Executed in a disposable or clean environment without unpublished author artifacts.
- **Autonomous**: Executed with zero maintainer assistance (any assistance is recorded and downgrades evidence to usability feedback).
- **Verifiable**: Emits a cryptographic reproduction record matching `schemas/reproduction-record.schema.json`.

---

## 2. Reproduction Tiers (Roadmap)

### Tier 1: Deterministic Reproduction (Offline & Fast)
- **Prerequisites**: Node.js `>= 20.0.0`, Git `>= 2.30.0`.
- **Zero Dependencies**: Requires no `npm install` and zero external npm packages.
- **Verification Steps**:
  1. Clone clean tag or extract published release archive.
  2. Run preflight environment check: `npm run doctor`
  3. Verify release provenance: `node scripts/verify-release-provenance.mjs`
  4. Verify Section 24 invariant suite: `npm test` (121/121 PASS)
  5. Verify documentation integrity: `npm run check:docs`
  6. Verify release invariants gate: `npm run check:release`

### Tier 2: Live Assurance Reproduction (Authentic LLM Execution)
- **Prerequisites**: Antigravity CLI (`agy`) `>= 1.2.0`, supported LLM credentials.
- **Frozen Micro-Corpus**:
  1. `quickstart-vulnerable`: Known true-positive security flaw.
  2. `quickstart-safe`: Known false-positive defense control.
  3. `quickstart-disputed`: Non-trivial architectural tradeoff.
- **Verification Steps**:
  1. Execute controlled live scan under Default-Deny.
  2. Retain raw stream NDJSON and runtime attestation.
  3. Emit structured `reproduction-record.json`.

---

## 3. Submitting an Independent Reproduction

Once Track D implementation is complete in `v1.9.0`:
1. Execute the reproduction protocol autonomously.
2. Record execution environment, commands, and resulting artifact hashes.
3. Submit the resulting `reproduction-record.json` via a GitHub issue or discussion for maintainer adjudication.
