# Changelog

All notable changes to `@arcobaleno64/agy-security-audit` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.10.0] - 2026-11-05

### Landmark Milestone 5.3 & Phase B-5 Baseline Freeze Release
This milestone release culminates the 112-round Milestone 5.3 Phase B-5 independent security assurance review under Default-Deny, introducing OS-isolated replica containers, double-blind 3-lens consensus, cryptographic anti-rollback journals, and a hardened shadow execution context.

### Added
- **Stage 5: Isolated Replica View (IRV) & Preflight Replay Verification**:
  - Linux Bubblewrap (`bwrap`) container isolation running under unprivileged UID 1000 with unshared User, Mount, and Network namespaces.
  - Disposable tmpfs projections (`/tmp/irv-...`) with synthetic outbound canary socket blocks and verified zero host filesystem mutation.
  - Three-Phase Automated Preflight Verifier (`verify-third-party-preflight.mjs`) for baseline hash auditing, Ed25519 anti-rollback journal verification, and post-cleanup mount leak audits.
- **Fixed 3-Lens Double-Blind Consensus Verification**:
  - Independent verification panel comprising `REACHABILITY`, `DEFENSES`, and `IMPACT` lenses.
  - Symmetrical conjunction voting rule: Decisive refutations (e.g. proof of sanitization or unreachable sink) suppress candidates under Default-Deny; defenses cannot be outvoted 2-to-1.
- **Dual-Key Cryptographic Anti-Rollback Journal & Checkpoint Engine**:
  - Dual Ed25519 signature chain: Genesis Line 1 signed by Supervisor v1, Sequence 2 Recovery signed by Supervisor v2 (`bfa8a29c...`).
  - Strict SHA-256 hash chaining linking Genesis raw bytes to Sequence 2 `prevRecordDigest`.
  - Checkpoint state anchor binding `checkpointSequenceFloor = 2` and persistent watermark monotonic recovery state machines.
- **Hardened Shadow Context PreToolUse Guard & Subprocess Contract**:
  - Subprocess Calling Contract enforcement: Non-blocking stdin, CRLF sanitization, and protocol payload validation.
  - TOCTOU-resistant atomic file reads, path traversal containment barriers, and symlink boundary enforcement.
- **121 Automated Security Invariants**:
  - 100% pass rate (121/121) across render-sarif, CVSS v4.0 scoring, Directory Accounting reconciliation, real agent discovery evaluation, and L1.5 ground-truth disposition benchmarks.
- **Antigravity CLI Plugin Specification Conformance**:
  - Updated `plugin.json` with display metadata, logo, and proactive prompt workflows.

### Changed
- **Architectural Shift from Dynamic Reflection to Static Schema Validation**:
  - Abolished runtime dynamic prototype inspection (`walkOptionsDeep`) in favor of immutable frozen prototype baselines and strict JSON Schema Draft-07 validation.
- **Delivery Packaging Discipline (`CORE_REPACKAGING_CESSATION`)**:
  - Mandated core package freezing to prevent binary hash drift during documentation and errata corrections.
- **Updated Evaluation Corpus**:
  - Augmented `evals/external-validity-corpus.json` with real-world CVE reproductions for path traversal, prototype pollution, and command injection.

### Security
- **Root Trust Anchor Rotation & Key Custody Policy**:
  - Remediated root key exposure (`B5-R43-F01`), rotated trust anchor to v2 key (`COLLECTOR-KEY-2026-V1`), and codified 4 non-negotiable governance invariants (0 ACL mutations, 0 private key access, 0 unmanaged test re-runs, Phase B-6 unauthorized).
- **Default-Deny Authority Claims**:
  - All candidate findings, remediation patches, and test coverage claims are treated as unverified by default until confirmed by affirmative multi-lens evidence.

---

## [1.9.2] - 2026-10-18
- Addressed external validity evaluation protocols and RFC 0003 empirical validation harness.

## [1.9.1] - 2026-10-17
- Added runtime confinement benchmark matrices and verified Bubblewrap isolation contracts.

## [1.9.0] - 2026-10-15
- Implemented Isolated Replica View (IRV) prototype and supervisor key custody policies.

## [1.8.1] - 2026-09-24
- Added consumer provenance verification guide and SLSA Build Level 2 transparency logs.
