# agy-security-audit (plugin ID: `security-audit`) v1.2.0

Evidence-backed, multi-stage security assurance and vulnerability verification plugin for **Google Antigravity (AGY)**, aligned with **NIST SSDF (SP 800-218)**, **OWASP ASVS 5.0.0**, **OWASP SAMM**, **CWE Taxonomy**, **CVSS v4.0**, and **SARIF 2.1.0**, incorporating defensive architectural concepts from frontier agent security frameworks including Anthropic's Claude Security and OpenAI's Codex Security research.

[繁體中文說明 →](README.zh-TW.md)

Companion project to [`agy-plugin-cc`](https://github.com/arcobaleno64/agy-plugin-cc): where `agy-plugin-cc` delegates review work from Claude Code to AGY as a cross-model reviewer, `agy-security-audit` is the security-assurance plugin that runs natively inside AGY itself.

## Foundational Axiom: Presumption of Non-Pass (Default-Deny on Authority Claims)

All authority claims (candidate findings, patch remediations, and coverage completeness) default to **`UNVERIFIED`**. An audited codebase is not presumed vulnerable; a review may legitimately produce zero candidates (zero findings, no quota pressure). A candidate cannot self-declare `CONFIRMED` or `REPORTABLE`; without verifier consensus, below quorum (< 2 votes), or with zero votes, it is strictly classified `DEFERRED` (`NEEDS_MANUAL_REVIEW`). When directory-accounting coverage is incomplete, the system strictly forbids declaring the codebase clean (Clean Claim Fail-Closed). A "Clean" declaration means no validated, unremediated substantive findings and no evidence gaps remain within declared scope — a bounded assurance, not an absolute, universal certification.

---

## Audit Intents & Convergence Semantics

1. **`DISCOVERY`**: Open-ended exploration across the component × vulnerability-family matrix, producing evidence-backed candidate hypotheses. No finding quota; zero findings is a legitimate, normal outcome.
2. **`VALIDATION`**: Independent 3-Lens panel review of specific candidates, deriving an authoritative disposition.
3. **`REGRESSION`**: Patch verification and coverage-convergence mode. Reruns re-examine only the attack surface affected by the change, preventing unbounded novelty hunting.

---

## Supported Job Contracts (Operational Job Modes)

1. **`scan`**: Full-codebase vulnerability scan under strict, deterministic Directory Accounting.
2. **`review`**: Incremental review of a git commit/PR diff, with 100% changed/deleted-file accounting and safe pre-image inspection of prior history.
3. **`validate`**: Independent verification of an existing finding report — checks a single candidate without a full repository rescan.
4. **`deep`**: Multi-Run Deep Scan — multiple randomized discovery passes deduplicated via a length-prefixed deterministic fingerprint, tracking `recurrenceCount`.
5. **`remediate`**: Generates a minimal, surgical patch inside an isolated `scratch/patches/` sandbox, protected by the Patch Jail perimeter.
6. **`verify-fix`**: Patch-verification contract combining the 3-Lens verifier panel (DEFENSES, REACHABILITY, IMPACT) with baseline-staleness detection (`detectStalePatch`), strictly guarding against regressions and backdoors.

---

## Conjunctive 3-Lens Verifier Panel

Uses conjunctive logic to prevent a 2-to-1 democratic vote from overriding a concrete technical fact:
- **Reachability Lens**: Verifies call-graph and taint-path reachability; a `REFUTES` verdict determines unreachability.
- **Defenses Lens**: Verifies sanitizers and security invariants; a refutation must cite a line number and evidence (`mitigationProofLine` + `mitigationReason`), blocking democratic override.
- **Impact Lens**: Verifies the CVSS v4 11-dimension vector and substantive harm; a refutation must prove no substantive harm.

---

## Directory Structure

```text
security-audit/
├── package.json                          # npm test, test:evals, test:semantic, test:discovery, test:stability, check:release (1.0.1)
├── plugin.json                           # Antigravity plugin manifest (with schema, no BOM)
├── hooks.json                            # Antigravity PreToolUse lifecycle hook registration
├── hooks/                                # Lifecycle hook implementations
│   └── shadow-context-guard.mjs          # PreToolUse transparent path rewrite to scratch/context/
├── SECURITY.md                           # Honest trust model and sandbox boundary disclosure
├── agents/                               # Dedicated subagent definitions (at plugin root)
│   ├── threat-modeler.md                 # Threat-modeling specialist
│   ├── discovery-agent.md                # 9x10 discovery matrix specialist
│   ├── verifier-reachability.md          # 3-Lens reachability verification specialist
│   ├── verifier-defenses.md              # 3-Lens defense-mechanism verification specialist
│   └── verifier-impact.md                # 3-Lens impact-calibration verification specialist
├── evals/                                # Test corpus and semantic benchmarks
│   ├── vulnerable/                       # 10 ground-truth vulnerabilities (True Positives)
│   ├── safe/                             # 10 patched-control defensive barriers (False Positive Guards)
│   ├── prompt-injection/                 # 5 prompt-injection penetration tests
│   ├── report-injection/                 # 5 report-poisoning and control-character tests
│   ├── secret-leak/                      # 5 credential-redaction tests
│   ├── coverage-gap/                     # 5 accounting-coverage boundary tests
│   ├── git-config/                       # 5 malicious git-config isolation tests
│   ├── patch-regression/                 # 5 malicious-patch and stale-baseline tests
│   └── semantic-benchmark/               # L1.5 disposition ground-truth benchmark (12 decision-invariant cases)
├── schemas/                              # R2-P1-08 versioned JSON Schemas (Draft-07)
│   ├── scan-manifest.schema.json         # Directory-accounting manifest schema
│   ├── threat-model.schema.json          # Threat-model schema
│   ├── candidate.schema.json             # Candidate-finding schema (Security Property & Lineage)
│   ├── verifier-ballot.schema.json       # Verifier-ballot schema (3-Lens evidence binding)
│   ├── canonical-finding.schema.json     # Canonical authoritative-finding schema (Taxonomy & Reason Code)
│   ├── execution-attestation.schema.json # Execution-attestation schema (stage-coverage completeness)
│   ├── audit-baseline.schema.json        # Audit-baseline schema (historical state baseline)
│   └── empirical-benchmark-run.schema.json # Empirical benchmark run envelope schema
├── rules/
│   └── AGENTS.md                         # Global zero-trust and data-review boundary rules
└── skills/
    └── security-audit/
        ├── SKILL.md                      # Primary skill entrypoint and workflow orchestration
        ├── standards/                    # R2-P1-01 standards-mapping layer
        │   ├── standards-map.json        # CWE -> ASVS 5.0 / SSDF / OWASP mapping
        │   └── applicability-profiles.json # Project-type applicability profiles
        ├── jobs/                         # 6 standard job contract specifications
        │   ├── scan.md                   # Full-repository accounting review contract
        │   ├── review.md                 # Diff and pre-image review contract
        │   ├── validate.md               # Independent finding-verification contract
        │   ├── deep.md                   # Multi-run randomized discovery and union contract
        │   ├── remediate.md              # Minimal surgical-patch generation contract
        │   └── verify-fix.md             # Patch verification and defense-invariant confirmation contract
        ├── references/
        │   ├── discovery.md              # 9-component × 10-vulnerability-family matrix
        │   ├── patching-jail.md          # Patch Jail perimeter specification
        │   ├── swarm-consensus.md        # 3-Lens conjunctive-consensus specification
        │   ├── threat-modeling.md        # Threat-modeling and 11-dimension vector baseline
        │   ├── verifier-protocol.md      # Verification protocol and evidence-binding invariants
        │   ├── finding-lineage.md        # Finding lineage tracking and fingerprinting architecture
        │   └── safe-proof-policy.md      # Safe defensive-proof policy and prohibited commands
        └── scripts/
            ├── path-containment.mjs      # Authoritative TCB path containment & TOCTOU-resistant atomic file reading
            ├── safe-git.mjs              # Hardened, isolated git-execution wrapper
            ├── finalize-scan.mjs         # Authoritative deterministic finalizer and standards integration
            ├── standards-mapping.mjs     # Industry-standards mapping and dependency-boundary detector
            ├── render-sarif.mjs          # SARIF 2.1.0 / Markdown rendering plus 114 invariant tests
            ├── build-inventory.mjs       # Ground-truth directory-accounting manifest generator
            ├── build-threat-model.mjs    # Deterministic threat-model generator
            ├── validate-attack-path.mjs  # Attack-path Schema 2.0 validation and proof-gap detection
            ├── validate-patch.mjs        # Patch-syntax, Patch Jail, staleness detection, and remediation verification
            ├── run-evals.mjs             # 50-case deterministic security-invariant and adversarial-regression suite
            ├── run-semantic-eval.mjs     # L1.5 disposition ground-truth benchmark suite
            ├── run-discovery-eval.mjs    # Agent discovery-evaluation suite (Simulated CI / Recorded Agent Run)
            ├── run-stability-eval.mjs    # Discovery-stability and multi-pass empirical benchmark
            ├── record-benchmark-run.mjs  # Recorded empirical benchmark protocol envelope recorder
            └── check-release-invariants.mjs # Section 24 release-invariant gate (55 files, 38 invariants)
```

---

## Testing & Release Verification

Run inside the project directory:
```bash
# Run the automated global security-invariant test suite:
npm test

# Run the 50-case deterministic security-invariant and adversarial-regression suite:
npm run test:evals

# Run the L1.5 disposition ground-truth benchmark (12 cases):
npm run test:semantic

# Run the agent discovery-evaluation benchmark (Simulated CI):
npm run test:discovery

# Run the stability benchmark (Synthetic Harness):
npm run test:stability

# Run the Section 24 release gate (verifies required specs, security invariants, and zero external dependencies):
npm run check:release
```

---

## Public Benchmark Claims Policy (R2-P2-02)

This tool strictly follows an honest-disclosure principle and makes no exaggerated or misleading claims:
- **No claim of "100% accuracy" or "provably free of vulnerabilities"**: a Clean review result means only that **defined coverage was completed within declared scope** and no reportable issue with verified evidence was found — not a universal security proof.
- **Test-corpus and benchmark-measurement transparency disclosure**:
  - **Deterministic security-invariant and adversarial-regression suite**: 50 cases (covering 8 boundary-threat classes), verifying deterministic rules and defensive boundaries (Invariant Rate: 100%).
  - **L1.5 disposition ground-truth benchmark**: 12 cases (8 vulnerable, 4 safe), evaluating the Finalizer's deterministic disposition logic — does not represent real-world LLM discovery rates.
  - **Agent discovery-evaluation harness**: ships 8 vulnerable ground-truth cases, verifying the evaluation pipeline via SIMULATED_CI; actual model discovery precision/recall is computed only once recorded agent candidates are supplied (`--candidates`); this release ships with no empirical model benchmark attached, so the public result is marked NOT MEASURED.
  - **Stability-evaluation harness**: synthetic mode verifies the lineage/Jaccard/convergence computation pipeline; empirical stability requires at least 2 sets of recorded model runs (`--runs-dir`); without recorded runs supplied, the public status is NOT MEASURED.

| Benchmark | Corpus | Measurement Type | Public Status |
| :--- | :--- | :--- | :--- |
| Deterministic Invariants | 50 cases (8 boundary-threat classes) | Deterministic rule measurement (MEASURED) | 100% PASS |
| Disposition Ground Truth | 12 cases (8 vulnerable / 4 safe) | Deterministic decision measurement (MEASURED) | 100% PASS |
| Discovery Harness | 8 vulnerable ground-truth cases | Synthetic pipeline self-test (SYNTHETIC PIPELINE TEST) | PASS (SIMULATED_CI) |
| Empirical Discovery | requires `--candidates` | Recorded model observation (RECORDED MODEL RUN) | NOT MEASURED (not attached) |
| Stability Harness | 3-corpus synthetic pass | Synthetic pipeline self-test (SYNTHETIC PIPELINE TEST) | PASS (SYNTHETIC_HARNESS) |
| Empirical Random Stability | requires `--runs-dir` | Recorded multi-run model observation (RECORDED MULTI-RUN) | NOT MEASURED (not attached) |

- **Model-agnostic architecture**: every agent contract is strictly specified via data schemas and JSON Schema; the orchestrator and adjudication core do not depend on any specific LLM's proprietary hidden behavior.

---

## Licensing & Governance (Defensive Use — R2-P2-07)

- This project is licensed under the **MIT License** (see [LICENSE](LICENSE)).
- **Project Scope & Defensive Use**: Intended and supported exclusively for authorized defensive security audits, vulnerability verification, and defensive R&D against codebases, local fixtures, or environments you are legitimately authorized to review. Not designed, intended, or supported for unauthorized penetration testing, exploitation, destructive actions, credential reuse, or non-consensual threat probing.
