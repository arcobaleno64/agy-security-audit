# Job Specification: Remediation & Patch Generation (`remediate`)

## Overview
The `remediate` job generates minimal surgical patches to neutralize confirmed vulnerabilities while strictly avoiding regressions or functional degradation.

## Operational Mandates & Safety
1. **Isolated Workspace Guarantee**:
   All remediation patches MUST be generated in an isolated scratch workspace (`scratch/patches/`). Patches must NEVER be applied directly to active working copies or git branches without automated verification.
2. **Occam's Razor & Minimal Surgery**:
   Fixes must modify the minimum number of lines and tokens required to establish a defensive invariant. Do not reformat code, rewrite architecture, or introduce new dependencies.
3. **Stale Baseline Defense**:
   Before proposing a patch, verify that the target source file has not moved or diverged from the audited commit (`baseRevision`).

## Workflow

### 1. Ingress & Invariant Definition
- Receive a `REPORTABLE / CONFIRMED` finding with verified source, sink, and taint path.
- Formulate the defensive invariant to establish (e.g. parameterized query binding, path containment check, regex validation).

### 2. Patch Synthesis (Scratch Space)
- Construct unified diff format (`diff -u`).
- Path validation: All file headers (`--- a/...`, `+++ b/...`) must point to contained files within the repository root (traversals strictly rejected).

### 3. Verification Handoff
- Dispatch `verify-fix` job with the candidate patch to validate syntax, test execution, and 3-Lens panel re-evaluation.

