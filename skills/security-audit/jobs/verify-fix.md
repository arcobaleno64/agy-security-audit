# Job Specification: Fix Verification (`verify-fix`)

## Overview
The `verify-fix` job automates the rigorous verification of candidate remediation patches, ensuring that the target vulnerability is neutralized under the Presumption of Non-Pass without introducing secondary vulnerabilities or build regressions.

## Workflow

### 1. Patch Syntax & Safety Check
- Invoke `scripts/validate-patch.mjs` on the proposed patch diff.
- Validate:
  - Unified diff format conforms to standard syntax.
  - Path traversal defense: all modified files exist within repository root.
  - Patch applies cleanly to target files (`git apply --check`).
  - Stale detection: target files have not been modified since baseline scan.

### 2. Sandbox Application
- Apply the patch into a temporary sandbox branch or staging directory.
- Never modify the user's active working tree during verification.

### 3. Automated Test Execution
- Run existing repository tests (`npm test`, `cargo test`, `pytest`, etc.).
- Ensure 100% of test suites pass without regressions.

### 4. 3-Lens Panel Re-evaluation
- Dispatch the complete 3-Lens Verifier Panel against the patched code:
  - **DEFENSES Lens**: Must vote `REFUTES` with explicit `mitigationProofLine` and `mitigationReason` establishing the defensive barrier.
  - **REACHABILITY Lens**: Must vote `REFUTES` confirming the attack path no longer reaches the vulnerable sink.
  - **IMPACT Lens**: Must vote `REFUTES` confirming security consequence is unobtainable or neutralized.
- **Default-Deny Invariant**: All 3 lenses are strictly required (`DEFENSES`, `REACHABILITY`, `IMPACT`). Missing votes fail verification fail-closed (silence != approval). A patch is certified ONLY when all 3 lenses confirm the finding is neutralized without dissent.


