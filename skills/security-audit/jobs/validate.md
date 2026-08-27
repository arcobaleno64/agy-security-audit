# Job Specification: Standalone Vulnerability Validation (`validate`)

## Overview
The `validate` job decouples vulnerability verification from discovery. It accepts an externally supplied candidate vulnerability, finding JSON, or source-to-sink hypothesis, and dispatches the **Fixed 3-Lens Verifier Panel** to determine the definitive verdict without scanning the entire codebase.

## Workflow

### 1. Ingress & Containment
- Input: JSON file containing one or more candidate findings, or CLI parameters specifying `file`, `line`, and `cwe`.
- Validation: Ensure all target paths are contained within the repository root (rejecting traversal).
- Invariant: A candidate finding NEVER has authority over its own disposition.

### 2. Panel Dispatch (Fixed 3-Lens)
Dispatch 3 orthogonal verifiers concurrently:
1. **REACHABILITY Lens** (`agents/verifier-reachability.md`):
   - Confirms entrypoint controllability and unbroken data/control flow to sink.
2. **DEFENSES Lens** (`agents/verifier-defenses.md`):
   - Confirms absence or bypassability of sanitizers, validators, or type constraints.
   - If effective mitigation exists, must report `mitigationProofLine` and vote `REFUTES`.
3. **IMPACT Lens** (`agents/verifier-impact.md`):
   - Calibrates authentic blast radius, privilege boundary transgression, and CVSS v4 vector.

### 3. Verdict Derivation (Default-Deny)
- **Conjunctive Rule**:
  $$\text{CONFIRMED} \iff \text{Reachable} \land \neg\text{Defenses} \land \text{Impact}$$
- **Veto Rule**: If any lens decisively refutes (unreachable, mitigated, or zero harm), the finding is suppressed as `FALSE_POSITIVE`.
- **Proof-Gap Tracking**: If dataflow cannot be proven at any intermediate hop, record explicit `proofGaps` and defer to `NEEDS_MANUAL_REVIEW`.

### 4. Output Generation
Outputs canonical SARIF 2.1.0 and Markdown validation report certifying the target candidate.

