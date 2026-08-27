# Job Specification: `review` (Diff Security Review)

## 1. Objective & Baseline
Modeled after Anthropic `/security-review`, the `review` job is specialized for pull requests, branch differences, and working-tree diffs.
Its core objectives are:
- **Maximum Precision & Minimal Noise**: Report only high-confidence, actionable vulnerabilities introduced or modified by the change.
- **Zero Full-Repo Bloat**: Restrict inspection strictly to changed files and minimal necessary context.
- **No Runtime Exploitation**: Focus on static taint propagation, source-to-sink flow, and security-sensitive behavioral diffs without requiring sandbox execution.

---

## 2. Review Invariants
1. **100% Changed File Accounting**:
   - Every modified, added, renamed, or deleted file identified in the Git diff must be explicitly accounted for in the inventory ledger.
   - For deleted files, the pre-image at the baseline revision must be inspected to ensure security controls (e.g. auth middleware, CSRF barriers) were not inadvertently removed.
2. **Behavior-Preserving Context**:
   - Supporting files outside the diff may only be read to inspect:
     - Direct callers/callees of changed functions.
     - Auth guards, validation middleware, and framework route definitions.
     - Type definitions and data models directly bound to changed arguments.
3. **High Signal Filtering**:
   - Low-confidence heuristic findings, pre-existing untouched issues, and stylistic/linter suggestions are excluded from the main report.
   - Any disputed or unproven finding is categorized as `DEFERRED` and kept out of blocking output.

---

## 3. Execution Pipeline
```text
[Git Working Diff / PR Ref]
           │
           ▼
[safe-git: Extract Changed & Deleted Files]
           │
           ▼
[build-inventory: Generate review-manifest.json]
           │
           ▼
[Targeted Diff Semantic Review & Taint Tracing]
           │
           ▼
[3-Lens Verifier Panel: Reachability, Defenses, Impact]
           │
           ▼
[finalize-scan: Canonical Findings & High-Signal Report]
```

