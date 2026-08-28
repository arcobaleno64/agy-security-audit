# Finding Novelty, Lineage, and Fingerprint v2 Reference Specification

---

## 1. Dual-Fingerprint Architecture

To maintain cross-run convergence, tracking across code refactoring, and deterministic stability measurement, `security-audit` employs a dual-fingerprint architecture:

### 1.1 Exact Location Fingerprint (`locationFingerprint`)
- **Purpose**: Identifies the exact physical instance in a specific file revision at a specific line.
- **Components**: `length-prefixed(ruleId) + length-prefixed(normalizedRelativeUri) + startLine`
- **Formula**: `SHA-256(ruleId.length : ruleId : uri.length : uri : startLine)[0..32]`
- **Property**: Highly specific. Changes whenever code shifts or is reformatted.

### 1.2 Semantic Lineage Fingerprint (`lineageId`)
- **Purpose**: Identifies the conceptual vulnerability or security property violation across git revisions, code refactorings, and line shifts.
- **Components**:
  - `ruleId` (CWE ID or rule identifier)
  - Normalized relative file URI
  - Component name
  - Vulnerability family
  - Sink symbol / operation / function descriptor
- **Formula**: `SHA-256("L2" : ruleId.length : ruleId : uri.length : uri : component : family : symbol)[0..32]`
- **Property**: Line-shift invariant. When unrelated code is inserted or deleted above the vulnerability, the `lineageId` remains constant.

---

## 2. Finding Novelty State Machine

When a finding is emitted (especially in `REGRESSION` or rerun scans), its novelty relation to prior scans must be explicitly classified:

| Novelty State | Description | `whyNow` Required? | Affects Review Stability? |
| :--- | :--- | :---: | :---: |
| `NEW_SURFACE` | Finding discovered in newly added or modified code/surface. | No | No |
| `PREVIOUSLY_MISSED` | Finding existed in prior unchanged code but was not detected in earlier scan runs. | **YES** | **YES** (Degrades Stability Metric) |
| `FIX_INTRODUCED` | Finding was introduced by a recent fix or remediation attempt. | **YES** | No (Reflects patch regression) |
| `REFINEMENT` | Finding is a clearer, more precise reformulation of an existing finding. | No | No |
| `DUPLICATE` | Finding represents the same root cause already identified in another candidate. | No | No |
| `HARDENING` | Non-exploitable defense-in-depth or hygiene suggestion. | No | No |

### 2.1 Rationale Enforcement (`whyNow`)
If `novelty` is `FIX_INTRODUCED` or `PREVIOUSLY_MISSED`, the candidate must supply a non-empty `whyNow` rationale:
```json
{
  "lineage": {
    "novelty": "FIX_INTRODUCED",
    "whyNow": "The remediation patch in PR #42 replaced string concatenation with an unvalidated eval call.",
    "predecessorId": "SEC-8f3a12bc"
  }
}
```
Candidates lacking `whyNow` fail validation closed.

---

## 3. Cross-Run Deduplication & Convergence (`unionCandidates`)

When merging candidates across iterative scans or parallel discovery agents, `unionCandidates` resolves candidates by their semantic `lineageId`. 

- If a finding changes line number from 42 to 49 due to added imports or comments, but its `lineageId` is identical:
  1. It is recognized as the same continuous vulnerability lineage.
  2. `recurrenceCount` is incremented.
  3. `runsObserved` logs all run indexes.
  4. It does **not** count as an explosion of new findings or a failure of convergence.
