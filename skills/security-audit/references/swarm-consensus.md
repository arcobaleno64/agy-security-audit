# Elastic Subagent Swarm & Consensus Voting Protocol

## 1. Presumption of Non-Pass (Default-Deny Engine)

The consensus engine operates strictly under the **Default-Deny** axiom:
- **Null Hypothesis**: Every candidate risk or audited component defaults to `NON_PASS / UNVERIFIED`.
- **Burden of Proof**: The burden of proof rests entirely on the party asserting safety or refutation. A finding cannot be dismissed as `FALSE_POSITIVE` without an affirmative, reproducible proof of mitigation (exact code line and barrier mechanism).
- **Fallback on Deadlock**: If consensus cannot be achieved, or if subagents time out, the finding automatically falls back to `NON_PASS / NEEDS_MANUAL_REVIEW`.

---

## 2. Elastic Sliding Worker Pool & Quota Throttling

To fulfill the user's intent of an "unbounded subagent pool" without causing local OS thread exhaustion or API 429 rate limit cascades, subagent execution is abstracted into an **Elastic Task Queue with a Sliding Concurrency Window**:

```
[Finding Candidates Queue]
        │
        ▼ (Concurrency Window: W = 3..6 workers)
[Subagent Worker 1] [Subagent Worker 2] [Subagent Worker 3] ... [Worker N]
        │
        ▼ (AIMD Rate Limiter: Halve W on 429, increment W on clean batch)
[Private Ballot Store: scratch/votes/{finding_id}/ballot_{uuid}.json]
```

### AIMD Throttle Specifications
- **Concurrency Range**: $W_{\text{active}} \in [3, 6]$, absolute ceiling 8.
- **AIMD Rules**:
  - On API 429 / ResourceExhausted: $W \leftarrow \max(2, \lfloor W / 2 \rfloor)$, sleep with exponential backoff + full jitter.
  - On consecutive successful batches without rate errors: $W \leftarrow \min(6, W + 1)$.
- **Token Budget Guardrail**: Maximum 300k tokens per single finding verification pass.

---

## 3. Double-Blind Private Ballot Protocol

To eliminate Cascading Hallucinations and Conformity Bias, reviewers must never see each other's reasoning or scores.

### Private Ballot Channels
1. The coordinator dispatches independent verification tasks via `invoke_subagent`.
2. Each subagent writes its completed vote to a dedicated, unguessable file path:
   `scratch/votes/{finding_id}/ballot_{uuid}.json`
3. Subagents are given read access **only** to the source code and candidate coordinate, strictly prohibited from inspecting `scratch/votes/`.

---

## 4. Four Cognitive Diversity Personas

To prevent Sybil collapse and shared model blindspots, reviewer subagents are assigned distinct, orthogonal personas:

### Persona 1: The Exploit Hacker (Offensive / Penetration)
- **Role System Prompt**:
  > You are an offensive exploit researcher. Your sole objective is to prove that untrusted input from the entry source can reach the vulnerable sink without being effectively neutralized. Disregard comments, docstrings, or assumed frameworks. Seek any viable character escaping bypass, type confusion, or injection gadget.

### Persona 2: The Paranoiac Defense Architect (Boundary / Evasion)
- **Role System Prompt**:
  > You are a paranoid defensive security architect. Even if a sanitizer or validation check exists, assume it can be bypassed under edge-case inputs (e.g., ReDoS, Unicode normalization collisions, null-byte truncations, double-encoding, case folding). Identify gaps where the sanitizer fails to cover the entire input domain.

### Persona 3: The Logic & State Auditor (State Machine / Business Logic)
- **Role System Prompt**:
  > You are a distributed systems and business logic auditor. Focus entirely on timing, authorization state machines, IDOR, race conditions (TOCTOU), double-spend, and missing access control barriers across multi-step execution flows.

### Persona 4: The Language Specification Formalist (Semantics & Spec)
- **Role System Prompt**:
  > You are a programming language specification specialist. Focus on language-level edge cases: JavaScript prototype pollution, Python variable scope leakage, C# type conversion quirks, dynamic attribute lookups, and compiler/runtime specific vulnerabilities.

---

## 5. Consensus Scoring & Minority Escalation

### Ballot Schema
```json
{
  "findingId": "SEC-001",
  "persona": "ExploitHacker",
  "verdict": "CONFIRMED | NEEDS_MANUAL_REVIEW | FALSE_POSITIVE",
  "confidence": 0.85,
  "concreteTaintPath": "Source (req.query.id, line 10) -> sanitizedId (line 12, regex bypassable) -> db.query (line 25)",
  "mitigationProofLine": null,
  "nonce": "X-NONCE-38f9b2"
}
```

### Table of Verdict Rules
1. **`CONFIRMED`** (Vulnerability Proven):
   - Confidence-weighted score $\ge 67\%$ (2/3 supermajority).
   - Must include a concrete, non-empty taint flow pathway.
2. **`FALSE_POSITIVE`** (Affirmatively Refuted):
   - Confidence-weighted score $\ge 75\%$ (3/4 supermajority).
   - **Mandatory Rebuttal**: Must explicitly cite the exact file and line number where mitigation occurs, and prove that the input domain is fully contained. Without this proof, confidence is capped at 0.2.
3. **`MINORITY ESCALATION`** (Anti-Groupthink Override):
   - If any specialist persona produces an unrefuted, verifiable taint path with confidence $\ge 0.80$, the finding **CANNOT** be dismissed by the majority. It is automatically escalated to `NEEDS_MANUAL_REVIEW` (or referred to a `Model: "pro"` Chief Adjudicator).
4. **`NEEDS_MANUAL_REVIEW`** (Presumption of Non-Pass):
   - Default for all split decisions, lack of quorum, low confidence, or timeouts.

---

## 6. Deadman Watchdog & Quorum Degraded Finalization

1. **Watchdog Timer**:
   - Coordinator sets a watchdog timer via `schedule(DurationSeconds=180, Prompt="Watchdog: Subagent batch timeout")`.
   - On completion, the timer task is cancelled immediately.
2. **Quorum Threshold**:
   - Minimum quorum: $Q_{\min} = \max(2, \lceil N \times 0.6 \rceil)$ (at least 60% ballots returned).
   - If $N_{\text{valid}} \ge Q_{\min}$: Finalize vote with `DEGRADED_QUORUM` annotation.
   - If $N_{\text{valid}} < Q_{\min}$: Vote is invalidated; status immediately sealed as `NEEDS_MANUAL_REVIEW (INSUFFICIENT_QUORUM)`.
