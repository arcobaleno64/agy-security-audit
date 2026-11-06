# Safe Proof Policy & Finding Type Specification

Benchmark: NIST SP 800-218 (SSDF v1.1) PW.7 / PW.8 / RV.1 & OWASP SAMM 2

---

## 1. Finding Type Taxonomy (R2-P0-11)

To prevent finding pressure from inflating proactive defense-in-depth suggestions into synthetic High/Critical vulnerabilities, findings are strictly separated into three authoritative finding types:

| Finding Type | Definition | Release-Blocking / Reportability |
| :--- | :--- | :--- |
| `VULNERABILITY` | Authentic security property violation with reachable attack path and demonstrable blast radius (e.g. SQLi, RCE, IDOR, SSRF, Auth Bypass). | Eligible for `REPORTABLE` status upon unanimous 3-lens verifier consensus. |
| `HARDENING` | Proactive defense-in-depth improvement without an active, reachable vulnerability (e.g. rate-limiting, stricter CSP headers, additional logging, future misuse resistance). | **Non-blocking advisory**. Cannot be elevated to Critical or High vulnerability solely to manufacture findings. |
| `INFORMATIONAL` | Low-risk security observations, verbose error messages, or framework version disclosures without immediate security impact. | **Advisory note**. Non-blocking. |

### Presentation Separation in Reports
In all SARIF and Markdown outputs, findings are presented in separate sections:
1. **Validated Vulnerabilities (Reportable)**
2. **Advisory Hardening Opportunities**
3. **Informational Security Notes**
4. **Needs Manual Review (Deferred)**
5. **Affirmatively Refuted (Suppressed False Positives)**

---

## 2. Safe Defensive Proof Policy (R2-P0-12)

The `security-audit` plugin is an authorized, defensive assurance tool. It explicitly prohibits live offensive exploitation, destructive payloads, credential reuse, persistence, or unauthorized third-party probing.

### Approved Proof Mechanisms (`proofKind`)
Every finding and verifier ballot must indicate its proof mechanism:

| `proofKind` | Description | Validated Invariants |
| :--- | :--- | :--- |
| `STATIC_TRACE` | Source code dataflow or control flow path from untrusted source to sensitive sink. | Bounded within repository tree; verified line bounds. |
| `UNIT_TEST` | Deterministic unit test or property test demonstrating the flaw or verifying the fix. | Executed in sandboxed local test harness. |
| `BENIGN_REPRODUCTION` | Non-destructive proof of concept demonstrating control of execution flow. | Uses safe audit tokens (e.g. `echo BENIGN_AUDIT_TOKEN`). |
| `CONFIG_EVIDENCE` | Configuration file or manifest setting violating security baseline. | Verified against committed configuration file. |
| `DEPENDENCY_EVIDENCE` | Documented vulnerability in direct/transitive dependency manifest. | Verified against package lockfiles. |
| `EXTERNAL_SCANNER_EVIDENCE` | Corroborating output from deterministic external SAST or linter. | Ingested via standard SARIF/JSON adapter. |
| `MANUAL_ATTESTATION` | Signed review by authorized security engineer. | Recorded with reviewer attribution and cryptographic signature. |

### Prohibited Proof Activities (Fail-Closed Enforcement)
The finalizer deterministically rejects and downgrades any finding claiming or executing:
- **Live Exploitation**: `LIVE_EXPLOIT` or active external service compromise.
- **Destructive Commands**: `rm -rf`, `format`, `dd if=`, `mkfs`, `drop database`, `shutdown`.
- **External Exfiltration**: Probing external domains, webhook listeners (`burpcollaborator`, `oast`, etc.), or unauthenticated third-party network egress.
- **Credential Reuse**: Using discovered tokens against external live infrastructure.
- **Persistence**: Modifying system autostart, systemd units, cron tasks, or shell profiles.

### Safe PoC Standards
When demonstrating vulnerable control flow:
- **Command Injection**: Demonstrate control using harmless audit commands:
  ```bash
  echo BENIGN_AUDIT_TOKEN
  ```
- **SSRF**: Point to RFC 2606 / RFC 5737 reserved documentation ranges:
  ```text
  http://example.com
  http://192.0.2.1/test
  ```
- **Path Traversal**: Access benign project-local fixture files:
  ```text
  src/package.json
  ```
- **Authentication Bypass**: Exercise mocked local identities:
  ```text
  tenant-test-user-01
  ```
