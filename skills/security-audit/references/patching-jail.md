# Patch Jail & Dual-Track Remediation Specification

## 1. Presumption of Non-Pass for Patches

Every candidate remediation patch is presumed **`UNPASSED / REJECTED`** by default.
A patch is certified and presented to the user **ONLY IF** it affirmatively satisfies the **Triple Guarantee**:
1. **Targeted Resolution**: Directly eliminates the vulnerability sink/source flow identified in the finding.
2. **Zero Side-Effects**: Introduces no new vulnerability, compiler error, or lint violation.
3. **Behavioral Invariant**: Leaves intended application behavior unchanged for all valid non-malicious inputs.

---

## 2. Patch Jail Constraints (Anti-Backdoor Perimeter)

To prevent supply chain poisoning, Trojan Source attacks, and malicious config overwrites, proposed patches are strictly confined within the **Patch Jail**:

### Strict Jail Rules
1. **Single-File Confinement**: A patch may **ONLY** modify the specific file that contains the vulnerable code. It is strictly forbidden to touch adjacent files.
2. **No New Files**: The patch must never introduce new files (no `new file mode` in diff).
3. **No Root / CI/CD Tampering**:
   - Strictly forbidden from modifying `.github/`, `.gitlab-ci.yml`, `.circleci/`, or Dockerfiles.
   - Strictly forbidden from modifying package manifests (`package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`).
   - Strictly forbidden from modifying root `.gitignore` or `.git/`.
4. **No Path Traversal**: Diff headers containing relative traversals (e.g. `+++ b/../../`) are immediately rejected.
5. **Unicode Bidi Filtering (CVE-2021-42574)**:
   - Patches are scanned for invisible Bidirectional Unicode control characters (e.g. `U+202A` through `U+202E`, `U+2066` through `U+2069`). Any diff containing these characters is rejected.

---

## 3. Dual-Track Delivery Format

Because LLMs can occasionally miscalculate unified diff chunk line offsets (`@@ -start,len +start,len @@`), all remediation advice must be delivered via **Dual-Track**:

### Track A: Validated Unified Diff (`patches/F{N}.patch`)
A standard unified diff saved to disk that developer tooling can apply via:
```bash
git apply patches/F01.patch
```

### Track B: Semantic Search-and-Replace (Markdown)
A human-readable semantic block that can be manually reviewed or applied via `replace_file_content`:

````markdown
#### Target: `src/controllers/auth.ts` (Lines 42-45)

**Existing Code (Vulnerable)**:
```typescript
const query = `SELECT * FROM users WHERE username = '${username}'`;
return db.execute(query);
```

**Replacement Code (Remediated)**:
```typescript
const query = `SELECT * FROM users WHERE username = $1`;
return db.execute(query, [username]);
```
````

---

## 4. Pre-Delivery Dry-Run Verification (`git apply --check`)

Before presenting any patch file to the user:
1. **Dry-Run Validation**:
   The coordinator executes a dry-run check in the working tree without applying:
   ```bash
   git apply --check patches/F01.patch
   ```
2. **Line Ending & Whitespace Handling**:
   If the target file uses CRLF line endings, the patch must match CRLF, or include `--ignore-whitespace`.
3. **Failure Action**:
   If `git apply --check` exits with non-zero (e.g. `patch does not apply`), the patch file is marked `INVALID_DIFF` and Track B (Semantic Search-and-Replace) is highlighted as the fallback.
