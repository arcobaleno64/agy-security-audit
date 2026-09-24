# Consumer Provenance Verification Guide

> **Acceptance Criterion D-AC-06**: Independent consumer verification path for immutable release assets.

This guide provides step-by-step procedures for consumers, third-party auditors, and downstream operators to independently verify the authenticity, cryptographic integrity, and supply chain provenance of published `@arcobaleno64/agy-security-audit` releases.

---

## 1. Provenance Architecture & Trust Model

The project enforces **SLSA Build Level 2** supply chain assurance via GitHub Actions OIDC and Sigstore public transparency logs:
- **Zero Self-Hosted Runners**: All release builds and attestations run exclusively on GitHub-hosted Ubuntu runners (`--deny-self-hosted-runners`).
- **Cryptographic Attestations**: Build provenance statements adhere to the [SLSA Provenance v1](https://slsa.dev/provenance/v1) predicate specification.
- **Immutable Releases**: Release tags and source references are pinned to exact 40-character Git commit SHAs.
- **Fail-Closed Verification**: Any discrepancy between downloaded assets, `SHA256SUMS.txt`, or signed attestations results in verification termination.

---

## 2. Prerequisites

Verification requires standard developer tooling with zero project dependencies:
- **Node.js**: `>= 20.18.0`
- **GitHub CLI (`gh`)**: `>= 2.50.0` (with authenticated or public read permissions)
- **Standard Checksum Tool**: `sha256sum` (Linux/macOS) or `Get-FileHash` / PowerShell (Windows)

Verify your tools via:
```bash
gh --version
node -v
```

---

## 3. Step-by-Step Verification Procedure

### Step 1: Download Release Assets
Download the release assets into a dedicated empty directory:
```bash
mkdir release-verify && cd release-verify
gh release download v1.8.1 --repo arcobaleno64/agy-security-audit
```

The release directory contains:
- `agy-security-audit-v1.8.1.zip`: The packaged plugin archive.
- `SHA256SUMS.txt`: Canonical manifest of SHA-256 digests for all release files.
- Accompanying evaluation benchmarks, reports, and evidence matrices.

### Step 2: Verify Local Cryptographic Integrity
Verify that downloaded files match the canonical `SHA256SUMS.txt` manifest:

**On Linux / macOS:**
```bash
sha256sum -c SHA256SUMS.txt
```

**On Windows (PowerShell):**
```powershell
Get-Content SHA256SUMS.txt | ForEach-Object {
    $parts = $_ -split '  '
    $expected = $parts[0].Trim().ToLower()
    $file = $parts[1].Trim()
    $actual = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
        Write-Error "Mismatch for $file"
    } else {
        Write-Host "OK: $file"
    }
}
```

Or using the built-in integrity checker:
```bash
node scripts/verify-release-provenance.mjs --dir . --integrity-only
```

### Step 3: Verify Sigstore / GitHub Attestation via GitHub CLI
Verify that the release asset was built and attested by the official GitHub Actions workflow from the tagged release commit:

```bash
gh attestation verify agy-security-audit-v1.8.1.zip \
  --repo arcobaleno64/agy-security-audit \
  --signer-workflow arcobaleno64/agy-security-audit/.github/workflows/release.yml@refs/tags/v1.8.1 \
  --source-ref refs/tags/v1.8.1 \
  --source-digest 8af4bca5cdfef89c93649c03a70d43767875ffb7 \
  --deny-self-hosted-runners
```

**Expected Output:**
```text
Loaded digest sha256:2a0ece157b0264fc2cfd2efc8d87de78696ffe3a3d79fd01bfa8f83153ee04da for agy-security-audit-v1.8.1.zip
The following policy criteria will be enforced:
...
✓ Verification succeeded!
```

### Step 4: Full Automated Verification
To verify all assets simultaneously against repository policies, run:
```bash
node scripts/verify-release-provenance.mjs \
  --dir . \
  --repo arcobaleno64/agy-security-audit \
  --signer-workflow arcobaleno64/agy-security-audit/.github/workflows/release.yml@refs/tags/v1.8.1 \
  --source-ref refs/tags/v1.8.1 \
  --source-digest 8af4bca5cdfef89c93649c03a70d43767875ffb7
```

---

## 4. Public Transparency Log (Rekor) Inspection

Each GitHub attestation is published to the Sigstore public transparency log (Rekor). To inspect the public transparency log entry directly using `gh attestation verify --format json`:

```bash
gh attestation verify agy-security-audit-v1.8.1.zip \
  --repo arcobaleno64/agy-security-audit \
  --format json > attestation-result.json
```

Key immutable fields to verify in the resulting JSON:
- `verificationResult.statement.predicateType`: `https://slsa.dev/provenance/v1`
- `verificationResult.statement.subject[0].digest.sha256`: Matches local asset SHA-256.
- `verificationResult.signature.certificate`: Issued by GitHub OIDC provider (`https://token.actions.githubusercontent.com`).
- `verificationResult.tlogEntries`: Cryptographic log index proving permanent inclusion in Rekor.

---

## 5. Failure Scenarios & Security Responses

| Observation | Root Cause | Operator Action |
|---|---|---|
| `SHA mismatch for asset` | File corrupted in transit or tampered on mirror | Terminate installation. Re-download directly from GitHub Releases. |
| `Attestation verification failed: signer workflow mismatch` | Asset was not generated by official release workflow | **REJECT**. Potential untrusted third-party build. |
| `Source digest mismatch` | Tag was moved or pointed to unverified commit | **REJECT**. Immutable tag policy violated. |
| `Self-hosted runner detected` | Build occurred on non-GitHub infrastructure | **REJECT**. Violates zero self-hosted runner policy. |
