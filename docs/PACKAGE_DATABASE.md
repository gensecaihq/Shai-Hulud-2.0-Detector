# Package Database Contribution Guide

This document explains how the Shai-Hulud 2.0 Detector's package database is maintained and how you can contribute.

## Table of Contents

- [Overview](#overview)
- [Automated Updates](#automated-updates)
- [Data Sources](#data-sources)
- [Database Structure](#database-structure)
- [How to Contribute](#how-to-contribute)
  - [Adding New Packages](#adding-new-packages)
  - [Reporting False Positives](#reporting-false-positives)
  - [Updating Package Information](#updating-package-information)
- [Evidence Requirements](#evidence-requirements)
- [Verification Process](#verification-process)
- [Automated Submission](#automated-submission)
- [Community Guidelines](#community-guidelines)
- [FAQ](#faq)

---

## Overview

The `compromised-packages.json` file is the heart of the Shai-Hulud 2.0 Detector. It contains the list of all known compromised packages from the attack. This database is:

- **Automatically Updated** - Syncs daily from 7 security vendors
- **Precise Version Matching** - Only specific compromised versions are flagged
- **Open Source** - Anyone can view and contribute
- **Verified** - All data is cross-referenced from multiple sources

### Current Statistics

| Metric | Value |
|--------|-------|
| Total Packages | 1,241 (795 Shai-Hulud 2.0 + 446 ChainDrop) |
| Campaign Waves | Shai-Hulud 2.0 (Nov 2025) + ChainDrop (Aug 2026) |
| Data Sources | 7 security vendors + Wiz ChainDrop feed |
| Update Frequency | Daily (automated) |
| Version Precision | Specific versions only |
| Last Updated | See `lastUpdated` field in JSON |

---

## Automated Updates

The package database is **automatically updated daily** via GitHub Actions. This ensures the database stays current with the latest threat intelligence from multiple security vendors.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    DAILY UPDATE PROCESS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. GitHub Action runs at 00:00 UTC daily                       │
│                                                                 │
│  2. Fetches consolidated IOCs from Datadog repository           │
│     └─► https://github.com/DataDog/indicators-of-compromise     │
│     and the ChainDrop package list from Wiz Research            │
│     └─► https://github.com/wiz-sec-public/wiz-research-iocs     │
│                                                                 │
│  3. Parses both CSVs, merges waves, extracts specific versions  │
│                                                                 │
│  4. Updates compromised-packages.json                           │
│                                                                 │
│  5. Creates Pull Request if changes detected                    │
│                                                                 │
│  6. Maintainers review and merge                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Manual Update

To manually trigger an update:

```bash
# Via GitHub Actions UI
# Go to Actions → "Update IOC Database" → "Run workflow"

# Or locally
node scripts/update-ioc-database.js
```

---

## Data Sources

**Shai-Hulud 2.0 wave (Nov 2025):** aggregated from **7 security vendors** via the [Datadog Consolidated IOCs](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0):

| Source | Packages | Description |
|--------|----------|-------------|
| **[Wiz](https://www.wiz.io)** | 795 | Threat investigation & attack analysis |
| **[Koi Security](https://koi.security)** | 789 | Supply chain threat intelligence |
| **[HelixGuard](https://helixguard.ai)** | 782 | Malware analysis and IOC identification |
| **[StepSecurity](https://www.stepsecurity.io)** | 781 | GitHub Actions security |
| **[ReversingLabs](https://www.reversinglabs.com)** | 605 | Software supply chain security |
| **[Socket.dev](https://socket.dev)** | 554 | npm security monitoring |
| **[Datadog Security Labs](https://securitylabs.datadoghq.com)** | 428 | SHA256 hash IOCs & malware analysis |

**ChainDrop wave (Aug 2026):** sourced from the continuously updated [Wiz Research ChainDrop package list](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv) (446 packages including `keyv`, `cacheable`, `flat-cache`, `file-entry-cache`). Packages appearing in both feeds get their affected-version lists merged.

### Why Multiple Sources?

Each security vendor has unique detection methods. By aggregating data:
- **Higher coverage**: No single source catches everything
- **Cross-validation**: Multiple sources confirming = higher confidence
- **Faster updates**: New discoveries propagate from any source

---

## Database Structure

### File Location

```
/compromised-packages.json
```

### Schema (v2.2.0)

```json
{
  "version": "2.2.0",
  "lastUpdated": "2026-08-08T00:00:00Z",
  "attackInfo": {
    "name": "Shai-Hulud 2.0 / ChainDrop",
    "alias": "The Second Coming / Here We Go Again",
    "firstDetected": "2025-11-24T03:16:00Z",
    "description": "..."
  },
  "indicators": {
    "maliciousFiles": ["setup_bun.js", "bun_environment.js", "actionsSecrets.json", ...],
    "maliciousWorkflows": [".github/workflows/discussion.yaml", ".github/workflows/formatter_*.yml", ...],
    "fileHashes": {
      "setup_bun.js": {
        "sha1": "d1829b4708126dcc7bea7437c04d1f10eacd4a16",
        "sha256": "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
      },
      "bun_environment.js": {
        "sha1": "d60ec97eea19fffb4809bc35b91033b52490ca11",
        "sha256": ["62ee164b...", "cbb9bc5a...", "..."]  // Multiple variants
      }
    },
    "gitHubIndicators": {
      "runnerName": "SHA1HULUD",
      "repoDescription": "Shai-Hulud: The Second Coming",
      "repoNamePattern": "[0-9a-z]{18}",
      "workflowTrigger": "on: discussion"
    },
    "runnerPaths": ["$HOME/.dev-env/", "actions-runner-linux-x64-2.330.0.tar.gz"],
    "credentialPaths": [".config/gcloud/application_default_credentials.json", ".npmrc"],
    "primaryInfectionVectors": ["@postman/tunnel-agent@0.6.7", "posthog-node", "@asyncapi/specs@6.8.3"],
    "mavenPackages": ["org.mvnpm:posthog-node:4.18.1"]
  },
  "stats": {
    "totalUniquePackages": 790,
    "byOrganization": { ... }
  },
  "packages": [
    {
      "name": "@scope/package-name",
      "severity": "critical",
      "affectedVersions": ["*"]
    }
  ],
  "sources": ["https://..."],
  "acknowledgements": {
    "securityResearchers": [
      {"org": "Wiz", "github": "wiz-sec"},
      {"org": "Datadog Security Labs", "github": "DataDog"},
      ...
    ]
  }
}
```

### New in v2.0.0

| Field | Description |
|-------|-------------|
| `indicators.fileHashes` | Now supports both SHA-1 and SHA-256 hashes, with multiple variants per file |
| `indicators.gitHubIndicators.repoNamePattern` | Regex pattern for malicious repo names |
| `indicators.gitHubIndicators.workflowTrigger` | Malicious workflow trigger pattern |
| `indicators.runnerPaths` | Paths where rogue runners are installed |
| `indicators.credentialPaths` | Targeted credential file paths |
| `indicators.primaryInfectionVectors` | Known initial infection packages |
| `indicators.mavenPackages` | Maven/Java ecosystem packages affected |
| `acknowledgements` | Credits for security researchers |

### New in v2.2.0

| Change | Description |
|--------|-------------|
| ChainDrop wave merged | The daily updater merges the [Wiz Research ChainDrop list](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv) with the Datadog feed (795 → 1,241 packages) |
| `dataSource.chainDropUrl` | Points at the ChainDrop feed used for the merge |
| Version-list union | Packages present in both feeds get their `affectedVersions` merged |

### Package Entry Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Full npm package name (e.g., `@scope/pkg` or `pkg`) |
| `severity` | string | Yes | One of: `critical`, `high`, `medium`, `low` |
| `affectedVersions` | array | Yes | **Specific versions only** (e.g., `["3.4.1", "3.4.2"]`) |

### Version Precision

The database now uses **specific version numbers** instead of wildcards:

```json
// OLD format (caused false positives)
{
  "name": "@asyncapi/parser",
  "severity": "critical",
  "affectedVersions": ["*"]  // Flagged ALL versions
}

// NEW format (precise matching)
{
  "name": "@asyncapi/parser",
  "severity": "critical",
  "affectedVersions": ["3.4.1", "3.4.2"]  // Only compromised versions
}
```

This eliminates false positives for:
- Pre-attack versions (published before Nov 24, 2025)
- Post-remediation clean versions

### Severity Levels

| Level | Criteria | Example |
|-------|----------|---------|
| **critical** | Confirmed malicious code execution | Package with `setup_bun.js` |
| **high** | Strong evidence of compromise | Package from compromised maintainer |
| **medium** | Suspected or partial compromise | Related package, unverified |
| **low** | Potentially affected | Dependency of compromised package |

---

## How to Contribute

### Adding New Packages

#### Method 1: GitHub Issue (Easiest)

1. Go to [Issues](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues)
2. Click "New Issue"
3. Select "Package Report" template
4. Fill in the details:

```markdown
## Package Report

**Package Name:** @scope/package-name
**npm Link:** https://www.npmjs.com/package/@scope/package-name
**Severity:** critical

### Evidence

- [ ] Contains setup_bun.js
- [ ] Contains bun_environment.js
- [ ] Suspicious postinstall script
- [ ] Published during attack window (Nov 24, 2025)
- [ ] Other (describe below)

### Evidence Details

[Paste links, screenshots, or analysis here]

### Source

Where did you find this information?
- [ ] Personal discovery
- [ ] Security advisory
- [ ] Researcher report
- [ ] Other: ___________
```

#### Method 2: Pull Request (Preferred for Multiple Packages)

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/Shai-Hulud-2.0-Detector.git
   cd Shai-Hulud-2.0-Detector
   ```

2. **Create a branch**
   ```bash
   git checkout -b add-packages/your-name
   ```

3. **Edit compromised-packages.json**

   Add new packages to the `packages` array (maintain alphabetical order):
   ```json
   {
     "name": "@new-scope/new-package",
     "severity": "critical",
     "affectedVersions": ["*"]
   }
   ```

4. **Update statistics**
   ```bash
   # Run the stats updater (if available)
   node scripts/update-stats.js

   # Or manually update stats.totalUniquePackages
   ```

5. **Build and test**
   ```bash
   npm run build
   ```

6. **Commit with evidence**
   ```bash
   git add compromised-packages.json
   git commit -m "feat(db): add @new-scope/new-package

   Evidence: [link to analysis]
   Source: [researcher name/advisory]"
   ```

7. **Submit PR**
   - Push to your fork
   - Create PR with detailed description
   - Link to evidence

#### Method 3: Batch Submission (For Researchers)

If you've identified many packages:

1. Create a CSV file:
   ```csv
   name,severity,evidence_url
   @scope/pkg1,critical,https://...
   @scope/pkg2,critical,https://...
   pkg3,high,https://...
   ```

2. Open an issue with the CSV attached
3. Or use our submission script:
   ```bash
   node scripts/batch-submit.js packages.csv
   ```

### Reporting False Positives

If a package is incorrectly flagged:

1. **Open an Issue**
   - Title: `[False Positive] package-name`
   - Provide evidence the package is clean

2. **Required Evidence:**
   - Official statement from maintainers
   - Code audit showing no malicious code
   - Timestamp proving publish before attack
   - npm security team confirmation

3. **PR to Remove:**
   ```bash
   git checkout -b fix/false-positive-package-name
   # Remove from compromised-packages.json
   git commit -m "fix(db): remove false positive package-name

   Evidence: [link]"
   ```

### Updating Package Information

To update severity or affected versions:

```bash
# Edit compromised-packages.json
# Change:
{
  "name": "@scope/package",
  "severity": "critical",
  "affectedVersions": ["*"]
}

# To:
{
  "name": "@scope/package",
  "severity": "critical",
  "affectedVersions": [">=1.0.0 <1.0.5"],
  "patchedVersion": "1.0.5",
  "advisory": "https://..."
}
```

---

## Evidence Requirements

### Minimum Evidence (Required)

At least ONE of the following:

| Evidence Type | Description | Example |
|---------------|-------------|---------|
| Malicious File | Package contains known malicious files | `setup_bun.js` found in package |
| File Hash Match | Files match known malicious hashes | SHA-1 matches IOC list |
| Postinstall Script | Suspicious lifecycle script | Downloads external payload |
| Maintainer Compromise | Maintainer account was compromised | Same maintainer as known bad pkg |
| Security Advisory | Official security advisory | npm advisory, GitHub advisory |

### Strong Evidence (Preferred)

| Evidence Type | Value |
|---------------|-------|
| Code analysis | Detailed breakdown of malicious behavior |
| Timeline correlation | Package updated during attack window |
| Multiple sources | Confirmed by 2+ security researchers |
| Behavioral analysis | Observed malicious network activity |

### Evidence Templates

#### For Malicious File Discovery

```markdown
## Evidence: Malicious File

**Package:** @scope/package-name
**Version:** 1.2.3

### File Found
- Location: `node_modules/@scope/package-name/setup_bun.js`
- SHA-1: d1829b4708126dcc7bea7437c04d1f10eacd4a16

### Verification
```bash
shasum -a 1 node_modules/@scope/package-name/setup_bun.js
# Output: d1829b4708126dcc7bea7437c04d1f10eacd4a16
```

### Screenshot
[Attach screenshot of file contents]
```

#### For Postinstall Script Analysis

```markdown
## Evidence: Malicious Postinstall

**Package:** package-name
**Version:** 2.0.0

### package.json scripts
```json
{
  "scripts": {
    "postinstall": "node setup_bun.js"
  }
}
```

### Script Behavior
1. Downloads Bun runtime from [URL]
2. Executes bun_environment.js
3. Scans for credentials
4. Uploads to GitHub

### Network Activity
[Paste network logs or screenshots]
```

---

## Verification Process

All submissions go through a verification process:

### Automated Checks

1. **Schema Validation** - JSON structure is valid
2. **Duplicate Check** - Package not already in database
3. **Name Validation** - Valid npm package name format
4. **Version Format** - Valid semver range

### Manual Review

1. **Evidence Review** - Maintainer verifies evidence
2. **Cross-Reference** - Check against known sources
3. **Risk Assessment** - Evaluate severity level
4. **Merge Decision** - Approve, request changes, or reject

### Review Timeline

| Priority | Response Time | Merge Time |
|----------|---------------|------------|
| Critical (active attack) | < 2 hours | < 4 hours |
| High (confirmed) | < 24 hours | < 48 hours |
| Medium (suspected) | < 48 hours | < 1 week |
| Low (needs investigation) | < 1 week | Varies |

---

## Automated Submission

### GitHub Actions Workflow

You can automate package submission using our GitHub Action:

```yaml
name: Submit Compromised Package
on:
  workflow_dispatch:
    inputs:
      package_name:
        description: 'Package name (e.g., @scope/pkg)'
        required: true
      severity:
        description: 'Severity level'
        required: true
        default: 'critical'
        type: choice
        options:
          - critical
          - high
          - medium
          - low
      evidence_url:
        description: 'URL to evidence'
        required: true

jobs:
  submit:
    runs-on: ubuntu-latest
    steps:
      - uses: gensecaihq/Shai-Hulud-2.0-Detector/submit-package@v1
        with:
          package-name: ${{ inputs.package_name }}
          severity: ${{ inputs.severity }}
          evidence-url: ${{ inputs.evidence_url }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### API Submission (Coming Soon)

```bash
curl -X POST https://api.shai-hulud-detector.dev/packages \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "@scope/package",
    "severity": "critical",
    "evidence": "https://...",
    "reporter": "github:username"
  }'
```

---

## Community Guidelines

### Do's

- **Do** provide evidence for all submissions
- **Do** check if package is already reported
- **Do** use appropriate severity levels
- **Do** respond to review feedback promptly
- **Do** credit original researchers

### Don'ts

- **Don't** submit without evidence
- **Don't** inflate severity levels
- **Don't** submit test/spam packages
- **Don't** use automated mass submissions without approval
- **Don't** share unverified information publicly

### Recognition

Contributors are recognized through:

1. **GitHub Contributors** - Automatic via commits
2. **CONTRIBUTORS.md** - Listed for significant contributions
3. **Release Notes** - Mentioned for discoveries
4. **Hall of Fame** - Major contributors highlighted

---

## FAQ

### Q: How quickly are submissions reviewed?

Critical submissions (active threats) are prioritized and typically reviewed within 2-4 hours. Regular submissions are reviewed within 24-48 hours.

### Q: What if I'm not sure about the severity?

When in doubt, use `medium` severity. Maintainers will adjust based on evidence during review.

### Q: Can I submit packages found by automated tools?

Yes, but please verify the findings manually before submission. Include the tool name and output in your evidence.

### Q: What happens if my submission is rejected?

You'll receive feedback explaining why. You can provide additional evidence and resubmit.

### Q: How do I know if a package was already reported?

1. Search the `compromised-packages.json` file
2. Search existing GitHub issues
3. Use our search tool:
   ```bash
   grep -i "package-name" compromised-packages.json
   ```

### Q: Can I submit packages from private registries?

Yes, if they're related to the Shai-Hulud attack. Mark them clearly as private registry packages.

### Q: What about scoped packages?

Include the full scope: `@scope/package-name`, not just `package-name`.

### Q: How are versions handled?

- `["*"]` - All versions affected
- `[">=1.0.0 <2.0.0"]` - Specific range affected
- Add `patchedVersion` when a fix is available

---

## Quick Reference

### Submission Checklist

```markdown
- [ ] Package name is correct and complete
- [ ] Severity level is appropriate
- [ ] At least one form of evidence provided
- [ ] Evidence link is accessible
- [ ] Not a duplicate submission
- [ ] JSON syntax is valid
- [ ] Alphabetical order maintained (for PRs)
```

### Package Entry Template

```json
{
  "name": "@scope/package-name",
  "severity": "critical",
  "affectedVersions": ["*"]
}
```

### Extended Package Entry (Optional Fields)

```json
{
  "name": "@scope/package-name",
  "severity": "critical",
  "affectedVersions": [">=1.0.0 <1.0.5"],
  "patchedVersion": "1.0.5",
  "advisory": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
  "cve": "CVE-2025-XXXXX",
  "reportedBy": "github:username",
  "reportedAt": "2025-11-25T10:00:00Z",
  "notes": "Additional context about this package"
}
```

---

## Contact

- **General Questions**: Open a [Discussion](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/discussions)
- **Bug Reports**: Open an [Issue](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/issues)
- **Security Concerns**: See [SECURITY.md](../SECURITY.md)
- **Urgent Submissions**: Tag issue with `priority:critical`

---

**Thank you for helping protect the open-source community!**

Every package you report helps prevent attacks on developers worldwide.
