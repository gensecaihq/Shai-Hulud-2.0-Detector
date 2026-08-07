# Changelog

All notable changes to the Shai-Hulud 2.0 Detector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.2.0] - 2026-08-08

### Why This Release?

On **August 4, 2026** the Shai-Hulud campaign returned as **ChainDrop** ("Shai-Hulud: Here We Go Again"), compromising the maintainer of `keyv`, `cacheable`, `flat-cache` and `file-entry-cache` and worm-propagating to 450+ packages (~2 billion monthly downloads). This release adds full ChainDrop coverage, corroborated across Elastic Security Labs, Unit 42, Wiz Research, OX Security and GitGuardian.

### Added

#### ChainDrop Package Database (Critical)
- Merged the [Wiz Research ChainDrop package list](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv) into the IOC database: **795 → 1,241 unique packages**, including `keyv@6.0.0`, `cacheable@2.5.1`, `flat-cache@6.1.24`, `file-entry-cache@11.1.6`, `cacheable-request@13.0.20`, `cache-manager@7.2.10`
- `scripts/update-ioc-database.js` now fetches and merges both campaign feeds on the daily schedule

#### ChainDrop Malware Detection (Critical)
- SHA256 hashes for `Math_Symbol.js` / `math_init.js` and `setup.mjs` dropper variants
- Payload filename detection: `Math_Symbol.js`, `math_init.js`, `router_runtime.js`
- Lifecycle-script detection for the `preinstall: node setup.mjs` infection vector

#### IDE/Agent Persistence Detection (Critical) — new `ide-persistence` finding type
- `.claude/settings.json` **SessionStart** hooks referencing droppers (executes on every Claude Code start)
- `.vscode/tasks.json` **folderOpen** tasks referencing droppers (executes on folder open)
- Dropper/payload files inside `.claude/` and `.vscode/` directories
- `gh-token-monitor` persistence artifacts (LaunchAgents plist, systemd user service, `~/.local/bin` script)

#### C2 / Dead-Drop Infrastructure Detection (Critical)
- Domains: `npm-cache.com`, `awqhnjewqjkl.icu`, `pypi-get.com`, `js-mirror.com`
- Ethereum C2 resolver contract `0xE1f2395e...` and operator wallet
- Commit markers: `thebeautifulmarchoftime`, `thebeautifulsnadsoftime`, `IfYouBlockThisAPIKey...`
- Campaign marker: "Shai-Hulud: Here We Go Again"

#### Malicious Workflow Detection
- Fake `codeql_analysis.yml` workflow (underscore variant of GitHub's `codeql-analysis.yml`)
- `toJSON(secrets)` full-secret dumps in any workflow (high severity)

#### pnpm Support (community, PR #51 by @woss)
- `pnpm-lock.yaml` scanning with vitest test coverage

### Fixed
- **Scanner blind spot**: security checks now descend into `.claude/`, `.vscode/`, `.github/` and `.config/` hidden directories — exactly where ChainDrop drops its payloads
- `npm test` was broken (referenced jest, which was never installed); now runs vitest
- SARIF report version string was stuck at 2.0.0
- Removed unused `@actions/github` and `@actions/glob` dependencies (smaller bundle)

### Changed
- **Node.js runtime upgraded from node20 to node24** (Node 20 is EOL since April 2026) — PR #52 by @daniel-toth-leeder
- GitHub Actions bumped to latest majors: `actions/checkout@v7`, `actions/setup-node@v7`, `github/codeql-action/upload-sarif@v4`, `peter-evans/create-pull-request@v8`, `actions/github-script@v9`
- CI now includes a ChainDrop regression test (`keyv@6.0.0` must be detected)
- Dependencies refreshed (`semver`, `@types/node@24`, `typescript@5.9`, `@vercel/ncc@0.38.4`)

---

## [2.0.0] - 2025-12-02

### Why This Release?

After the initial Shai-Hulud 2.0 attack on November 24, 2025, security researchers from Wiz, Datadog Security Labs, and others continued investigating the aftermath. Their findings revealed additional attack vectors and persistence mechanisms that v1.x could not detect:

1. **Backdoor Persistence**: The attack planted `on: discussion` workflow triggers that persist even after removing compromised packages
2. **Rogue Runner Installation**: Attackers installed self-hosted runners in `$HOME/.dev-env/` for long-term access
3. **Malware Variants**: Multiple variants of `bun_environment.js` exist with different SHA256 hashes

This release incorporates these findings to provide comprehensive detection coverage.

### Added

#### SHA256 Hash Matching (Critical)
- **What**: Cryptographic signature matching against known Shai-Hulud malware variants
- **Why**: Security researchers at Datadog identified 6+ unique variants of the malicious `bun_environment.js` payload. Simple filename matching is insufficient - attackers can rename files. SHA256 hash matching provides definitive malware identification.
- **How**: Files named `setup_bun.js` or `bun_environment.js` are hashed and compared against the IOC database from Datadog Security Labs
- **Source**: [Datadog Security Labs - Shai-Hulud 2.0 npm Worm Analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)

#### on:discussion Workflow Trigger Detection (Critical)
- **What**: Detects GitHub Actions workflows with `on: discussion` triggers
- **Why**: Wiz's aftermath analysis revealed that the attack creates workflows triggered by GitHub discussions. These triggers allow attackers to execute arbitrary commands by simply posting a discussion comment - a persistent backdoor that survives package cleanup.
- **How**: Scans all `.yml`/`.yaml` files in `.github/workflows/` for the `on: discussion` pattern
- **Source**: [Wiz - Shai-Hulud 2.0 Aftermath Analysis](https://www.wiz.io/blog/shai-hulud-2-0-aftermath-ongoing-supply-chain-attack)

#### Runner Installation Path Detection (Critical)
- **What**: Detects `.dev-env/` directories and specific GitHub Actions runner artifacts
- **Why**: The attack installs rogue self-hosted runners to maintain persistent access. These are installed in `$HOME/.dev-env/` and use `actions-runner-linux-x64-2.330.0.tar.gz`. Detection of these artifacts indicates active compromise.
- **How**: Scans the repository and home directory for `.dev-env/` directories and runner installation files
- **Source**: [Wiz - Shai-Hulud 2.0 Investigation](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)

#### New Exfiltration File Detection
- **What**: Added detection for `actionsSecrets.json` and `trufflehog_output.json`
- **Why**: These files contain stolen credentials. `actionsSecrets.json` stores GitHub Actions secrets with double Base64 encoding before exfiltration. `trufflehog_output.json` contains raw TruffleHog credential scan results.
- **How**: File existence checks during directory scanning

#### Enhanced IOC Database (v2.0.0)
- **What**: Expanded Indicators of Compromise database
- **Why**: Provides comprehensive threat intelligence from multiple security research sources
- **New fields**:
  - `fileHashes.*.sha256` - SHA256 hashes (single or array for variants)
  - `gitHubIndicators.repoNamePattern` - Regex for malicious repo names (`[0-9a-z]{18}`)
  - `gitHubIndicators.workflowTrigger` - Malicious trigger pattern
  - `runnerPaths` - Runner installation locations
  - `credentialPaths` - Targeted credential files
  - `primaryInfectionVectors` - Known initial infection packages
  - `mavenPackages` - Java/Maven ecosystem packages affected
  - `acknowledgements` - Security researcher credits

#### New Security Finding Types
- `malware-hash-match` - File hash matches known malware
- `runner-installation` - Rogue runner artifacts detected
- `malicious-workflow-trigger` - Dangerous workflow trigger found

### Changed

- **Database version**: Updated from 1.0.0 to 2.0.0
- **FileHash structure**: Now supports both SHA-1 and SHA-256, with support for multiple variants per file
- **SARIF tool version**: Updated to 2.0.0
- **README action version**: Updated examples to use `@v2`

### Preserved from v1.x

All features from v1.x releases continue to work:

- **Semver Version Matching** (PR #11) - Precise version range detection reduces false positives
- **Scan node_modules Option** (PR #9) - Optional deep scanning of installed packages
- **iOS Xcode False Positive Fix** (PR #5) - Correctly excludes `.xcassets/*/contents.json`
- **CLI Flags & Environment Variables** (PR #4) - Flexible configuration options
- **Total Dependencies Count** (PR #10) - Accurate dependency counting

### Security Researcher Acknowledgements

This release would not have been possible without the security research community:

| Organization | Contribution |
|-------------|--------------|
| [Wiz](https://github.com/wiz-sec) | Comprehensive threat investigation, aftermath analysis, runner installation discovery |
| [Datadog Security Labs](https://github.com/DataDog) | SHA256 hash IOCs, detailed malware analysis, variant identification |
| [Aikido Security](https://github.com/AikidoSec) | Initial attack discovery, package database foundation |
| [Postman](https://github.com/postmanlabs) | Incident disclosure, `@postman/tunnel-agent` investigation |
| [PostHog](https://github.com/PostHog) | Attack timeline, `posthog-node` post-mortem |
| [HelixGuard](https://github.com/helixguard) | Malware analysis, IOC identification |

### Research References

- [Wiz - Shai-Hulud 2.0 Aftermath](https://www.wiz.io/blog/shai-hulud-2-0-aftermath-ongoing-supply-chain-attack) - Analysis of persistence mechanisms and ongoing attack
- [Datadog - npm Worm Analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/) - Technical deep-dive with SHA256 hashes
- [Datadog IOC Repository](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0) - Machine-readable IOCs
- [Aikido - Initial Discovery](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains) - First public report
- [Postman Engineering](https://blog.postman.com/engineering/shai-hulud-2-0-npm-supply-chain-attack/) - Vendor post-mortem
- [PostHog Blog](https://posthog.com/blog/nov-24-shai-hulud-attack-post-mortem) - Attack timeline and response

---

## [1.0.2] - 2025-11-27

### Added
- Semver version matching for precise vulnerability detection (PR #11)

### Fixed
- Accurate total dependencies count (PR #10)

---

## [1.0.1] - 2025-11-26

### Added
- Scan node_modules option for thorough scanning (PR #9)

---

## [1.0.0] - 2025-11-25

### Added
- Initial release
- Database of 790+ compromised packages
- Support for package.json, package-lock.json, yarn.lock
- GitHub Action with SARIF output
- CLI support with environment variables (PR #4)
- iOS Xcode false positive fix (PR #5)
- Suspicious script detection
- TruffleHog activity detection
- SHA1HULUD runner detection
- Webhook exfiltration detection
- Shai-Hulud repository reference detection

---

## Upgrade Guide

### From v1.x to v2.0.0

Update your workflow file:

```diff
- uses: gensecaihq/Shai-Hulud-2.0-Detector@v1
+ uses: gensecaihq/Shai-Hulud-2.0-Detector@v2
```

No configuration changes required. v2.0.0 is fully backward compatible.

### New Outputs Available

v2.0.0 adds enhanced security findings. Access them via:

```yaml
- name: Run Scan
  id: scan
  uses: gensecaihq/Shai-Hulud-2.0-Detector@v2

- name: Check Results
  run: |
    echo "Security findings: ${{ steps.scan.outputs.security-findings-count }}"
    echo "Details: ${{ steps.scan.outputs.security-findings }}"
```

---

[2.0.0]: https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/compare/v1.0.2...v2.0.0
[1.0.2]: https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/releases/tag/v1.0.0
