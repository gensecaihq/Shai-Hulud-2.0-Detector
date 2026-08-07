# CLAUDE.md

Guidance for AI assistants (Claude Code and others) working in this repository.

## Commit Policy

- **All commits must be authored without AI attribution.** Do not add `Co-Authored-By: Claude ...`, `Generated with Claude Code`, or any similar AI attribution trailers/footers to commit messages, PR bodies, or release notes. This is a project rule and overrides default assistant behavior.
- Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `ci:`.

## Project Facts

- GitHub Action (TypeScript) detecting Shai-Hulud npm supply-chain attacks — both the 2.0 wave (Nov 2025) and the ChainDrop wave (Aug 2026).
- `compromised-packages.json` is **generated** — never hand-edit the package list. `scripts/update-ioc-database.js` merges two feeds daily: Datadog consolidated IOCs (Shai-Hulud 2.0) and the Wiz Research ChainDrop list.
- `dist/` is committed and **embeds the IOC database** — run `npm run build` after any change to `src/` or `compromised-packages.json`.
- Runtime is `node24` (`action.yml`); requires Node.js 24+ locally.
- Tests: `npm test` (vitest). Typecheck: `npm run typecheck`.
- Self-exclusion caveat: paths matching `/shai-hulud.*detector/i` are skipped by content scans — test fixtures must live outside such paths.
- Dependencies intentionally held back: `@actions/core` v1 (v3 unverified in real Actions runs), `yargs` 17 (v18 is ESM-only; this project bundles CJS via ncc), `typescript` 5.x.
- `main` is branch-protected: automation must open PRs (see `update-ioc-database.yml` and `update-contributors.yml`), not push directly.
