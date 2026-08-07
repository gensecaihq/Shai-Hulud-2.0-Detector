# Contributing to Shai-Hulud 2.0 Detector

First off, thank you for considering contributing to Shai-Hulud 2.0 Detector! This project helps protect the open-source community from supply chain attacks, and every contribution matters.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Updating Package Database](#updating-package-database)
  - [Code Contributions](#code-contributions)
- [Development Setup](#development-setup)
- [Style Guidelines](#style-guidelines)
- [Pull Request Process](#pull-request-process)
- [Recognition](#recognition)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to creating a welcoming and inclusive environment. By participating, you agree to:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**When reporting a bug, include:**

1. **Clear title** - Summarize the issue in one line
2. **Environment details** - Node.js version, OS, GitHub Actions runner
3. **Steps to reproduce** - Detailed steps to reproduce the issue
4. **Expected behavior** - What you expected to happen
5. **Actual behavior** - What actually happened
6. **Screenshots/logs** - If applicable

**Example bug report:**

```markdown
## Bug: Scanner fails on yarn.lock v2 format

### Environment
- Node.js: 20.10.0
- OS: Ubuntu 22.04 (GitHub Actions)
- Action version: v1.0.0

### Steps to Reproduce
1. Create a project with Yarn Berry
2. Run the Shai-Hulud detector
3. Observe the error

### Expected Behavior
Scanner should parse yarn.lock and detect compromised packages

### Actual Behavior
Error: "Unable to parse yarn.lock file"

### Logs
```
Error: YAML parse error at line 15
```
```

### Suggesting Enhancements

We welcome suggestions for new features! Please include:

1. **Use case** - Why is this needed?
2. **Proposed solution** - How should it work?
3. **Alternatives considered** - What other approaches were considered?
4. **Additional context** - Screenshots, mockups, etc.

### Updating Package Database

The package database (`compromised-packages.json`) is critical for detection accuracy.

#### Adding a New Compromised Package

1. **Gather evidence** of compromise:
   - Link to security advisory
   - npm audit report
   - Analysis from security researchers
   - Presence of known malicious files

2. **Create a pull request** with:
   ```json
   {
     "name": "@scope/package-name",
     "severity": "critical",
     "affectedVersions": ["*"]
   }
   ```

3. **Include in PR description:**
   - Evidence of compromise
   - Affected versions (if known)
   - Source of information

#### Reporting False Positives

If a package is incorrectly flagged:

1. Open an issue with title: `[False Positive] package-name`
2. Provide evidence the package is clean:
   - Official statement from maintainers
   - Code audit results
   - Version that was remediated

### Code Contributions

We accept code contributions for:

- Bug fixes
- New features
- Performance improvements
- Documentation updates
- Test coverage

## Development Setup

### Prerequisites

- Node.js 24.x or higher
- npm 10.x or higher
- Git

### Setup Steps

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/Shai-Hulud-2.0-Detector.git
cd Shai-Hulud-2.0-Detector

# 3. Add upstream remote
git remote add upstream https://github.com/gensecaihq/Shai-Hulud-2.0-Detector.git

# 4. Install dependencies
npm install

# 5. Create a feature branch
git checkout -b feature/your-feature-name
```

### Building

```bash
# Build the action
npm run build

# This compiles TypeScript and bundles everything into dist/
```

### Testing Locally

```bash
# Set environment variables to simulate inputs
export INPUT_FAIL_ON_CRITICAL=true
export INPUT_SCAN_LOCKFILES=true
export INPUT_OUTPUT_FORMAT=text
export INPUT_WORKING_DIRECTORY=/path/to/test/project

# Run the action
node dist/index.js
```

### Creating Test Cases

Create test projects in a `test-fixtures/` directory (not committed):

```bash
mkdir -p test-fixtures/clean-project
cd test-fixtures/clean-project
npm init -y
npm install express lodash
cd ../..

mkdir -p test-fixtures/affected-project
cd test-fixtures/affected-project
echo '{"dependencies":{"posthog-node":"^5.0.0"}}' > package.json
```

## Style Guidelines

### TypeScript

- Use strict mode
- Prefer `const` over `let`
- Use meaningful variable names
- Add JSDoc comments for public functions

```typescript
/**
 * Scans a package.json file for compromised dependencies
 * @param filePath - Absolute path to package.json
 * @param isDirect - Whether to mark results as direct dependencies
 * @returns Array of scan results for affected packages
 */
export function scanPackageJson(
  filePath: string,
  isDirect: boolean = true
): ScanResult[] {
  // Implementation
}
```

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(scanner): add pnpm-lock.yaml support
fix(parser): handle malformed yarn.lock files
docs(readme): add CircleCI integration example
```

### Code Organization

```
src/
├── index.ts      # Entry point - GitHub Action interface
├── scanner.ts    # Core scanning logic
├── types.ts      # TypeScript interfaces
└── utils/        # Helper functions (if needed)
```

## Pull Request Process

### Before Submitting

1. **Update from upstream**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run build**
   ```bash
   npm run build
   ```

3. **Test your changes**
   - Test with clean project
   - Test with affected project
   - Test edge cases

4. **Commit dist/ changes**
   ```bash
   git add dist/
   git commit -m "chore: rebuild dist"
   ```

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Package database update
- [ ] Documentation update
- [ ] Other (please describe)

## Testing
Describe how you tested your changes

## Checklist
- [ ] I have read the CONTRIBUTING.md
- [ ] My code follows the project style
- [ ] I have run `npm run build`
- [ ] I have tested my changes
- [ ] I have updated documentation (if needed)

## Related Issues
Fixes #123
```

### Review Process

1. **Automated checks** - CI must pass
2. **Code review** - At least one maintainer approval
3. **Testing** - Changes tested by reviewer
4. **Merge** - Squash and merge to main

### After Merge

- Delete your feature branch
- Update your fork's main branch
- Celebrate! 🎉

## Recognition

Contributors are recognized in several ways:

### Contributors List

Active contributors are added to the README acknowledgments section.

### Release Notes

Significant contributions are mentioned in release notes.

### Hall of Fame

Major contributors who help identify compromised packages or make significant improvements are highlighted in project documentation.

---

## Questions?

- **General questions**: Open a Discussion
- **Bug reports**: Open an Issue
- **Security concerns**: See [Security Policy](SECURITY.md)

Thank you for contributing to making the npm ecosystem safer!
