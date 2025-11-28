import * as fs from 'fs';
import * as path from 'path';
import masterPackagesData from '../compromised-packages.json';
import type {
	MasterPackages,
	PackageJson,
	PackageLock,
	SarifResult,
	ScanResult,
	ScanSummary,
	SecurityFinding,
} from './types';

// =============================================================================
// SUSPICIOUS PATTERNS FOR ADVANCED DETECTION
// =============================================================================

// Suspicious commands in package.json scripts
const SUSPICIOUS_SCRIPT_PATTERNS = [
	{
		pattern: /setup_bun\.js/i,
		description: 'Shai-Hulud malicious setup script',
	},
	{
		pattern: /bun_environment\.js/i,
		description: 'Shai-Hulud environment script',
	},
	{
		pattern: /\bcurl\s+[^|]*\|\s*(ba)?sh/i,
		description: 'Curl piped to shell execution',
	},
	{
		pattern: /\bwget\s+[^|]*\|\s*(ba)?sh/i,
		description: 'Wget piped to shell execution',
	},
	{
		pattern: /\beval\s*\(/i,
		description: 'Eval execution (potential code injection)',
	},
	{ pattern: /\beval\s+['"`$]/i, description: 'Eval with dynamic content' },
	{
		pattern: /base64\s+(--)?d(ecode)?/i,
		description: 'Base64 decode execution',
	},
	{ pattern: /\$\(curl/i, description: 'Command substitution with curl' },
	{ pattern: /\$\(wget/i, description: 'Command substitution with wget' },
	{
		pattern: /node\s+-e\s+['"].*?(http|eval|Buffer\.from)/i,
		description: 'Inline Node.js code execution',
	},
	{
		pattern: /npx\s+--yes\s+[^@\s]+@/i,
		description: 'NPX auto-install of versioned package',
	},
];

// TruffleHog and credential scanning patterns
const TRUFFLEHOG_PATTERNS = [
	{ pattern: /trufflehog/i, description: 'TruffleHog reference detected' },
	{ pattern: /trufflesecurity/i, description: 'TruffleSecurity reference' },
	{
		pattern: /credential[_-]?scan/i,
		description: 'Credential scanning pattern',
	},
	{ pattern: /secret[_-]?scan/i, description: 'Secret scanning pattern' },
	{ pattern: /--json\s+--no-update/i, description: 'TruffleHog CLI pattern' },
	{
		pattern: /github\.com\/trufflesecurity\/trufflehog/i,
		description: 'TruffleHog GitHub download',
	},
	{
		pattern: /releases\/download.*trufflehog/i,
		description: 'TruffleHog binary download',
	},
];

// Shai-Hulud repository indicators
const SHAI_HULUD_REPO_PATTERNS = [
	{ pattern: /shai[-_]?hulud/i, description: 'Shai-Hulud repository name' },
	{
		pattern: /the\s+second\s+coming/i,
		description: 'Shai-Hulud campaign description',
	},
	{ pattern: /sha1hulud/i, description: 'SHA1HULUD variant' },
];

// Malicious runner patterns in GitHub Actions
const MALICIOUS_RUNNER_PATTERNS = [
	{
		pattern: /runs-on:\s*['"]?SHA1HULUD/i,
		description: 'SHA1HULUD malicious runner',
	},
	{
		pattern: /runs-on:\s*['"]?self-hosted.*SHA1HULUD/i,
		description: 'Self-hosted SHA1HULUD runner',
	},
	{
		pattern: /runner[_-]?name.*SHA1HULUD/i,
		description: 'SHA1HULUD runner reference',
	},
	{ pattern: /labels:.*SHA1HULUD/i, description: 'SHA1HULUD runner label' },
];

// Malicious workflow file patterns
const MALICIOUS_WORKFLOW_PATTERNS = [
	{
		pattern: /formatter_.*\.yml$/i,
		description: 'Shai-Hulud formatter workflow (formatter_*.yml)',
	},
	{
		pattern: /discussion\.ya?ml$/i,
		description: 'Shai-Hulud discussion workflow',
	},
];

// Medium Risk: Suspicious content patterns (webhook exfiltration)
const WEBHOOK_EXFIL_PATTERNS = [
	{
		pattern: /webhook\.site/i,
		description: 'Webhook.site exfiltration endpoint',
	},
	{
		pattern: /bb8ca5f6-4175-45d2-b042-fc9ebb8170b7/i,
		description: 'Known malicious webhook UUID',
	},
	{ pattern: /exfiltrat/i, description: 'Exfiltration reference' },
];

// Known affected namespaces (for low-risk warnings)
const AFFECTED_NAMESPACES = [
	'@zapier',
	'@posthog',
	'@asyncapi',
	'@postman',
	'@ensdomains',
	'@ens',
	'@voiceflow',
	'@browserbase',
	'@ctrl',
	'@crowdstrike',
	'@art-ws',
	'@ngx',
	'@nativescript-community',
	'@oku-ui',
];

// Files/paths to exclude from scanning (detector's own source code)
const EXCLUDED_PATHS = [
	/shai-hulud.*detector/i,
	/\/src\/scanner\.(ts|js)$/i,
	/\/src\/types\.(ts|js)$/i,
	/\/src\/index\.(ts|js)$/i,
	/\/dist\/index\.js$/i,
	/\/dist\/.*\.d\.ts$/i,
  /\/[^/]*\.xcassets\/.*\/contents\.json$/i,
];

/**
 * Determine whether a file path should be excluded from security scanning to avoid
 * self-referencing false positives (the detector's own source/build artifacts).
 * Normalizes path separators and matches against a curated exclusion pattern list.
 * @param filePath Absolute or relative path to evaluate.
 * @returns true if the path should be skipped.
 */
function isExcludedPath(filePath: string): boolean {
	// Normalize path separators
	const normalizedPath = filePath.replace(/\\/g, '/');

	// Check if this looks like the detector's own source
	for (const pattern of EXCLUDED_PATHS) {
		if (pattern.test(normalizedPath)) {
			return true;
		}
	}

	// Also exclude if the file contains detector identification markers
	return false;
}

/**
 * Heuristically identify the detector's own source code by counting unique marker
 * strings present in the file content. Used to suppress self-scan findings.
 * @param content Raw file contents (UTF-8 decoded).
 * @returns true if content is likely detector source code.
 */
function isDetectorSourceCode(content: string): boolean {
	// Check for unique markers that identify this as the detector's source
	const detectorMarkers = [
		'SHAI-HULUD 2.0 SUPPLY CHAIN ATTACK DETECTOR',
		'gensecaihq/Shai-Hulud-2.0-Detector',
		'SUSPICIOUS PATTERNS FOR ADVANCED DETECTION',
		'checkTrufflehogActivity',
		'checkMaliciousRunners',
	];

	let markerCount = 0;
	for (const marker of detectorMarkers) {
		if (content.includes(marker)) {
			markerCount++;
		}
	}

	// If 2+ markers found, this is likely the detector's source
	return markerCount >= 2;
}

const masterPackages: MasterPackages = masterPackagesData as MasterPackages;

// Create a Set for O(1) lookup
const affectedPackageNames = new Set(
	masterPackages.packages.map((p) => p.name),
);

/**
 * Fast membership check for whether a package name appears in the compromised
 * master package list.
 * @param packageName The dependency name to check.
 * @returns true if the package is flagged as affected.
 */
export function isAffected(packageName: string): boolean {
	return affectedPackageNames.has(packageName);
}

/**
 * Retrieve the recorded severity for an affected package. Defaults to 'critical'
 * if the package entry is missing (defensive fallback).
 * @param packageName Name of the compromised package.
 * @returns Severity classification.
 */
export function getPackageSeverity(
	packageName: string,
): 'critical' | 'high' | 'medium' | 'low' {
	const pkg = masterPackages.packages.find((p) => p.name === packageName);
	return pkg?.severity || 'critical';
}

/**
 * Safely parse a package.json file returning null if unreadable or invalid JSON.
 * @param filePath Path to a package.json file.
 * @returns Parsed PackageJson object or null on failure.
 */
export function parsePackageJson(filePath: string): PackageJson | null {
	try {
		const content = fs.readFileSync(filePath, 'utf8');
		return JSON.parse(content) as PackageJson;
	} catch {
		return null;
	}
}

/**
 * Parse a package-lock.json (v1/v2/v3) or npm-shrinkwrap.json file with graceful
 * failure on read/parse errors.
 * @param filePath Lockfile path.
 * @returns Parsed PackageLock object or null on failure.
 */
export function parsePackageLock(filePath: string): PackageLock | null {
	try {
		const content = fs.readFileSync(filePath, 'utf8');
		return JSON.parse(content) as PackageLock;
	} catch {
		return null;
	}
}

/**
 * Lightweight yarn.lock parser extracting package name -> version mappings.
 * Only intended for identifying affected packages; not a full fidelity parser.
 * @param filePath yarn.lock file path.
 * @returns Map of package names to versions or null on failure.
 */
export function parseYarnLock(filePath: string): Map<string, string> | null {
	try {
		const content = fs.readFileSync(filePath, 'utf8');
		const packages = new Map<string, string>();

		// Simple yarn.lock parser - extract package names
		const lines = content.split('\n');
		let currentPackage = '';

		for (const line of lines) {
			// Package declaration lines start without whitespace and contain @
			if (
				!line.startsWith(' ') &&
				!line.startsWith('#') &&
				line.includes('@')
			) {
				// Parse package name from lines like:
				// "@asyncapi/diff@^1.0.0":
				// "posthog-node@^5.0.0":
				const match = line.match(/^"?(@?[^@\s"]+)/);
				if (match) {
					currentPackage = match[1];
				}
			}
			// Version line
			if (line.trim().startsWith('version') && currentPackage) {
				const versionMatch = line.match(/version\s+"([^"]+)"/);
				if (versionMatch) {
					packages.set(currentPackage, versionMatch[1]);
				}
			}
		}

		return packages;
	} catch {
		return null;
	}
}

/**
 * Scan a package.json for compromised dependencies across all dependency blocks
 * (dependencies, dev, peer, optional). Marks each finding with direct/transitive flag.
 * @param filePath Path to package.json.
 * @param isDirect Whether dependencies should be considered direct (root-level scan).
 * @returns List of ScanResult entries.
 */
export function scanPackageJson(
	filePath: string,
	isDirect: boolean = true,
): ScanResult[] {
	const results: ScanResult[] = [];
	const pkg = parsePackageJson(filePath);

	if (!pkg) return results;

	const allDeps = {
		...pkg.dependencies,
		...pkg.devDependencies,
		...pkg.peerDependencies,
		...pkg.optionalDependencies,
	};

	for (const [name, version] of Object.entries(allDeps)) {
		if (isAffected(name)) {
			results.push({
				package: name,
				version: version || 'unknown',
				severity: getPackageSeverity(name),
				isDirect,
				location: filePath,
			});
		}
	}

	return results;
}

/**
 * Scan an npm lockfile (v1/v2/v3) for affected packages. Determines direct vs
 * transitive based on path nesting for v2+ format.
 * @param filePath Lockfile path.
 * @returns ScanResult list of affected packages.
 */
export function scanPackageLock(filePath: string): ScanResult[] {
	const results: ScanResult[] = [];
	const lock = parsePackageLock(filePath);

	if (!lock) return results;

	// Scan v2/v3 lockfile format (packages object)
	if (lock.packages) {
		for (const [pkgPath, entry] of Object.entries(lock.packages)) {
			// Extract package name from path like "node_modules/@asyncapi/diff"
			const match = pkgPath.match(/node_modules\/(.+)$/);
			if (match) {
				const name = match[1];
				if (isAffected(name)) {
					results.push({
						package: name,
						version: entry.version || 'unknown',
						severity: getPackageSeverity(name),
						isDirect: !pkgPath.includes('node_modules/node_modules'),
						location: filePath,
					});
				}
			}
		}
	}

	// Scan v1 lockfile format (dependencies object)
	if (lock.dependencies) {
		const scanDependencies = (deps: Record<string, any>, isDirect: boolean) => {
			for (const [name, entry] of Object.entries(deps)) {
				if (isAffected(name)) {
					results.push({
						package: name,
						version: entry.version || 'unknown',
						severity: getPackageSeverity(name),
						isDirect,
						location: filePath,
					});
				}
				// Recursively scan nested dependencies
				if (entry.dependencies) {
					scanDependencies(entry.dependencies, false);
				}
			}
		};
		scanDependencies(lock.dependencies, true);
	}

	return results;
}

/**
 * Scan a yarn.lock for affected packages. Yarn lockfiles do not distinguish
 * direct vs transitive so all findings are marked transitive.
 * @param filePath yarn.lock path.
 * @returns ScanResult list.
 */
export function scanYarnLock(filePath: string): ScanResult[] {
	const results: ScanResult[] = [];
	const packages = parseYarnLock(filePath);

	if (!packages) return results;

	for (const [name, version] of packages.entries()) {
		if (isAffected(name)) {
			results.push({
				package: name,
				version,
				severity: getPackageSeverity(name),
				isDirect: false, // yarn.lock doesn't indicate direct vs transitive
				location: filePath,
			});
		}
	}

	return results;
}

/**
 * Discover recognized lockfiles recursively (depth <= 5) excluding node_modules
 * and hidden directories.
 * @param directory Root directory to begin search.
 * @param scanNodeModules Whether to include node_modules directories in the scan. Defaults to false.
 * @returns Array of absolute lockfile paths.
 */
export function findLockfiles(directory: string, scanNodeModules: boolean = false): string[] {
	const lockfiles: string[] = [];
	const possibleFiles = [
		'package-lock.json',
		'yarn.lock',
		'pnpm-lock.yaml',
		'npm-shrinkwrap.json',
	];

	// Search in root and subdirectories (for monorepos)
	const searchDir = (dir: string, depth: number = 0) => {
		if (depth > 5) return; // Limit depth to prevent excessive recursion

		try {
			const entries = fs.readdirSync(dir, { withFileTypes: true });

			for (const entry of entries) {
				const fullPath = path.join(dir, entry.name);

				if (entry.isFile() && possibleFiles.includes(entry.name)) {
					lockfiles.push(fullPath);
				} else if (
					entry.isDirectory() &&
					!entry.name.startsWith('.') &&
					(scanNodeModules || entry.name !== 'node_modules')
				) {
					searchDir(fullPath, depth + 1);
				}
			}
		} catch {
			// Skip directories we can't read
		}
	};

	searchDir(directory);
	return lockfiles;
}

/**
 * Recursively locate package.json files up to depth 5 (monorepo friendly), skipping
 * node_modules and dot-prefixed directories.
 * @param directory Root search directory.
 * @param scanNodeModules Whether to include node_modules directories in the scan. Defaults to false.
 * @returns Array of package.json paths.
 */
export function findPackageJsonFiles(directory: string, scanNodeModules: boolean = false): string[] {
	const packageFiles: string[] = [];

	const searchDir = (dir: string, depth: number = 0) => {
		if (depth > 5) return;

		try {
			const entries = fs.readdirSync(dir, { withFileTypes: true });

			for (const entry of entries) {
				const fullPath = path.join(dir, entry.name);

				if (entry.isFile() && entry.name === 'package.json') {
					packageFiles.push(fullPath);
				} else if (
					entry.isDirectory() &&
					!entry.name.startsWith('.') &&
					(scanNodeModules || entry.name !== 'node_modules')
				) {
					searchDir(fullPath, depth + 1);
				}
			}
		} catch {
			// Skip directories we can't read
		}
	};

	searchDir(directory);
	return packageFiles;
}

// =============================================================================
// ADVANCED SECURITY CHECKS
// =============================================================================

/**
 * Inspect scripts in a package.json for indicators of compromise (IoCs) and general
 * suspicious execution patterns (curl|sh, wget|sh, eval, base64 decode, inline node -e, etc.).
 * Critical severity is assigned to malicious Shai-Hulud artifacts or dangerous lifecycle hooks.
 * @param filePath Path to package.json.
 * @returns SecurityFinding list.
 */
export function checkSuspiciousScripts(filePath: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const pkg = parsePackageJson(filePath);

	if (!pkg || !pkg.scripts) return findings;

	for (const [scriptName, scriptContent] of Object.entries(pkg.scripts)) {
		if (!scriptContent) continue;

		// Check for Shai-Hulud specific patterns (Critical)
		if (
			/setup_bun\.js/i.test(scriptContent) ||
			/bun_environment\.js/i.test(scriptContent)
		) {
			findings.push({
				type: 'suspicious-script',
				severity: 'critical',
				title: `Shai-Hulud malicious script in "${scriptName}"`,
				description: `The "${scriptName}" script contains a reference to known Shai-Hulud malicious files. This is a strong indicator of compromise.`,
				location: filePath,
				evidence: `"${scriptName}": "${scriptContent}"`,
			});
			continue;
		}

		// Check all suspicious patterns
		for (const { pattern, description } of SUSPICIOUS_SCRIPT_PATTERNS) {
			if (pattern.test(scriptContent)) {
				// preinstall/postinstall with suspicious commands are higher severity
				const isCritical =
					['preinstall', 'postinstall', 'prepare', 'prepublish'].includes(
						scriptName,
					) &&
					(pattern.test(scriptContent) ||
						/curl|wget|eval/i.test(scriptContent));

				findings.push({
					type: 'suspicious-script',
					severity: isCritical ? 'critical' : 'high',
					title: `Suspicious "${scriptName}" script`,
					description: `${description}. This pattern is commonly used in supply chain attacks.`,
					location: filePath,
					evidence: `"${scriptName}": "${scriptContent.substring(0, 200)}${scriptContent.length > 200 ? '...' : ''}"`,
				});
				break; // Only report first match per script
			}
		}
	}

	return findings;
}

/**
 * Traverse the repository (depth <= 5) searching for TruffleHog references, payload
 * artifacts, and exfiltration endpoints in script & code files. Skips detector sources
 * via path/content heuristics.
 * @param directory Root directory to scan.
 * @returns SecurityFinding list of critical indicators.
 */
export function checkTrufflehogActivity(directory: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const suspiciousFiles: string[] = [];

	const searchDir = (dir: string, depth: number = 0) => {
		if (depth > 5) return;

		try {
			const entries = fs.readdirSync(dir, { withFileTypes: true });

			for (const entry of entries) {
				const fullPath = path.join(dir, entry.name);

				if (entry.isFile()) {
					// Check for TruffleHog binary or related files
					if (
						/trufflehog/i.test(entry.name) ||
						entry.name === 'bun_environment.js' ||
						entry.name === 'setup_bun.js'
					) {
						suspiciousFiles.push(fullPath);
					}

					// Scan content of shell scripts and JS files
					if (/\.(sh|js|ts|mjs|cjs)$/i.test(entry.name)) {
						// Skip excluded paths (detector's own source code)
						if (isExcludedPath(fullPath)) {
							continue;
						}

						try {
							const content = fs.readFileSync(fullPath, 'utf8');

							// Skip if this is the detector's own source code
							if (isDetectorSourceCode(content)) {
								continue;
							}

							for (const { pattern, description } of TRUFFLEHOG_PATTERNS) {
								if (pattern.test(content)) {
									findings.push({
										type: 'trufflehog-activity',
										severity: 'critical',
										title: `TruffleHog activity detected`,
										description: `${description}. This may indicate automated credential theft as part of the Shai-Hulud attack.`,
										location: fullPath,
										evidence: pattern.toString(),
									});
									break;
								}
							}

							// Check for webhook exfiltration
							for (const { pattern, description } of WEBHOOK_EXFIL_PATTERNS) {
								if (pattern.test(content)) {
									findings.push({
										type: 'secrets-exfiltration',
										severity: 'critical',
										title: `Data exfiltration endpoint detected`,
										description: `${description}. This endpoint may be used to exfiltrate stolen credentials.`,
										location: fullPath,
										evidence: pattern.toString(),
									});
									break;
								}
							}
						} catch {
							// Skip files we can't read
						}
					}
				} else if (
					entry.isDirectory() &&
					!entry.name.startsWith('.') &&
					entry.name !== 'node_modules'
				) {
					searchDir(fullPath, depth + 1);
				}
			}
		} catch {
			// Skip directories we can't read
		}
	};

	searchDir(directory);

	// Report suspicious files found
	for (const file of suspiciousFiles) {
		const fileName = path.basename(file);
		findings.push({
			type: 'trufflehog-activity',
			severity: 'critical',
			title: `Suspicious file: ${fileName}`,
			description: `Found file "${fileName}" which is associated with the Shai-Hulud attack. This file may download and execute TruffleHog for credential theft.`,
			location: file,
		});
	}

	return findings;
}

/**
 * Detect presence of Shai-Hulud exfiltration output files (actionsSecrets.json, cloud.json,
 * contents.json, environment.json, truffleSecrets.json, etc.) and large obfuscated payloads.
 * Also flags potential encoded secrets JSON files.
 * @param directory Root directory.
 * @returns SecurityFinding list.
 */
export function checkSecretsExfiltration(directory: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	const searchDir = (dir: string, depth: number = 0) => {
		if (depth > 5) return;

		try {
			const entries = fs.readdirSync(dir, { withFileTypes: true });

			for (const entry of entries) {
				const fullPath = path.join(dir, entry.name);

				if (entry.isFile()) {
					// Check for actionsSecrets.json
					if (entry.name === 'actionsSecrets.json') {
						findings.push({
							type: 'secrets-exfiltration',
							severity: 'critical',
							title: `Secrets exfiltration file detected`,
							description: `Found "actionsSecrets.json" which is used by the Shai-Hulud attack to store stolen credentials with double Base64 encoding before exfiltration.`,
							location: fullPath,
						});
					}

					// Check for known Shai-Hulud exfiltration/output files
					const knownMaliciousFiles = [
						'cloud.json',
						'contents.json',
						'environment.json',
						'truffleSecrets.json',
						'trufflehog_output.json',
					];
					if (knownMaliciousFiles.includes(entry.name.toLowerCase())) {
            const isXcodeAssetContents =
              /\/[^/]+\.xcassets\/(?:.*\/)?contents\.json$/i.test(fullPath);
            if (isXcodeAssetContents) {
              continue;
            }
						findings.push({
							type: 'secrets-exfiltration',
							severity: 'critical',
							title: `Shai-Hulud output file: ${entry.name}`,
							description: `Found "${entry.name}" which is a known output file from the Shai-Hulud attack containing harvested credentials or environment data.`,
							location: fullPath,
						});
					}

					// Check for large obfuscated JS files (bun_environment.js is typically 10MB+)
					if (entry.name === 'bun_environment.js') {
						try {
							const stats = fs.statSync(fullPath);
							const sizeMB = stats.size / (1024 * 1024);
							findings.push({
								type: 'trufflehog-activity',
								severity: 'critical',
								title: `Shai-Hulud payload file: bun_environment.js`,
								description: `Found "bun_environment.js" (${sizeMB.toFixed(2)}MB). This is the main obfuscated payload used by the Shai-Hulud attack to execute TruffleHog for credential theft.`,
								location: fullPath,
								evidence: `File size: ${sizeMB.toFixed(2)}MB`,
							});
						} catch {
							// If we can't stat, still report it
							findings.push({
								type: 'trufflehog-activity',
								severity: 'critical',
								title: `Shai-Hulud payload file: bun_environment.js`,
								description: `Found "bun_environment.js" which is the main obfuscated payload used by the Shai-Hulud attack.`,
								location: fullPath,
							});
						}
					}

					// Check for other suspicious JSON files that might contain secrets
					if (
						/secrets?\.json$/i.test(entry.name) ||
						/credentials?\.json$/i.test(entry.name) ||
						/exfil.*\.json$/i.test(entry.name)
					) {
						try {
							const content = fs.readFileSync(fullPath, 'utf8');
							// Check if it looks like base64 encoded data
							if (/^[A-Za-z0-9+/=]{100,}$/m.test(content)) {
								findings.push({
									type: 'secrets-exfiltration',
									severity: 'high',
									title: `Potential secrets file with encoded data`,
									description: `Found "${entry.name}" containing what appears to be Base64 encoded data. This may be exfiltrated credentials.`,
									location: fullPath,
								});
							}
						} catch {
							// Skip files we can't read
						}
					}
				} else if (
					entry.isDirectory() &&
					!entry.name.startsWith('.') &&
					entry.name !== 'node_modules'
				) {
					searchDir(fullPath, depth + 1);
				}
			}
		} catch {
			// Skip directories we can't read
		}
	};

	searchDir(directory);
	return findings;
}

/**
 * Scan GitHub Actions workflow YAML files for malicious runner labels (SHA1HULUD),
 * suspicious workflow filenames, and Shai-Hulud repository indicators while excluding
 * legitimate detector usage.
 * @param directory Root repository directory.
 * @returns SecurityFinding list.
 */
export function checkMaliciousRunners(directory: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const workflowDirs = [
		path.join(directory, '.github', 'workflows'),
		path.join(directory, '.github'),
	];

	// Pattern to identify legitimate detector workflows (exclude from false positives)
	const DETECTOR_WORKFLOW_PATTERN =
		/gensecaihq\/Shai-Hulud-2\.0-Detector|Shai-Hulud.*Detector|shai-hulud-check|shai-hulud.*security/i;

	for (const workflowDir of workflowDirs) {
		if (!fs.existsSync(workflowDir)) continue;

		try {
			const entries = fs.readdirSync(workflowDir, { withFileTypes: true });

			for (const entry of entries) {
				if (!entry.isFile()) continue;
				if (!/\.(yml|yaml)$/i.test(entry.name)) continue;

				const fullPath = path.join(workflowDir, entry.name);

				// Check for malicious workflow filename patterns (formatter_*.yml, discussion.yaml)
				for (const { pattern, description } of MALICIOUS_WORKFLOW_PATTERNS) {
					if (pattern.test(entry.name)) {
						findings.push({
							type: 'malicious-runner',
							severity: 'critical',
							title: `Suspicious workflow file: ${entry.name}`,
							description: `${description}. This workflow filename matches patterns used by the Shai-Hulud attack for credential theft.`,
							location: fullPath,
							evidence: entry.name,
						});
					}
				}

				try {
					const content = fs.readFileSync(fullPath, 'utf8');

					// Skip workflows that are using the detector (legitimate use)
					if (
						DETECTOR_WORKFLOW_PATTERN.test(content) ||
						DETECTOR_WORKFLOW_PATTERN.test(entry.name)
					) {
						continue;
					}

					// Check for malicious runner patterns
					for (const { pattern, description } of MALICIOUS_RUNNER_PATTERNS) {
						if (pattern.test(content)) {
							findings.push({
								type: 'malicious-runner',
								severity: 'critical',
								title: `Malicious GitHub Actions runner detected`,
								description: `${description}. The SHA1HULUD runner is used by the Shai-Hulud attack to execute credential theft in CI/CD environments.`,
								location: fullPath,
								evidence: pattern.toString(),
							});
						}
					}

					// Check for Shai-Hulud repo patterns in workflow (excluding detector references)
					for (const { pattern, description } of SHAI_HULUD_REPO_PATTERNS) {
						if (pattern.test(content)) {
							// Additional check: make sure it's not just referencing the detector
							const contentWithoutDetector = content.replace(
								/gensecaihq\/Shai-Hulud-2\.0-Detector[^\s]*/gi,
								'',
							);
							if (pattern.test(contentWithoutDetector)) {
								findings.push({
									type: 'shai-hulud-repo',
									severity: 'critical',
									title: `Shai-Hulud reference in workflow`,
									description: `${description}. This workflow may be configured to exfiltrate data to attacker-controlled repositories.`,
									location: fullPath,
									evidence: pattern.toString(),
								});
							}
						}
					}
				} catch {
					// Skip files we can't read
				}
			}
		} catch {
			// Skip directories we can't read
		}
	}

	return findings;
}

/**
 * Inspect git config and package.json files for Shai-Hulud repository related markers
 * excluding references to the detector itself. Flags remote/potential infra compromise.
 * @param directory Root repo directory.
 * @returns SecurityFinding list.
 */
export function checkShaiHuludRepos(directory: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	// Check git config
	const gitConfigPath = path.join(directory, '.git', 'config');
	if (fs.existsSync(gitConfigPath)) {
		try {
			const content = fs.readFileSync(gitConfigPath, 'utf8');

			// Skip if this is the detector's own repository
			if (
				content.includes('Shai-Hulud-2.0-Detector') ||
				content.includes('gensecaihq')
			) {
				// This is the detector's own repo, skip
			} else {
				for (const { pattern, description } of SHAI_HULUD_REPO_PATTERNS) {
					if (pattern.test(content)) {
						findings.push({
							type: 'shai-hulud-repo',
							severity: 'critical',
							title: `Shai-Hulud repository reference in git config`,
							description: `${description}. Your repository may have been configured to push to an attacker-controlled remote.`,
							location: gitConfigPath,
						});
					}
				}
			}
		} catch {
			// Skip if we can't read
		}
	}

	// Check package.json for repository references
	const packageJsonFiles = findPackageJsonFiles(directory);
	for (const file of packageJsonFiles) {
		try {
			const content = fs.readFileSync(file, 'utf8');

			// Skip if this is the detector's own package.json
			if (
				content.includes('gensecaihq/Shai-Hulud-2.0-Detector') ||
				content.includes('shai-hulud-detector')
			) {
				continue;
			}

			for (const { pattern, description } of SHAI_HULUD_REPO_PATTERNS) {
				if (pattern.test(content)) {
					// Make sure it's not just a reference to the detector
					const contentWithoutDetector = content
						.replace(/gensecaihq\/Shai-Hulud-2\.0-Detector/gi, '')
						.replace(/shai-hulud-detector/gi, '');
					if (pattern.test(contentWithoutDetector)) {
						findings.push({
							type: 'shai-hulud-repo',
							severity: 'high',
							title: `Shai-Hulud reference in package.json`,
							description: `${description}. Package may be configured to reference attacker infrastructure.`,
							location: file,
						});
					}
				}
			}
		} catch {
			// Skip if we can't read
		}
	}

	return findings;
}

/**
 * Produce low severity warnings for dependencies from organizations affected in the
 * campaign when semver ranges (caret/tilde) may auto-update into compromised versions.
 * Skips already known compromised packages.
 * @param filePath Path to package.json.
 * @returns SecurityFinding list (low severity).
 */
export function checkAffectedNamespaces(filePath: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const pkg = parsePackageJson(filePath);

	if (!pkg) return findings;

	const allDeps = {
		...pkg.dependencies,
		...pkg.devDependencies,
		...pkg.peerDependencies,
		...pkg.optionalDependencies,
	};

	for (const [name, version] of Object.entries(allDeps)) {
		// Skip if already in affected packages list
		if (isAffected(name)) continue;

		// Check if from affected namespace
		for (const namespace of AFFECTED_NAMESPACES) {
			if (name.startsWith(namespace + '/')) {
				// Check for semver range patterns that could auto-update to compromised versions
				if (version && (version.startsWith('^') || version.startsWith('~'))) {
					findings.push({
						type: 'compromised-package',
						severity: 'low',
						title: `Package from affected namespace with semver range`,
						description: `"${name}" is from the ${namespace} namespace which has known compromised packages. The version pattern "${version}" could auto-update to a compromised version during npm update.`,
						location: filePath,
						evidence: `"${name}": "${version}"`,
					});
				}
				break;
			}
		}
	}

	return findings;
}

/**
 * Check local git branch names for Shai-Hulud related indicators to surface possible
 * attack propagation or staging branches.
 * @param directory Repository root.
 * @returns SecurityFinding list (medium severity).
 */
export function checkSuspiciousBranches(directory: string): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const headsPath = path.join(directory, '.git', 'refs', 'heads');

	if (!fs.existsSync(headsPath)) return findings;

	try {
		const branches = fs.readdirSync(headsPath);

		for (const branch of branches) {
			for (const { pattern, description } of SHAI_HULUD_REPO_PATTERNS) {
				if (pattern.test(branch)) {
					findings.push({
						type: 'shai-hulud-repo',
						severity: 'medium',
						title: `Suspicious git branch: ${branch}`,
						description: `${description}. This branch name is associated with the Shai-Hulud attack campaign.`,
						location: path.join(headsPath, branch),
					});
				}
			}
		}
	} catch {
		// Skip if we can't read
	}

	return findings;
}

/**
 * Orchestrate full scan: package.json files, optional lockfiles, and advanced security
 * checks (scripts, TruffleHog activity, exfiltration files, malicious runners, repo refs,
 * suspicious branches). Aggregates and de-duplicates findings, returning a structured summary.
 * @param directory Root directory to scan.
 * @param scanLockfiles Whether to include lockfile scanning.
 * @param scanNodeModules Whether to include node_modules directories in package.json scans. Defaults to false.
 * @returns Comprehensive ScanSummary.
 */
export function runScan(
	directory: string,
	scanLockfiles: boolean = true,
	scanNodeModules: boolean = false,
): ScanSummary {
	const startTime = Date.now();
	const allResults: ScanResult[] = [];
	const allSecurityFindings: SecurityFinding[] = [];
	const scannedFiles: string[] = [];
	const seenPackages = new Set<string>();
	const seenFindings = new Set<string>();

	// Scan package.json files
	const packageJsonFiles = findPackageJsonFiles(directory, scanNodeModules);
	for (const file of packageJsonFiles) {
		scannedFiles.push(file);
		const results = scanPackageJson(file, true);
		for (const result of results) {
			const key = `${result.package}@${result.version}`;
			if (!seenPackages.has(key)) {
				seenPackages.add(key);
				allResults.push(result);
			}
		}

		// Check for suspicious scripts in package.json
		const scriptFindings = checkSuspiciousScripts(file);
		for (const finding of scriptFindings) {
			const key = `${finding.type}:${finding.location}:${finding.title}`;
			if (!seenFindings.has(key)) {
				seenFindings.add(key);
				allSecurityFindings.push(finding);
			}
		}

		// Check for packages from affected namespaces
		const namespaceFindings = checkAffectedNamespaces(file);
		for (const finding of namespaceFindings) {
			const key = `${finding.type}:${finding.location}:${finding.title}`;
			if (!seenFindings.has(key)) {
				seenFindings.add(key);
				allSecurityFindings.push(finding);
			}
		}
	}

	// Scan lockfiles if enabled
	if (scanLockfiles) {
		const lockfiles = findLockfiles(directory, scanNodeModules);
		for (const file of lockfiles) {
			scannedFiles.push(file);

			let results: ScanResult[] = [];
			if (
				file.endsWith('package-lock.json') ||
				file.endsWith('npm-shrinkwrap.json')
			) {
				results = scanPackageLock(file);
			} else if (file.endsWith('yarn.lock')) {
				results = scanYarnLock(file);
			}
			// TODO: Add pnpm-lock.yaml support

			for (const result of results) {
				const key = `${result.package}@${result.version}`;
				if (!seenPackages.has(key)) {
					seenPackages.add(key);
					allResults.push(result);
				}
			}
		}
	}

	// ==========================================================================
	// ADVANCED SECURITY CHECKS
	// ==========================================================================

	// Check for TruffleHog activity and credential scanning
	const trufflehogFindings = checkTrufflehogActivity(directory);
	for (const finding of trufflehogFindings) {
		const key = `${finding.type}:${finding.location}:${finding.title}`;
		if (!seenFindings.has(key)) {
			seenFindings.add(key);
			allSecurityFindings.push(finding);
		}
	}

	// Check for secrets exfiltration files (actionsSecrets.json)
	const exfilFindings = checkSecretsExfiltration(directory);
	for (const finding of exfilFindings) {
		const key = `${finding.type}:${finding.location}:${finding.title}`;
		if (!seenFindings.has(key)) {
			seenFindings.add(key);
			allSecurityFindings.push(finding);
		}
	}

	// Check GitHub Actions workflows for malicious runners
	const runnerFindings = checkMaliciousRunners(directory);
	for (const finding of runnerFindings) {
		const key = `${finding.type}:${finding.location}:${finding.title}`;
		if (!seenFindings.has(key)) {
			seenFindings.add(key);
			allSecurityFindings.push(finding);
		}
	}

	// Check for Shai-Hulud repository references
	const repoFindings = checkShaiHuludRepos(directory);
	for (const finding of repoFindings) {
		const key = `${finding.type}:${finding.location}:${finding.title}`;
		if (!seenFindings.has(key)) {
			seenFindings.add(key);
			allSecurityFindings.push(finding);
		}
	}

	// Check for suspicious git branches
	const branchFindings = checkSuspiciousBranches(directory);
	for (const finding of branchFindings) {
		const key = `${finding.type}:${finding.location}:${finding.title}`;
		if (!seenFindings.has(key)) {
			seenFindings.add(key);
			allSecurityFindings.push(finding);
		}
	}

	// Sort results by severity
	const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
	allResults.sort(
		(a, b) => severityOrder[a.severity] - severityOrder[b.severity],
	);

	// Sort security findings by severity
	allSecurityFindings.sort(
		(a, b) => severityOrder[a.severity] - severityOrder[b.severity],
	);

	return {
		totalDependencies: seenPackages.size,
		affectedCount: allResults.length,
		cleanCount: seenPackages.size - allResults.length,
		results: allResults,
		securityFindings: allSecurityFindings,
		scannedFiles,
		scanTime: Date.now() - startTime,
	};
}

/**
 * Transform a ScanSummary into a SARIF 2.1.0 compliant result set including unique rules
 * for each compromised package and security finding.
 * @param summary Completed scan summary.
 * @returns SARIF result object suitable for upload.
 */
export function generateSarifReport(summary: ScanSummary): SarifResult {
	const rules: any[] = [];
	const results: any[] = [];

	// Create unique rules for each affected package
	const ruleMap = new Map<string, string>();
	let ruleIndex = 0;

	for (const result of summary.results) {
		let ruleId = ruleMap.get(result.package);
		if (!ruleId) {
			ruleId = `SHAI-HULUD-${String(++ruleIndex).padStart(4, '0')}`;
			ruleMap.set(result.package, ruleId);

			rules.push({
				id: ruleId,
				name: `CompromisedPackage_${result.package.replace(/[^a-zA-Z0-9]/g, '_')}`,
				shortDescription: {
					text: `Compromised package: ${result.package}`,
				},
				fullDescription: {
					text: `The package "${result.package}" has been identified as compromised in the Shai-Hulud 2.0 supply chain attack. This package may contain malicious code that steals credentials and exfiltrates sensitive data.`,
				},
				helpUri:
					'https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains',
				defaultConfiguration: {
					level: result.severity === 'critical' ? 'error' : 'warning',
				},
			});
		}

		results.push({
			ruleId,
			level: result.severity === 'critical' ? 'error' : 'warning',
			message: {
				text: `Compromised package "${result.package}@${result.version}" detected. This package is part of the Shai-Hulud 2.0 supply chain attack.`,
			},
			locations: [
				{
					physicalLocation: {
						artifactLocation: {
							uri: result.location,
						},
					},
				},
			],
		});
	}

	// Add security findings to SARIF report
	const findingTypeToRulePrefix: Record<string, string> = {
		'suspicious-script': 'SCRIPT',
		'trufflehog-activity': 'TRUFFLEHOG',
		'shai-hulud-repo': 'REPO',
		'secrets-exfiltration': 'EXFIL',
		'malicious-runner': 'RUNNER',
		'compromised-package': 'PKG',
	};

	for (const finding of summary.securityFindings) {
		const prefix = findingTypeToRulePrefix[finding.type] || 'SEC';
		const ruleKey = `${finding.type}:${finding.title}`;
		let ruleId = ruleMap.get(ruleKey);

		if (!ruleId) {
			ruleId = `SHAI-${prefix}-${String(++ruleIndex).padStart(4, '0')}`;
			ruleMap.set(ruleKey, ruleId);

			rules.push({
				id: ruleId,
				name: finding.title.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 64),
				shortDescription: {
					text: finding.title,
				},
				fullDescription: {
					text: finding.description,
				},
				helpUri:
					'https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains',
				defaultConfiguration: {
					level:
						finding.severity === 'critical'
							? 'error'
							: finding.severity === 'high'
								? 'warning'
								: 'note',
				},
			});
		}

		results.push({
			ruleId,
			level:
				finding.severity === 'critical'
					? 'error'
					: finding.severity === 'high'
						? 'warning'
						: 'note',
			message: {
				text: `${finding.title}: ${finding.description}${finding.evidence ? `\n\nEvidence: ${finding.evidence}` : ''}`,
			},
			locations: [
				{
					physicalLocation: {
						artifactLocation: {
							uri: finding.location,
						},
						...(finding.line && {
							region: {
								startLine: finding.line,
							},
						}),
					},
				},
			],
		});
	}

	return {
		$schema:
			'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
		version: '2.1.0',
		runs: [
			{
				tool: {
					driver: {
						name: 'shai-hulud-detector',
						version: '1.0.0',
						informationUri:
							'https://github.com/gensecaihq/Shai-Hulud-2.0-Detector',
						rules,
					},
				},
				results,
			},
		],
	};
}

/**
 * Render human-readable multi-section text output summarizing compromised packages,
 * grouped security findings and recommended remediation steps.
 * @param summary Scan summary input.
 * @returns Formatted text report string.
 */
export function formatTextReport(summary: ScanSummary): string {
	const lines: string[] = [];
	const hasIssues =
		summary.affectedCount > 0 || summary.securityFindings.length > 0;
	const criticalFindings = summary.securityFindings.filter(
		(f) => f.severity === 'critical',
	);
	const highFindings = summary.securityFindings.filter(
		(f) => f.severity === 'high',
	);
	const mediumFindings = summary.securityFindings.filter(
		(f) => f.severity === 'medium',
	);
	const lowFindings = summary.securityFindings.filter(
		(f) => f.severity === 'low',
	);

	lines.push('');
	lines.push('='.repeat(70));
	lines.push('  SHAI-HULUD 2.0 SUPPLY CHAIN ATTACK DETECTOR');
	lines.push('='.repeat(70));
	lines.push('');

	if (!hasIssues) {
		lines.push('  STATUS: CLEAN');
		lines.push('  No compromised packages or security issues detected.');
	} else {
		const statusParts = [];
		if (summary.affectedCount > 0) {
			statusParts.push(`${summary.affectedCount} compromised package(s)`);
		}
		if (summary.securityFindings.length > 0) {
			statusParts.push(
				`${summary.securityFindings.length} security finding(s)`,
			);
		}
		lines.push(`  STATUS: AFFECTED - ${statusParts.join(', ')}`);
	}

	// Compromised packages section
	if (summary.affectedCount > 0) {
		lines.push('');
		lines.push('-'.repeat(70));
		lines.push('  COMPROMISED PACKAGES:');
		lines.push('-'.repeat(70));

		for (const result of summary.results) {
			const badge =
				result.severity === 'critical'
					? '[CRITICAL]'
					: `[${result.severity.toUpperCase()}]`;
			const direct = result.isDirect ? '(direct)' : '(transitive)';
			lines.push(`  ${badge} ${result.package}@${result.version} ${direct}`);
			lines.push(`         Location: ${result.location}`);
		}
	}

	// Security findings section
	if (summary.securityFindings.length > 0) {
		lines.push('');
		lines.push('-'.repeat(70));
		lines.push('  SECURITY FINDINGS:');
		lines.push('-'.repeat(70));

		// Group by severity
		const printFindings = (
			findings: typeof summary.securityFindings,
			label: string,
		) => {
			if (findings.length === 0) return;
			lines.push('');
			lines.push(`  ${label} (${findings.length}):`);
			for (const finding of findings) {
				lines.push(`    [${finding.severity.toUpperCase()}] ${finding.title}`);
				lines.push(`           Type: ${finding.type}`);
				lines.push(`           Location: ${finding.location}`);
				if (finding.evidence) {
					const evidence =
						finding.evidence.length > 80
							? finding.evidence.substring(0, 77) + '...'
							: finding.evidence;
					lines.push(`           Evidence: ${evidence}`);
				}
				lines.push(`           ${finding.description}`);
			}
		};

		printFindings(criticalFindings, 'CRITICAL');
		printFindings(highFindings, 'HIGH');
		printFindings(mediumFindings, 'MEDIUM');
		printFindings(lowFindings, 'LOW');
	}

	lines.push('');
	lines.push('-'.repeat(70));
	lines.push(`  Files scanned: ${summary.scannedFiles.length}`);
	lines.push(`  Compromised packages: ${summary.affectedCount}`);
	lines.push(`  Security findings: ${summary.securityFindings.length}`);
	lines.push(`  Scan time: ${summary.scanTime}ms`);
	lines.push(`  Database version: ${masterPackages.version}`);
	lines.push(`  Last updated: ${masterPackages.lastUpdated}`);
	lines.push('='.repeat(70));
	lines.push('');

	if (hasIssues) {
		lines.push('  IMMEDIATE ACTIONS REQUIRED:');
		lines.push('  1. Do NOT run npm install until packages are updated');
		lines.push('  2. Rotate all credentials (npm, GitHub, AWS, etc.)');
		lines.push(
			'  3. Check for unauthorized GitHub self-hosted runners named "SHA1HULUD"',
		);
		lines.push(
			'  4. Audit GitHub repos for "Shai-Hulud: The Second Coming" description',
		);
		lines.push(
			'  5. Check for actionsSecrets.json files containing stolen credentials',
		);
		lines.push(
			'  6. Review package.json scripts for suspicious preinstall/postinstall hooks',
		);
		lines.push('');
		lines.push('  For more information:');
		lines.push(
			'  https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains',
		);
		lines.push('');
	}

	return lines.join('\n');
}

/**
 * Expose metadata about the compromised packages database (version, timestamps,
 * aggregate counts and indicator lists) for display or debugging.
 * @returns Object containing database metadata and counts.
 */
export function getMasterPackagesInfo() {
	return {
		version: masterPackages.version,
		lastUpdated: masterPackages.lastUpdated,
		totalPackages: masterPackages.packages.length,
		attackInfo: masterPackages.attackInfo,
		indicators: masterPackages.indicators,
	};
}
