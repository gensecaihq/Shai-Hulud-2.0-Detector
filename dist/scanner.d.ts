import type { PackageJson, PackageLock, SarifResult, ScanResult, ScanSummary, SecurityFinding } from './types';
/**
 * Fast membership check for whether a package name appears in the compromised
 * master package list.
 * @param packageName The dependency name to check.
 * @returns true if the package is flagged as affected.
 */
export declare function isAffected(packageName: string): boolean;
/**
 * Retrieve the recorded severity for an affected package. Defaults to 'critical'
 * if the package entry is missing (defensive fallback).
 * @param packageName Name of the compromised package.
 * @returns Severity classification.
 */
export declare function getPackageSeverity(packageName: string): 'critical' | 'high' | 'medium' | 'low';
/**
 * Safely parse a package.json file returning null if unreadable or invalid JSON.
 * @param filePath Path to a package.json file.
 * @returns Parsed PackageJson object or null on failure.
 */
export declare function parsePackageJson(filePath: string): PackageJson | null;
/**
 * Parse a package-lock.json (v1/v2/v3) or npm-shrinkwrap.json file with graceful
 * failure on read/parse errors.
 * @param filePath Lockfile path.
 * @returns Parsed PackageLock object or null on failure.
 */
export declare function parsePackageLock(filePath: string): PackageLock | null;
/**
 * Lightweight yarn.lock parser extracting package name -> version mappings.
 * Only intended for identifying affected packages; not a full fidelity parser.
 * @param filePath yarn.lock file path.
 * @returns Map of package names to versions or null on failure.
 */
export declare function parseYarnLock(filePath: string): Map<string, string> | null;
/**
 * Scan a package.json for compromised dependencies across all dependency blocks
 * (dependencies, dev, peer, optional). Marks each finding with direct/transitive flag.
 * @param filePath Path to package.json.
 * @param isDirect Whether dependencies should be considered direct (root-level scan).
 * @returns List of ScanResult entries.
 */
export declare function scanPackageJson(filePath: string, isDirect?: boolean): ScanResult[];
/**
 * Scan an npm lockfile (v1/v2/v3) for affected packages. Determines direct vs
 * transitive based on path nesting for v2+ format.
 * @param filePath Lockfile path.
 * @returns ScanResult list of affected packages.
 */
export declare function scanPackageLock(filePath: string): ScanResult[];
/**
 * Scan a yarn.lock for affected packages. Yarn lockfiles do not distinguish
 * direct vs transitive so all findings are marked transitive.
 * @param filePath yarn.lock path.
 * @returns ScanResult list.
 */
export declare function scanYarnLock(filePath: string): ScanResult[];
/**
 * Discover recognized lockfiles recursively (depth <= 5) excluding node_modules
 * and hidden directories.
 * @param directory Root directory to begin search.
 * @param scanNodeModules Whether to include node_modules directories in the scan. Defaults to false.
 * @returns Array of absolute lockfile paths.
 */
export declare function findLockfiles(directory: string, scanNodeModules?: boolean): string[];
/**
 * Recursively locate package.json files up to depth 5 (monorepo friendly), skipping
 * node_modules and dot-prefixed directories.
 * @param directory Root search directory.
 * @param scanNodeModules Whether to include node_modules directories in the scan. Defaults to false.
 * @returns Array of package.json paths.
 */
export declare function findPackageJsonFiles(directory: string, scanNodeModules?: boolean): string[];
/**
 * Inspect scripts in a package.json for indicators of compromise (IoCs) and general
 * suspicious execution patterns (curl|sh, wget|sh, eval, base64 decode, inline node -e, etc.).
 * Critical severity is assigned to malicious Shai-Hulud artifacts or dangerous lifecycle hooks.
 * @param filePath Path to package.json.
 * @returns SecurityFinding list.
 */
export declare function checkSuspiciousScripts(filePath: string): SecurityFinding[];
/**
 * Traverse the repository (depth <= 5) searching for TruffleHog references, payload
 * artifacts, and exfiltration endpoints in script & code files. Skips detector sources
 * via path/content heuristics.
 * @param directory Root directory to scan.
 * @returns SecurityFinding list of critical indicators.
 */
export declare function checkTrufflehogActivity(directory: string): SecurityFinding[];
/**
 * Detect presence of Shai-Hulud exfiltration output files (actionsSecrets.json, cloud.json,
 * contents.json, environment.json, truffleSecrets.json, etc.) and large obfuscated payloads.
 * Also flags potential encoded secrets JSON files.
 * @param directory Root directory.
 * @returns SecurityFinding list.
 */
export declare function checkSecretsExfiltration(directory: string): SecurityFinding[];
/**
 * Scan GitHub Actions workflow YAML files for malicious runner labels (SHA1HULUD),
 * suspicious workflow filenames, and Shai-Hulud repository indicators while excluding
 * legitimate detector usage.
 * @param directory Root repository directory.
 * @returns SecurityFinding list.
 */
export declare function checkMaliciousRunners(directory: string): SecurityFinding[];
/**
 * Inspect git config and package.json files for Shai-Hulud repository related markers
 * excluding references to the detector itself. Flags remote/potential infra compromise.
 * @param directory Root repo directory.
 * @returns SecurityFinding list.
 */
export declare function checkShaiHuludRepos(directory: string): SecurityFinding[];
/**
 * Produce low severity warnings for dependencies from organizations affected in the
 * campaign when semver ranges (caret/tilde) may auto-update into compromised versions.
 * Skips already known compromised packages.
 * @param filePath Path to package.json.
 * @returns SecurityFinding list (low severity).
 */
export declare function checkAffectedNamespaces(filePath: string): SecurityFinding[];
/**
 * Check local git branch names for Shai-Hulud related indicators to surface possible
 * attack propagation or staging branches.
 * @param directory Repository root.
 * @returns SecurityFinding list (medium severity).
 */
export declare function checkSuspiciousBranches(directory: string): SecurityFinding[];
/**
 * Orchestrate full scan: package.json files, optional lockfiles, and advanced security
 * checks (scripts, TruffleHog activity, exfiltration files, malicious runners, repo refs,
 * suspicious branches). Aggregates and de-duplicates findings, returning a structured summary.
 * @param directory Root directory to scan.
 * @param scanLockfiles Whether to include lockfile scanning.
 * @param scanNodeModules Whether to include node_modules directories in package.json scans. Defaults to false.
 * @returns Comprehensive ScanSummary.
 */
export declare function runScan(directory: string, scanLockfiles?: boolean, scanNodeModules?: boolean): ScanSummary;
/**
 * Transform a ScanSummary into a SARIF 2.1.0 compliant result set including unique rules
 * for each compromised package and security finding.
 * @param summary Completed scan summary.
 * @returns SARIF result object suitable for upload.
 */
export declare function generateSarifReport(summary: ScanSummary): SarifResult;
/**
 * Render human-readable multi-section text output summarizing compromised packages,
 * grouped security findings and recommended remediation steps.
 * @param summary Scan summary input.
 * @returns Formatted text report string.
 */
export declare function formatTextReport(summary: ScanSummary): string;
/**
 * Expose metadata about the compromised packages database (version, timestamps,
 * aggregate counts and indicator lists) for display or debugging.
 * @returns Object containing database metadata and counts.
 */
export declare function getMasterPackagesInfo(): {
    version: string;
    lastUpdated: string;
    totalPackages: number;
    attackInfo: {
        name: string;
        alias: string;
        firstDetected: string;
        description: string;
    };
    indicators: {
        maliciousFiles: string[];
        maliciousWorkflows: string[];
        fileHashes: Record<string, string>;
        gitHubIndicators: {
            runnerName: string;
            repoDescription: string;
        };
    };
};
