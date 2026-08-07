export interface PackageEntry {
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    affectedVersions: string[];
}
export interface FileHash {
    sha1?: string;
    sha256: string | string[];
}
export interface MasterPackages {
    version: string;
    lastUpdated: string;
    attackInfo: {
        name: string;
        alias: string;
        firstDetected: string;
        description: string;
    };
    indicators: {
        maliciousFiles: string[];
        maliciousWorkflows: string[];
        fileHashes: Record<string, FileHash>;
        gitHubIndicators: {
            runnerName: string;
            repoDescription: string;
            repoNamePattern?: string;
            workflowTrigger?: string;
        };
        runnerPaths?: string[];
        credentialPaths?: string[];
        primaryInfectionVectors?: string[];
        mavenPackages?: string[];
    };
    stats?: {
        totalUniquePackages: number;
        byOrganization: Record<string, number>;
    };
    packages: PackageEntry[];
    sources?: string[];
    dataSource?: {
        url: string;
        description: string;
        sources: string[];
        fetchedAt: string;
    };
    acknowledgements?: {
        securityResearchers: Array<{
            org: string;
            github: string;
        }>;
    };
}
export interface ScanResult {
    package: string;
    version: string;
    affected: boolean;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
    isDirect: boolean;
    location: string;
}
export type SecurityFindingType = 'compromised-package' | 'suspicious-script' | 'trufflehog-activity' | 'shai-hulud-repo' | 'secrets-exfiltration' | 'malicious-runner' | 'malware-hash-match' | 'runner-installation' | 'malicious-workflow-trigger' | 'ide-persistence';
export interface SecurityFinding {
    type: SecurityFindingType;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    location: string;
    line?: number;
    evidence?: string;
    sha256?: string;
}
/**
 * Allowlist entry for excluding false positives from scan results.
 * All specified fields must match (AND logic). Omitted fields act as wildcards.
 * @see Discussion #17: https://github.com/gensecaihq/Shai-Hulud-2.0-Detector/discussions/17
 */
export interface AllowlistEntry {
    /** Finding type to match (e.g., 'suspicious-script', 'compromised-package') */
    type?: SecurityFindingType;
    /** Severity level to match */
    severity?: 'critical' | 'high' | 'medium' | 'low';
    /** Exact title match */
    title?: string;
    /** Substring match on title */
    titleContains?: string;
    /** Exact location/file path match */
    location?: string;
    /** Substring match on location */
    locationContains?: string;
    /** Substring match on evidence field */
    evidenceContains?: string;
    /** Exact SHA256 hash match, used for file and script contents */
    sha256?: string;
    /** Documentation comment (not used in matching) */
    comment?: string;
}
export interface ScriptCheckResult {
    hasSuspiciousScripts: boolean;
    findings: SecurityFinding[];
}
export interface FileCheckResult {
    found: boolean;
    findings: SecurityFinding[];
}
export interface ScanSummary {
    totalDependencies: number;
    affectedCount: number;
    cleanCount: number;
    results: ScanResult[];
    securityFindings: SecurityFinding[];
    scannedFilesCount: number;
    scannedFiles: string[];
    scanTime: number;
}
export interface PackageJson {
    name?: string;
    version?: string;
    scripts?: Record<string, string>;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
}
export interface PackageLock {
    name?: string;
    version?: string;
    lockfileVersion?: number;
    packages?: Record<string, PackageLockEntry>;
    dependencies?: Record<string, PackageLockDependency>;
}
export interface PackageLockEntry {
    version?: string;
    resolved?: string;
    integrity?: string;
    dev?: boolean;
    optional?: boolean;
    dependencies?: Record<string, string>;
}
export interface PackageLockDependency {
    version: string;
    resolved?: string;
    integrity?: string;
    dev?: boolean;
    optional?: boolean;
    requires?: Record<string, string>;
    dependencies?: Record<string, PackageLockDependency>;
}
export interface YarnLockEntry {
    version: string;
    resolved?: string;
    integrity?: string;
    dependencies?: Record<string, string>;
}
export interface BunLock {
    lockfileVersion: number;
    configVersion: number;
    workspaces: Record<string, BunLockWorkspace>;
    trustedDependencies: string[];
    overrides: Record<string, string>;
    packages: Record<string, BunLockPackageEntry>;
}
export type BunLockPackageEntry = [string, string, {
    dependencies: Record<string, string>;
}, string];
export interface BunLockWorkspace {
    name: string;
    dependencies: Record<string, string>;
    devDependencies: Record<string, string>;
}
export interface Inputs {
    failOnCritical: boolean;
    failOnHigh: boolean;
    failOnAny: boolean;
    scanLockfiles: boolean;
    scanNodeModules: boolean;
    outputFormat: 'text' | 'json' | 'sarif';
    workingDirectory: string;
    /** Path to allowlist JSON file for excluding false positives */
    allowlistPath: string;
    /** Skip allowlist processing entirely (for security audits) */
    ignoreAllowlist: boolean;
    /** Show allowlisted items as warnings instead of hiding them */
    warnOnAllowlist: boolean;
}
export interface SarifResult {
    $schema: string;
    version: string;
    runs: SarifRun[];
}
export interface SarifRun {
    tool: {
        driver: {
            name: string;
            version: string;
            informationUri: string;
            rules: SarifRule[];
        };
    };
    results: SarifResultEntry[];
}
export interface SarifRule {
    id: string;
    name: string;
    shortDescription: {
        text: string;
    };
    fullDescription: {
        text: string;
    };
    helpUri: string;
    defaultConfiguration: {
        level: 'error' | 'warning' | 'note';
    };
}
export interface SarifResultEntry {
    ruleId: string;
    level: 'error' | 'warning' | 'note';
    message: {
        text: string;
    };
    locations: SarifLocation[];
}
export interface SarifLocation {
    physicalLocation: {
        artifactLocation: {
            uri: string;
        };
        region?: {
            startLine: number;
            startColumn: number;
        };
    };
}
