import * as core from "@actions/core";
import * as github from "@actions/github";
import * as fs from "fs";
import * as path from "path";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import {
	formatTextReport,
	generateSarifReport,
	getMasterPackagesInfo,
	runScan,
} from "./scanner";
import type { Inputs, ScanSummary } from "./types";

// =============================================================================
// DISCLAIMER
// =============================================================================
// This tool is designed for DETECTION purposes only. It provides visibility
// into potential supply chain compromises but does NOT:
//
//   - Automatically remove or quarantine malicious code
//   - Patch, fix, or remediate compromised packages
//   - Prevent future supply chain attacks
//   - Guarantee detection of all compromised packages
//
// All findings should be manually verified by your security team. Take
// appropriate remediation steps including credential rotation, dependency
// updates, and forensic analysis of affected systems.
// =============================================================================


/**
 * Detect whether the current process is executing inside a GitHub Actions runner.
 * Uses the conventional environment variable GITHUB_ACTIONS exposed by the platform.
 * @returns true if running in GitHub Actions, otherwise false.
 */
function isRunningInGithubActions(): boolean {
	return process.env.GITHUB_ACTIONS === "true";
}

/**
 * Resolve final user inputs combining (in priority order): explicit GitHub Action inputs,
 * CLI arguments, environment variables (INPUT_*), and built-in defaults. This allows
 * the same code path to support both Action execution and local/CI CLI usage seamlessly.
 *
 * Validation:
 * - Boolean inputs: empty Action inputs fall back to provided defaults
 * - output-format: coerces to one of 'text' | 'json' | 'sarif', defaulting to 'json'
 *
 * @param inputs Pre-populated inputs gathered from CLI flags and env vars.
 * @returns A fully populated and normalized Inputs object ready for scanning.
 */
function getInputs(inputs: Inputs): Inputs {
	const inActions = isRunningInGithubActions();

	const getBool = (
		name: string,
		argVal: boolean | undefined,
		defaultVal: boolean,
	): boolean => {
		// In GitHub Actions, check if the input is provided; if not, use default
		if (inActions) {
			const raw = core.getInput(name);
			return raw !== "" ? core.getBooleanInput(name) : defaultVal;
		}

		// In local/CLI mode, use the argument value or default
		return argVal ?? defaultVal;
	};

	const getStr = (
		name: string,
		argVal: string | undefined,
		defaultVal: string,
	): string => {
		// In GitHub Actions, check if the input is provided; if not, use default
		if (inActions) {
			const raw = core.getInput(name);
			return raw !== "" ? raw : defaultVal;
		}

		// In local/CLI mode, use the argument value or default
		return argVal ?? defaultVal;
	};

	const outputFormatRaw = getStr("output-format", inputs.outputFormat, "json");

	const outputFormat: "text" | "json" | "sarif" = [
		"text",
		"json",
		"sarif",
	].includes(outputFormatRaw as string)
		? (outputFormatRaw as "text" | "json" | "sarif")
		: "json";

	const workingDirectory = getStr(
		"working-directory",
		inputs.workingDirectory,
		process.cwd(),
	);

	return {
		failOnCritical: getBool("fail-on-critical", inputs.failOnCritical, true),
		failOnHigh: getBool("fail-on-high", inputs.failOnHigh, false),
		failOnAny: getBool("fail-on-any", inputs.failOnAny, false),
		scanLockfiles: getBool("scan-lockfiles", inputs.scanLockfiles, true),
		scanNodeModules: getBool(
			"scan-node-modules",
			inputs.scanNodeModules,
			false,
		),
		outputFormat,
		workingDirectory,
	};
}

/**
 * Main entrypoint: parses CLI flags / env vars, normalizes inputs, executes the scan,
 * renders output (text | json | sarif), sets GitHub Action outputs & annotations,
 * determines failure conditions based on severity policy, and writes a job summary.
 *
 * Failure policy precedence (first match wins):
 * 1. fail-on-any
 * 2. fail-on-critical
 * 3. fail-on-high
 *
 * All exceptions are caught and converted to a failed Action.
 */
async function run(): Promise<void> {
	try {
		const parseBoolEnv = (val: string | undefined): boolean | undefined => {
			return val === undefined ? undefined : val === "true";
		};

		// Parse CLI flags (works in local/CLI mode).
		const argv = yargs(hideBin(process.argv))
			.option("fail-on-critical", {
				type: "boolean",
				description: "Fail the run on any critical findings",
			})
			.option("fail-on-high", {
				type: "boolean",
				description: "Fail the run on high or critical findings",
			})
			.option("fail-on-any", {
				type: "boolean",
				description: "Fail the run if any issues are found",
			})
			.option("scan-lockfiles", {
				type: "boolean",
				description: "Scan lockfiles (package-lock.json / yarn.lock)",
			})
			.option("scan-node-modules", {
				type: "boolean",
				description: "Scan node_modules directory",
			})
			.option("output-format", {
				choices: ["text", "json", "sarif"] as const,
				description: "Report output format",
			})
			.option("working-directory", {
				type: "string",
				description: "Directory to scan",
			})
			.parseSync();

		// Build inputs from CLI flags first, then fall back to environment variables.
		const argsInputs: Inputs = {
			failOnCritical:
				argv["fail-on-critical"] ??
				parseBoolEnv(process.env.INPUT_FAIL_ON_CRITICAL) ??
				true,
			failOnHigh:
				argv["fail-on-high"] ?? parseBoolEnv(process.env.INPUT_FAIL_ON_HIGH) ?? false,
			failOnAny:
				argv["fail-on-any"] ?? parseBoolEnv(process.env.INPUT_FAIL_ON_ANY) ?? false,
			scanLockfiles:
				argv["scan-lockfiles"] ??
				parseBoolEnv(process.env.INPUT_SCAN_LOCKFILES) ??
				true,
			scanNodeModules:
				argv["scan-node-modules"] ??
				parseBoolEnv(process.env.INPUT_SCAN_NODE_MODULES) ??
				false,
			outputFormat:
				argv["output-format"] ??
				(process.env.INPUT_OUTPUT_FORMAT as "text" | "json" | "sarif" | undefined) ??
				"json",
			workingDirectory:
				(argv["working-directory"] as string | undefined) ??
				process.env.INPUT_WORKING_DIRECTORY ??
				process.cwd(),
		};

		core.info('');
		core.info('Shai-Hulud 2.0 Detector');
		core.info('=======================');
		core.info('');

		// Display inputs
		const inputs = getInputs(argsInputs);
		core.info('Inputs:');
		core.info(`- Fail on Critical: ${inputs.failOnCritical}`);
		core.info(`- Fail on High: ${inputs.failOnHigh}`);
		core.info(`- Fail on Any: ${inputs.failOnAny}`);
		core.info(`- Scan Lockfiles: ${inputs.scanLockfiles}`);
		core.info(`- Scan Node Modules: ${inputs.scanNodeModules}`);
		core.info(`- Output Format: ${inputs.outputFormat}`);
		core.info(`- Working Directory: ${inputs.workingDirectory}`);
		core.info('');

		// Display database info
		const dbInfo = getMasterPackagesInfo();
		core.info(`Database version: ${dbInfo.version}`);
		core.info(`Last updated: ${dbInfo.lastUpdated}`);
		core.info(`Total known affected packages: ${dbInfo.totalPackages}`);
        core.info('');

		// Resolve working directory
		const workDir = path.resolve(inputs.workingDirectory);
		core.info(`Scanning directory: ${workDir}`);

		if (!fs.existsSync(workDir)) {
			core.setFailed(`Working directory does not exist: ${workDir}`);
			return;
		}

		// Run the scan
		core.info('Starting scan...');
		const summary = runScan(workDir, inputs.scanLockfiles, inputs.scanNodeModules);

		// Output results based on format
		switch (inputs.outputFormat) {
            case 'json':
                core.info('');
                core.info('JSON Report:');
				core.info(JSON.stringify(summary, null, 2));
				break;

			case 'sarif': {
				const sarifReport = generateSarifReport(summary);
				const sarifPath = path.join(workDir, 'shai-hulud-results.sarif');
				fs.writeFileSync(sarifPath, JSON.stringify(sarifReport, null, 2));
				core.info(`SARIF report written to: ${sarifPath}`);
				core.setOutput('sarif-file', sarifPath);
				break;
			}

			case 'text':
			default:
				core.info(formatTextReport(summary));
				break;
		}

		// Set outputs
        const hasIssues = summary.affectedCount > 0 || summary.securityFindings.length > 0;
        core.setOutput('affected-count', summary.affectedCount.toString());
        core.setOutput('security-findings-count', summary.securityFindings.length.toString());
        core.setOutput('scan-time', summary.scanTime.toString());
        core.setOutput('status', hasIssues ? 'affected' : 'clean');
        core.setOutput('results', JSON.stringify(summary.results));
        core.setOutput('security-findings', JSON.stringify(summary.securityFindings));

		// Create annotations for affected packages
		if (summary.affectedCount > 0) {
			for (const result of summary.results) {
				const annotation = {
					title: `Compromised Package: ${result.package}`,
					file: result.location,
					startLine: 1,
				};

                if (result.severity === 'critical') {
					core.error(
						`[CRITICAL] ${result.package}@${result.version} - Shai-Hulud 2.0 compromised package detected`,
                        annotation
					);
				} else {
					core.warning(
						`[${result.severity.toUpperCase()}] ${result.package}@${result.version} - Shai-Hulud 2.0 compromised package detected`,
						annotation
					);
				}
			}
		}

		// Create annotations for security findings
		if (summary.securityFindings.length > 0) {
			for (const finding of summary.securityFindings) {
				const annotation = {
					title: finding.title,
					file: finding.location,
					startLine: finding.line || 1,
				};

                if (finding.severity === 'critical') {
                    core.error(`[CRITICAL] ${finding.title} - ${finding.type}`, annotation);
                } else if (finding.severity === 'high') {
					core.warning(`[HIGH] ${finding.title} - ${finding.type}`, annotation);
				} else {
                    core.notice(`[${finding.severity.toUpperCase()}] ${finding.title} - ${finding.type}`, annotation);
				}
			}
		}

		// Create job summary if there are any issues
		if (hasIssues) {
			await createJobSummary(summary);
		}

		// Determine if we should fail
		let shouldFail = false;
        let failReason = '';

		// Count critical findings from security checks
		const criticalSecurityFindings = summary.securityFindings.filter(
            (f) => f.severity === 'critical'
		).length;
		const highSecurityFindings = summary.securityFindings.filter(
            (f) => f.severity === 'critical' || f.severity === 'high'
		).length;

		if (inputs.failOnAny && hasIssues) {
			const issues = [];
            if (summary.affectedCount > 0) issues.push(`${summary.affectedCount} compromised package(s)`);
            if (summary.securityFindings.length > 0) issues.push(`${summary.securityFindings.length} security finding(s)`);
			shouldFail = true;
            failReason = issues.join(' and ');
		} else if (inputs.failOnCritical) {
			const criticalPackages = summary.results.filter(
				(r) => r.severity === 'critical'
			).length;
			const totalCritical = criticalPackages + criticalSecurityFindings;
			if (totalCritical > 0) {
				shouldFail = true;
				failReason = `${totalCritical} critical severity issue(s) detected`;
			}
		} else if (inputs.failOnHigh) {
			const highOrAbovePackages = summary.results.filter(
				(r) => r.severity === 'critical' || r.severity === 'high'
			).length;
			const totalHighOrAbove = highOrAbovePackages + highSecurityFindings;
			if (totalHighOrAbove > 0) {
				shouldFail = true;
				failReason = `${totalHighOrAbove} high/critical severity issue(s) detected`;
			}
		}

		if (shouldFail) {
			core.setFailed(
				`Shai-Hulud 2.0 supply chain attack indicators detected: ${failReason}`
			);
		} else if (hasIssues) {
			core.warning(
				`Shai-Hulud 2.0: Issues found (${summary.affectedCount} package(s), ${summary.securityFindings.length} finding(s)) but not failing due to configuration`
			);
		} else {
            core.info('Scan complete. No compromised packages or security issues detected.');
		}
	} catch (error) {
		if (error instanceof Error) {
			core.setFailed(`Action failed: ${error.message}`);
		} else {
            core.setFailed('Action failed with unknown error');
		}
	}
}

/**
 * Generate a rich Markdown job summary for GitHub Actions showing compromised packages,
 * grouped security findings with collapsible detail sections, and recommended immediate
 * remediation steps. Only written when issues are detected.
 *
 * @param summary Aggregate scan results produced by runScan.
 */
async function createJobSummary(summary: ScanSummary): Promise<void> {
	const lines: string[] = [];
    const hasIssues = summary.affectedCount > 0 || summary.securityFindings.length > 0;

    lines.push('# Shai-Hulud 2.0 Supply Chain Attack Scan Results');
    lines.push('');
    lines.push(
        `> **Status:** ${hasIssues ? 'AFFECTED' : 'CLEAN'}`
    );
    lines.push('');

	// Summary stats
    lines.push('## Summary');
    lines.push('');
	lines.push(`- **Compromised Packages:** ${summary.affectedCount}`);
	lines.push(`- **Security Findings:** ${summary.securityFindings.length}`);
	lines.push(`- **Files Scanned:** ${summary.scannedFiles.length}`);
    lines.push('');

	if (summary.affectedCount > 0) {
		lines.push('## Compromised Packages');
		lines.push('');
		lines.push('| Package | Version | Severity | Type |');
		lines.push('|---------|---------|----------|------|');

		for (const result of summary.results) {
            const type = result.isDirect ? 'Direct' : 'Transitive';
			lines.push(
                `| \`${result.package}\` | ${result.version} | ${result.severity.toUpperCase()} | ${type} |`
			);
		}
		lines.push('');
	}

	if (summary.securityFindings.length > 0) {
		lines.push('## Security Findings');
		lines.push('');
		lines.push('| Finding | Type | Severity | Location |');
		lines.push('|---------|------|----------|----------|');

		for (const finding of summary.securityFindings) {
            const shortLocation = finding.location.split('/').slice(-2).join('/');
			lines.push(
                `| ${finding.title} | \`${finding.type}\` | ${finding.severity.toUpperCase()} | \`${shortLocation}\` |`
			);
		}
		lines.push('');

		// Detail findings by type
		const findingTypes = new Map<string, typeof summary.securityFindings>();
		for (const finding of summary.securityFindings) {
			if (!findingTypes.has(finding.type)) {
				findingTypes.set(finding.type, []);
			}
			const list = findingTypes.get(finding.type);
			if (list) {
				list.push(finding);
			}
		}

		lines.push('### Finding Details');
		lines.push('');
		for (const [type, findings] of findingTypes) {
            lines.push(`<details>`);
            lines.push(`<summary><strong>${type}</strong> (${findings.length} finding(s))</summary>`);
			lines.push('');
			for (const finding of findings) {
				lines.push(`- **${finding.title}**`);
				lines.push(`  - Location: \`${finding.location}\``);
				lines.push(`  - ${finding.description}`);
				if (finding.evidence) {
                    lines.push(`  - Evidence: \`${finding.evidence.substring(0, 100)}${finding.evidence.length > 100 ? '...' : ''}\``);
				}
			}
			lines.push('');
			lines.push('</details>');
			lines.push('');
		}
	}

	if (hasIssues) {
        lines.push('## Immediate Actions Required');
        lines.push('');
        lines.push('1. **Do NOT run `npm install`** until packages are updated');
        lines.push('2. **Rotate all credentials** (npm, GitHub, AWS, GCP, Azure)');
        lines.push('3. **Check for unauthorized self-hosted runners** named "SHA1HULUD"');
        lines.push('4. **Audit GitHub repos** for "Shai-Hulud: The Second Coming" description');
        lines.push('5. **Search for `actionsSecrets.json`** files containing stolen credentials');
        lines.push('6. **Review `package.json` scripts** for suspicious preinstall/postinstall hooks');
        lines.push('');
        lines.push('## More Information');
        lines.push('');
        lines.push('- [Aikido Security Analysis](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)');
        lines.push('- [Wiz.io Investigation](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)');
	} else {
        lines.push('No compromised packages or security issues were detected.');
	}

	lines.push('');
	lines.push('---');
	lines.push('');
    lines.push('> **Disclaimer:** This tool is for detection purposes only. It does not automatically remove malicious code, fix compromised packages, or prevent future attacks. Always verify findings manually and take appropriate remediation steps.');
	lines.push('');
    lines.push(`*Scanned ${summary.scannedFiles.length} files in ${summary.scanTime}ms*`);

    await core.summary.addRaw(lines.join('\n')).write();
}

run();
