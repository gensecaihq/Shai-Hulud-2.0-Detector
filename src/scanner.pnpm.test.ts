import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { parsePnpmLock, scanPnpmLock } from './scanner';

describe('pnpm lock parsing and scanning', () => {
	let tempDir: string;
	let lockfilePath: string;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pnpm-lock-test-'));
		lockfilePath = path.join(tempDir, 'pnpm-lock.yaml');
	});

	afterEach(() => {
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it('parses package keys from packages section with peer suffixes', () => {
		const content = `
lockfileVersion: '9.0'
packages:
  '@actions/core@1.11.1':
    resolution: {integrity: sha512-abc}
  'ts-jest@29.4.5(@babel/core@7.28.5)(typescript@5.9.3)':
    resolution: {integrity: sha512-def}
`;
		fs.writeFileSync(lockfilePath, content, 'utf8');

		const parsed = parsePnpmLock(lockfilePath);
		expect(parsed).not.toBeNull();
		expect(parsed?.get('@actions/core')).toEqual(new Set(['1.11.1']));
		expect(parsed?.get('ts-jest')).toEqual(new Set(['29.4.5']));
	});

	it('parses importer-only dependencies when package entry is missing', () => {
		const content = `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@huntersofbook/core':
        specifier: ^0.5.1
        version: 0.5.1
packages:
  '@actions/core@1.11.1':
    resolution: {integrity: sha512-abc}
`;
		fs.writeFileSync(lockfilePath, content, 'utf8');

		const parsed = parsePnpmLock(lockfilePath);
		expect(parsed).not.toBeNull();
		expect(parsed?.get('@huntersofbook/core')).toEqual(new Set(['0.5.1']));
	});

	it('prefers packages section versions over importer-only fallback', () => {
		const content = `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@huntersofbook/core':
        specifier: ^0.5.1
        version: 0.5.1
packages:
  '@huntersofbook/core@0.5.2':
    resolution: {integrity: sha512-abc}
`;
		fs.writeFileSync(lockfilePath, content, 'utf8');

		const parsed = parsePnpmLock(lockfilePath);
		expect(parsed).not.toBeNull();
		// 0.5.2 comes from packages, 0.5.1 from importers — packages should win
		expect(parsed?.get('@huntersofbook/core')).toEqual(new Set(['0.5.2']));

		const results = scanPnpmLock(lockfilePath);
		// 0.5.2 is not a compromised version of @huntersofbook/core
		expect(results.some((r) => r.package === '@huntersofbook/core')).toBe(false);
	});

	it('preserves and scans multiple versions for the same package name', () => {
		const content = `
lockfileVersion: '9.0'
packages:
  '@huntersofbook/core@0.5.0':
    resolution: {integrity: sha512-a}
  '@huntersofbook/core@0.5.1':
    resolution: {integrity: sha512-b}
`;
		fs.writeFileSync(lockfilePath, content, 'utf8');

		const parsed = parsePnpmLock(lockfilePath);
		expect(parsed).not.toBeNull();
		expect(parsed?.get('@huntersofbook/core')).toEqual(new Set(['0.5.0', '0.5.1']));

		const results = scanPnpmLock(lockfilePath);
		expect(results.some((r) => r.package === '@huntersofbook/core' && r.version === '0.5.1')).toBe(true);
	});

	it('returns scan results for each version when multiple entries exist in packages', () => {
		const content = `
lockfileVersion: '9.0'
packages:
  '@ifelsedeveloper/protocol-contracts-svm-idl@0.1.2':
    resolution: {integrity: sha512-a}
  '@ifelsedeveloper/protocol-contracts-svm-idl@0.1.3':
    resolution: {integrity: sha512-b}
`;
		fs.writeFileSync(lockfilePath, content, 'utf8');

		const parsed = parsePnpmLock(lockfilePath);
		expect(parsed).not.toBeNull();
		expect(parsed?.get('@ifelsedeveloper/protocol-contracts-svm-idl')).toEqual(new Set(['0.1.2', '0.1.3']));

		const results = scanPnpmLock(lockfilePath);
		expect(results.some((r) => r.package === '@ifelsedeveloper/protocol-contracts-svm-idl' && r.version === '0.1.2' && r.affected)).toBe(true);
		expect(results.some((r) => r.package === '@ifelsedeveloper/protocol-contracts-svm-idl' && r.version === '0.1.3' && r.affected)).toBe(true);
	});

	it('detects known compromised importer dependency in scanPnpmLock', () => {
		const content = `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@huntersofbook/core':
        specifier: ^0.5.1
        version: 0.5.1
packages: {}
`;
		fs.writeFileSync(lockfilePath, content, 'utf8');

		const results = scanPnpmLock(lockfilePath);
		expect(results.some((r) => r.package === '@huntersofbook/core' && r.version === '0.5.1' && r.affected)).toBe(true);
	});

	it('returns null on invalid yaml', () => {
		fs.writeFileSync(lockfilePath, 'lockfileVersion: [broken', 'utf8');
		expect(parsePnpmLock(lockfilePath)).toBeNull();
	});
});
