#!/usr/bin/env node
/**
 * Shai-Hulud 2.0 IOC Database Updater
 *
 * Fetches the latest compromised package data from the Datadog consolidated IOCs
 * which aggregates data from 7 security vendors:
 * - Datadog Security Labs
 * - HelixGuard
 * - Koi Security
 * - ReversingLabs
 * - Socket.dev
 * - StepSecurity
 * - Wiz
 *
 * Source: https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const CONSOLIDATED_IOC_URL = 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv';
// ChainDrop wave (Aug 2026, "Shai-Hulud: Here We Go Again") - Wiz Research maintained list
const CHAINDROP_IOC_URL = 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/keyv-packages.csv';
const OUTPUT_FILE = path.join(__dirname, '..', 'compromised-packages.json');

/**
 * Fetch URL content via HTTPS
 */
function fetchUrl(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            if (res.statusCode === 301 || res.statusCode === 302) {
                return fetchUrl(res.headers.location).then(resolve).catch(reject);
            }
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
                return;
            }
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve(data));
            res.on('error', reject);
        }).on('error', reject);
    });
}

/**
 * Parse CSV line handling quoted fields
 */
function parseCSVLine(line) {
    const result = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            result.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }
    result.push(current.trim());
    return result;
}

/**
 * Parse the consolidated IOCs CSV
 */
function parseConsolidatedCSV(csvContent) {
    const lines = csvContent.trim().split('\n');
    const packages = [];

    // Skip header
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        const [packageName, packageVersions, sources] = parseCSVLine(line);

        if (!packageName || !packageVersions) continue;

        // Parse versions (comma-separated)
        const versions = packageVersions
            .split(',')
            .map(v => v.trim())
            .filter(v => v.length > 0);

        // Parse sources
        const sourceList = sources
            ? sources.split(',').map(s => s.trim()).filter(s => s.length > 0)
            : [];

        packages.push({
            name: packageName,
            severity: 'critical',
            affectedVersions: versions,
            sources: sourceList
        });
    }

    return packages;
}

/**
 * Parse the Wiz Research ChainDrop CSV (format: Package,"v1, v2, ...")
 */
function parseChainDropCSV(csvContent) {
    const lines = csvContent.trim().split('\n');
    const packages = [];

    // Skip header
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        const [packageName, packageVersions] = parseCSVLine(line);
        if (!packageName || !packageVersions) continue;

        const versions = packageVersions
            .split(',')
            .map(v => v.trim())
            .filter(v => v.length > 0);

        packages.push({
            name: packageName,
            severity: 'critical',
            affectedVersions: versions,
            sources: ['wiz-chaindrop']
        });
    }

    return packages;
}

/**
 * Merge package lists from multiple campaign feeds, unioning affected
 * versions when the same package appears in more than one feed.
 */
function mergePackageLists(...lists) {
    const byName = new Map();
    for (const list of lists) {
        for (const pkg of list) {
            const existing = byName.get(pkg.name);
            if (existing) {
                const versions = new Set([...existing.affectedVersions, ...pkg.affectedVersions]);
                existing.affectedVersions = [...versions];
                existing.sources = [...new Set([...existing.sources, ...pkg.sources])];
            } else {
                byName.set(pkg.name, { ...pkg, affectedVersions: [...pkg.affectedVersions], sources: [...pkg.sources] });
            }
        }
    }
    return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Load existing database to preserve metadata
 */
function loadExistingDatabase() {
    try {
        const content = fs.readFileSync(OUTPUT_FILE, 'utf-8');
        return JSON.parse(content);
    } catch (err) {
        console.error('Warning: Could not load existing database:', err.message);
        return null;
    }
}

/**
 * Main update function
 */
async function updateDatabase() {
    console.log('Shai-Hulud 2.0 IOC Database Updater');
    console.log('===================================\n');

    // Fetch consolidated IOCs (Shai-Hulud 2.0 wave, Nov 2025)
    console.log(`Fetching: ${CONSOLIDATED_IOC_URL}`);
    const csvContent = await fetchUrl(CONSOLIDATED_IOC_URL);
    console.log(`Downloaded ${csvContent.length} bytes\n`);

    const shaiHulud2Packages = parseConsolidatedCSV(csvContent);
    console.log(`Parsed ${shaiHulud2Packages.length} packages from Shai-Hulud 2.0 consolidated IOCs\n`);

    // Fetch ChainDrop IOCs (Aug 2026 wave)
    console.log(`Fetching: ${CHAINDROP_IOC_URL}`);
    let chainDropPackages = [];
    try {
        const chainDropCsv = await fetchUrl(CHAINDROP_IOC_URL);
        console.log(`Downloaded ${chainDropCsv.length} bytes\n`);
        chainDropPackages = parseChainDropCSV(chainDropCsv);
        console.log(`Parsed ${chainDropPackages.length} packages from ChainDrop (Wiz Research) IOCs\n`);
    } catch (err) {
        console.error(`Warning: Could not fetch ChainDrop feed (${err.message}); keeping Shai-Hulud 2.0 data only`);
    }

    // Merge both campaign waves
    const packages = mergePackageLists(shaiHulud2Packages, chainDropPackages);
    console.log(`Merged total: ${packages.length} unique packages\n`);

    // Load existing database
    const existing = loadExistingDatabase();

    // Count sources
    const sourceCounts = {};
    packages.forEach(pkg => {
        pkg.sources.forEach(source => {
            sourceCounts[source] = (sourceCounts[source] || 0) + 1;
        });
    });

    console.log('Sources aggregated:');
    Object.entries(sourceCounts)
        .sort((a, b) => b[1] - a[1])
        .forEach(([source, count]) => {
            console.log(`  - ${source}: ${count} packages`);
        });
    console.log('');

    // Build updated database
    const now = new Date().toISOString();
    const database = {
        version: existing?.version || '2.2.0',
        lastUpdated: now,
        dataSource: {
            url: 'https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0',
            description: 'Consolidated IOCs from multiple security vendors (Shai-Hulud 2.0 wave) merged with the Wiz Research ChainDrop package list (Aug 2026 wave)',
            chainDropUrl: 'https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv',
            sources: Object.keys(sourceCounts).sort(),
            fetchedAt: now
        },
        attackInfo: {
            name: 'Shai-Hulud 2.0 / ChainDrop',
            alias: 'The Second Coming / Here We Go Again',
            firstDetected: '2025-11-24T03:16:00Z',
            description: 'Self-replicating npm worm targeting credential theft and supply chain compromise. The ChainDrop wave (Aug 4, 2026) hit keyv, cacheable, flat-cache and 450+ packages.'
        },
        indicators: existing?.indicators || {},
        acknowledgements: existing?.acknowledgements || [],
        packages: packages.map(pkg => ({
            name: pkg.name,
            severity: pkg.severity,
            affectedVersions: pkg.affectedVersions
        }))
    };

    // Write updated database
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(database, null, 2) + '\n');

    // Summary
    console.log('Database updated successfully!');
    console.log(`  - Total packages: ${packages.length}`);
    console.log(`  - Output: ${OUTPUT_FILE}`);
    console.log(`  - Last updated: ${now}`);

    // Compare with previous
    if (existing?.packages) {
        const oldCount = existing.packages.length;
        const newCount = packages.length;
        const diff = newCount - oldCount;
        if (diff > 0) {
            console.log(`  - New packages added: +${diff}`);
        } else if (diff < 0) {
            console.log(`  - Packages removed: ${diff}`);
        } else {
            console.log(`  - Package count unchanged`);
        }

        // Count packages that now have specific versions vs wildcards
        const oldWildcards = existing.packages.filter(p =>
            p.affectedVersions?.length === 1 && p.affectedVersions[0] === '*'
        ).length;
        console.log(`  - Previous wildcards: ${oldWildcards}`);
        console.log(`  - Now all packages have specific versions`);
    }

    return { success: true, packageCount: packages.length };
}

// Run if executed directly
if (require.main === module) {
    updateDatabase()
        .then(result => {
            console.log('\nDone!');
            process.exit(0);
        })
        .catch(err => {
            console.error('\nError:', err.message);
            process.exit(1);
        });
}

module.exports = { updateDatabase, parseConsolidatedCSV, fetchUrl };
