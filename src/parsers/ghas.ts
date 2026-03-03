// src/parsers/ghas.ts

import type { VulnerabilityFinding } from '../types/index.js';

export function parseGHASDescription(description: string): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];

  // GHAS ticket format example:
  // Package Name | Severity | CVE/CWE | Count
  // minimatch    | high     | CVE-2026-26996, CWE-1333 | 1

  const lines = description.split('\n');
  let inTable = false;
  let packageCol = -1;
  let severityCol = -1;
  let cveCol = -1;

  for (const line of lines) {
    const trimmed = line.trim();

    // Detect table header
    if (trimmed.toLowerCase().includes('package name') && trimmed.includes('|')) {
      const cols = trimmed.split('|').map(c => c.trim().toLowerCase());
      packageCol = cols.findIndex(c => c.includes('package'));
      severityCol = cols.findIndex(c => c.includes('severity'));
      cveCol = cols.findIndex(c => c.includes('cve') || c.includes('cwe'));
      inTable = true;
      continue;
    }

    // Skip separator rows
    if (trimmed.match(/^[\|\-\s]+$/)) continue;

    // Parse data rows
    if (inTable && trimmed.includes('|')) {
      const cols = trimmed.split('|').map(c => c.trim());

      const packageName = packageCol >= 0 ? cols[packageCol] : '';
      const severity = severityCol >= 0 ? cols[severityCol] : '';
      const cveCell = cveCol >= 0 ? cols[cveCol] : '';

      // Extract CVEs from cell
      const cveMatches = cveCell.match(/CVE-\d{4}-\d+/g) || [];

      for (const cve of cveMatches) {
        findings.push({
          cve,
          packageName,
          description: '',
          severity,
          affectedVersion: '',
          fixedVersion: '',
          locationPath: '',
          detectionMethod: 'GHAS',
          firstDetected: '',
          lastDetected: '',
        });
      }

      // If no CVE found but package exists, still add
      if (cveMatches.length === 0 && packageName) {
        findings.push({
          cve: cveCell,
          packageName,
          description: '',
          severity,
          affectedVersion: '',
          fixedVersion: '',
          locationPath: '',
          detectionMethod: 'GHAS',
          firstDetected: '',
          lastDetected: '',
        });
      }
    }
  }

  return findings;
}

export function extractRepoFromSummary(summary: string): string {
  // GHAS ticket summary format: "GHAS 2026-02-25 - repo-name"
  const match = summary.match(/GHAS\s+[\d-]+\s+-\s+(.+)/i);
  return match ? match[1].trim() : '';
}
