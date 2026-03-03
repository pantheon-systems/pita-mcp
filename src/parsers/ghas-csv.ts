// src/parsers/ghas-csv.ts

import type { VulnerabilityFinding } from '../types/index.js';

export function parseGHASCSV(csvContent: string): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];
  const records = parseCSVRecords(csvContent);

  if (records.length < 2) return findings;

  // First record is the header
  const header = records[0];
  const columnMap = new Map<string, number>();
  header.forEach((col, idx) => columnMap.set(col.toLowerCase(), idx));

  for (let i = 1; i < records.length; i++) {
    const values = records[i];

    // Extract CVE from cve_cwe field (e.g., "CVE-2026-26996, CWE-1333")
    const cveCweRaw = getValue(values, columnMap, 'cve_cwe');
    const cveMatch = cveCweRaw.match(/CVE-\d{4}-\d+/);
    const cve = cveMatch ? cveMatch[0] : cveCweRaw;

    const finding: VulnerabilityFinding = {
      cve,
      packageName: getValue(values, columnMap, 'package_name') || '',
      description: getValue(values, columnMap, 'summary') || '',
      severity: getValue(values, columnMap, 'severity') || '',
      affectedVersion: getValue(values, columnMap, 'vulnerable_range') || '',
      fixedVersion: getValue(values, columnMap, 'patched_version') || '',
      locationPath: getValue(values, columnMap, 'html_url') || '',
      detectionMethod: 'GHAS',
      firstDetected: getValue(values, columnMap, 'created_at') || '',
      lastDetected: '',
    };

    if (finding.cve || finding.packageName) {
      findings.push(finding);
    }
  }

  return findings;
}

/**
 * Parse CSV content into records, handling quoted fields with commas and newlines.
 */
function parseCSVRecords(content: string): string[][] {
  const records: string[][] = [];
  let currentRecord: string[] = [];
  let currentField = '';
  let inQuotes = false;

  for (let i = 0; i < content.length; i++) {
    const char = content[i];

    if (inQuotes) {
      if (char === '"') {
        if (content[i + 1] === '"') {
          currentField += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        currentField += char;
      }
    } else {
      if (char === '"') {
        inQuotes = true;
      } else if (char === ',') {
        currentRecord.push(currentField.trim());
        currentField = '';
      } else if (char === '\n' || (char === '\r' && content[i + 1] === '\n')) {
        if (char === '\r') i++;
        currentRecord.push(currentField.trim());
        if (currentRecord.some(f => f !== '')) {
          records.push(currentRecord);
        }
        currentRecord = [];
        currentField = '';
      } else {
        currentField += char;
      }
    }
  }

  if (currentField || currentRecord.length > 0) {
    currentRecord.push(currentField.trim());
    if (currentRecord.some(f => f !== '')) {
      records.push(currentRecord);
    }
  }

  return records;
}

function getValue(values: string[], columnMap: Map<string, number>, column: string): string {
  const idx = columnMap.get(column);
  if (idx === undefined || idx >= values.length) return '';
  return values[idx];
}
