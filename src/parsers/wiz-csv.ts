// src/parsers/wiz-csv.ts

import type { VulnerabilityFinding } from '../types/index.js';

export function parseWizCSV(csvContent: string): VulnerabilityFinding[] {
  const findings: VulnerabilityFinding[] = [];

  // Parse CSV records handling multi-line quoted fields
  const records = parseCSVRecords(csvContent);
  if (records.length < 2) return findings;

  // First record is the header
  const header = records[0];
  const columnMap = new Map<string, number>();
  header.forEach((col, idx) => columnMap.set(col.toLowerCase(), idx));

  // Parse data rows
  for (let i = 1; i < records.length; i++) {
    const values = records[i];

    const finding: VulnerabilityFinding = {
      cve: getValue(values, columnMap, 'name') || '',
      packageName: getValue(values, columnMap, 'detailedname') || '',
      description: getValue(values, columnMap, 'description') || '',
      severity: getValue(values, columnMap, 'severity') || '',
      affectedVersion: getValue(values, columnMap, 'version') || '',
      fixedVersion: getValue(values, columnMap, 'fixedversion') || '',
      locationPath: getValue(values, columnMap, 'locationpath') || '',
      detectionMethod: getValue(values, columnMap, 'detectionmethod') || 'Wiz',
      firstDetected: getValue(values, columnMap, 'firstdetectedat') || '',
      lastDetected: getValue(values, columnMap, 'lastdetectedat') || '',
    };

    if (finding.cve || finding.packageName) {
      findings.push(finding);
    }
  }

  return findings;
}

/**
 * Parse CSV content into records, properly handling:
 * - Quoted fields containing commas
 * - Quoted fields containing newlines (multi-line fields)
 * - Escaped quotes (doubled "")
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
          // Escaped quote
          currentField += '"';
          i++;
        } else {
          // End of quoted field
          inQuotes = false;
        }
      } else {
        // Any character inside quotes (including newlines)
        currentField += char;
      }
    } else {
      if (char === '"') {
        inQuotes = true;
      } else if (char === ',') {
        currentRecord.push(currentField.trim());
        currentField = '';
      } else if (char === '\n' || (char === '\r' && content[i + 1] === '\n')) {
        if (char === '\r') i++; // skip \n in \r\n
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

  // Handle last record
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
