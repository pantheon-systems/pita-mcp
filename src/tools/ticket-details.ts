// src/tools/ticket-details.ts

import type { JiraClient } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';
import type { VulTicket, VulnerabilityFinding } from '../types/index.js';
import { parseWizCSV } from '../parsers/wiz-csv.js';
import { parseGHASCSV } from '../parsers/ghas-csv.js';

export async function getTicketDetails(
  jira: JiraClient,
  tts: TTSClient,
  ticketKey: string
): Promise<VulTicket> {
  const issue = await jira.getIssue(ticketKey);

  // Determine source
  const summary = issue.fields.summary.toLowerCase();
  let source: 'ghas' | 'wiz' | 'unknown' = 'unknown';
  if (summary.includes('ghas') || summary.includes('dependabot')) {
    source = 'ghas';
  } else if (summary.includes('wiz')) {
    source = 'wiz';
  }

  // Get SLA status
  const slaResponse = await tts.getIssueSLA(ticketKey);
  const sla = tts.parseSLAStatus(slaResponse);

  // Extract description text
  const description = jira.extractTextFromADF(issue.fields.description);

  // Parse findings from CSV attachments first, fall back to description
  let findings: VulnerabilityFinding[] = [];

  const csvAttachments = issue.fields.attachment.filter(
    a => a.filename.endsWith('.csv') && !a.filename.includes('criticality')
  );

  for (const csvAttachment of csvAttachments) {
    try {
      const csvContent = await jira.getAttachmentContent(csvAttachment.content);
      const parsed = csvContent.includes('package_name')
        ? parseGHASCSV(csvContent)
        : parseWizCSV(csvContent);
      findings.push(...parsed);
    } catch (e) {
      console.error(`Failed to parse CSV for ${issue.key}:`, e);
    }
  }

  // Fall back to CVE extraction from description if no CSV findings
  if (findings.length === 0) {
    const cvePattern = /CVE-\d{4}-\d+/g;
    const cves = description.match(cvePattern) || [];
    for (const cve of cves) {
      findings.push({
        cve,
        packageName: 'Unknown',
        description: '',
        severity: '',
        affectedVersion: '',
        fixedVersion: '',
        locationPath: '',
        detectionMethod: source === 'ghas' ? 'GHAS' : 'Wiz',
        firstDetected: '',
        lastDetected: '',
      });
    }
  }

  return {
    key: issue.key,
    summary: issue.fields.summary,
    description,
    severity: issue.fields.customfield_12500?.value ?? 'Unknown',
    status: issue.fields.status.name,
    squad: issue.fields.customfield_12050?.value ?? null,
    assignee: issue.fields.assignee?.emailAddress ?? null,
    created: issue.fields.created,
    source,
    sla,
    findings,
  };
}
