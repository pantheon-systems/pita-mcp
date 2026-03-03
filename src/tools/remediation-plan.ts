// src/tools/remediation-plan.ts

import type { JiraClient } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';
import type { RemediationPlan, RemediationGroup, VulnerabilityFinding } from '../types/index.js';
import { parseWizCSV } from '../parsers/wiz-csv.js';
import { parseGHASCSV } from '../parsers/ghas-csv.js';
import { parseGHASDescription, extractRepoFromSummary } from '../parsers/ghas.js';
import { groupByFix, type TicketFindings } from '../analysis/grouping.js';

export async function getRemediationPlan(
  jira: JiraClient,
  tts: TTSClient,
  squad?: string,
  limit = 10,
  scope = 'audit',
  auditFilterId = '26914'
): Promise<RemediationPlan> {
  // Fetch all open VUL tickets
  const base = scope === 'audit' ? `filter = ${auditFilterId}` : 'project = VUL';
  const squadClause = squad ? ` AND "Squad" = "${squad}"` : '';
  const jql = `${base}${squadClause} AND status NOT IN (Done, Closed)`;
  const response = await jira.searchIssues(jql, Infinity);
  const issues = response.issues;

  // Parse findings from each ticket
  const ticketFindings: TicketFindings[] = [];

  for (const issue of issues) {
    const summary = issue.fields.summary;
    const description = jira.extractTextFromADF(issue.fields.description);
    const isGHAS = summary.toLowerCase().includes('ghas');

    let findings: VulnerabilityFinding[] = [];

    // Try CSV attachments first (both Wiz and GHAS have them)
    const csvAttachments = issue.fields.attachment.filter(
      a => a.filename.endsWith('.csv') && !a.filename.includes('criticality')
    );

    for (const csvAttachment of csvAttachments) {
      try {
        const csvContent = await jira.getAttachmentContent(csvAttachment.content);
        // GHAS CSVs have 'package_name' header, Wiz CSVs have 'detailedName'
        const parsed = csvContent.includes('package_name')
          ? parseGHASCSV(csvContent)
          : parseWizCSV(csvContent);
        findings.push(...parsed);
      } catch (e) {
        console.error(`Failed to parse CSV for ${issue.key}:`, e);
      }
    }

    // Fall back to description parsing for GHAS if no CSV findings
    if (findings.length === 0 && isGHAS) {
      findings = parseGHASDescription(description);
    }

    if (findings.length > 0) {
      ticketFindings.push({
        ticketKey: issue.key,
        summary,
        repo: extractRepoFromSummary(summary),
        findings,
      });
    }
  }

  // Group findings by fix
  const allGroups = groupByFix(ticketFindings);

  // Separate high-leverage (multiple tickets) from standalone
  const highLeverageFixes = allGroups
    .filter(g => g.ticketsResolved > 1)
    .slice(0, limit);

  // For squad-specific queries, enrich top fixes with PDE-wide counts
  if (squad && highLeverageFixes.length > 0) {
    await enrichWithPDEWideCounts(jira, highLeverageFixes, squad, base);
  }

  const standaloneFixes = allGroups
    .filter(g => g.ticketsResolved === 1)
    .slice(0, 10)
    .map(g => {
      // Extract first key from JQL "key in (VUL-1234)"
      const keyMatch = g.ticketsJql.match(/VUL-\d+/);
      const key = keyMatch ? keyMatch[0] : '';
      return {
        key,
        summary: ticketFindings.find(t => t.ticketKey === key)?.summary || '',
        fix: g.fix,
      };
    });

  return {
    squad: squad || 'All PDE',
    highLeverageFixes,
    standaloneFixes,
  };
}

/**
 * For each high-leverage fix, search PDE-wide for tickets containing the same
 * CVE to show cross-org impact. Only searches by CVE since that's the most
 * reliable cross-ticket identifier.
 */
async function enrichWithPDEWideCounts(
  jira: JiraClient,
  fixes: RemediationGroup[],
  squad: string,
  base: string
): Promise<void> {
  // Collect unique CVEs from top fixes
  const cvesToSearch = new Map<string, RemediationGroup[]>();
  for (const fix of fixes) {
    if (fix.cve && fix.cve.startsWith('CVE-')) {
      if (!cvesToSearch.has(fix.cve)) {
        cvesToSearch.set(fix.cve, []);
      }
      cvesToSearch.get(fix.cve)!.push(fix);
    }
  }

  // Search PDE-wide for each CVE (excluding the squad's own tickets)
  for (const [cve, relatedFixes] of cvesToSearch) {
    try {
      const pdeJql = `${base} AND "Squad" != "${squad}" AND status NOT IN (Done, Closed) AND text ~ "${cve}"`;
      const pdeResponse = await jira.searchIssues(pdeJql, Infinity, ['summary']);

      for (const fix of relatedFixes) {
        fix.pdeWideTickets = pdeResponse.issues.length;
        fix.pdeWideJql = pdeJql;
      }
    } catch (e) {
      console.error(`Failed PDE-wide lookup for ${cve}:`, e);
    }
  }
}
