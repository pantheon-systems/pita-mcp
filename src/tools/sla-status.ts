// src/tools/sla-status.ts

import type { JiraClient } from '../clients/jira.js';
import { SLA_FIELDS } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';

interface SLATicket {
  key: string;
  summary: string;
  daysOverdue: number;
  assignee: string | null;
  severity: string;
}

export interface SLAStatusResult {
  squad: string;
  breached: SLATicket[];
  breachedClosed: SLATicket[];
  approaching: {
    key: string;
    summary: string;
    daysRemaining: number;
    assignee: string | null;
    severity: string;
  }[];
}

export async function getSLAStatus(
  jira: JiraClient,
  tts: TTSClient,
  squad?: string,
  priorityFilter?: string,
  scope = 'audit',
  auditFilterId = '26914'
): Promise<SLAStatusResult> {
  // Build JQL
  const base = scope === 'audit' ? `filter = ${auditFilterId}` : 'project = VUL';
  const squadClause = squad ? ` AND "Squad" = "${squad}"` : '';

  let severityClause = '';
  if (priorityFilter) {
    const severities = priorityFilter.split(',').map(p => p.trim());
    const severityList = severities.map(s => `"${s}"`).join(', ');
    severityClause = ` AND "Severity" IN (${severityList})`;
  }

  const openJql = `${base}${squadClause} AND status NOT IN (Done, Closed)${severityClause}`;
  const closedJql = `${base}${squadClause} AND status IN (Done, Closed)${severityClause}`;

  const [openResponse, closedResponse] = await Promise.all([
    jira.searchIssues(openJql, Infinity, SLA_FIELDS),
    jira.searchIssues(closedJql, Infinity, SLA_FIELDS),
  ]);

  // Get SLA status for all tickets
  const openKeys = openResponse.issues.map(i => i.key);
  const closedKeys = closedResponse.issues.map(i => i.key);

  const [openSlaResults, closedSlaResults] = await Promise.all([
    tts.getIssueSLABatch(openKeys, 15),
    tts.getIssueSLABatch(closedKeys, 15),
  ]);

  const breached: SLATicket[] = [];
  const approaching: SLAStatusResult['approaching'] = [];

  for (const issue of openResponse.issues) {
    const slaResponse = openSlaResults.get(issue.key);
    const status = tts.parseSLAStatus(slaResponse ?? null);

    if (status.status === 'breached') {
      breached.push({
        key: issue.key,
        summary: issue.fields.summary,
        daysOverdue: status.daysOverdue ?? 0,
        assignee: issue.fields.assignee?.emailAddress ?? null,
        severity: issue.fields.customfield_12500?.value ?? 'Unknown',
      });
    } else if (status.status === 'approaching') {
      approaching.push({
        key: issue.key,
        summary: issue.fields.summary,
        daysRemaining: status.daysRemaining ?? 0,
        assignee: issue.fields.assignee?.emailAddress ?? null,
        severity: issue.fields.customfield_12500?.value ?? 'Unknown',
      });
    }
  }

  // Find closed tickets that breached SLA
  const breachedClosed: SLATicket[] = [];
  for (const issue of closedResponse.issues) {
    const slaResponse = closedSlaResults.get(issue.key);
    const status = tts.parseSLAStatus(slaResponse ?? null);

    if (status.status === 'breached') {
      breachedClosed.push({
        key: issue.key,
        summary: issue.fields.summary,
        daysOverdue: status.daysOverdue ?? 0,
        assignee: issue.fields.assignee?.emailAddress ?? null,
        severity: issue.fields.customfield_12500?.value ?? 'Unknown',
      });
    }
  }

  breached.sort((a, b) => b.daysOverdue - a.daysOverdue);
  breachedClosed.sort((a, b) => b.daysOverdue - a.daysOverdue);
  approaching.sort((a, b) => a.daysRemaining - b.daysRemaining);

  return { squad: squad || 'All PDE', breached, breachedClosed, approaching };
}
