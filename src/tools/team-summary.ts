// src/tools/team-summary.ts

import type { JiraClient } from '../clients/jira.js';
import { SUMMARY_FIELDS, TREND_FIELDS } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';
import type { TeamSummary, JiraIssue } from '../types/index.js';

function baseFilter(scope: string, filterId: string): string {
  return scope === 'audit' ? `filter = ${filterId}` : 'project = VUL';
}

export async function getTeamSummary(
  jira: JiraClient,
  tts: TTSClient,
  squad?: string,
  scope = 'audit',
  auditFilterId = '26914'
): Promise<TeamSummary> {
  const base = baseFilter(scope, auditFilterId);
  const squadClause = squad ? ` AND "Squad" = "${squad}"` : '';

  // Query open VUL tickets
  const openJql = `${base}${squadClause} AND status NOT IN (Done, Closed)`;
  // Query closed VUL tickets (for breached-but-closed SLA tracking)
  const closedJql = `${base}${squadClause} AND status IN (Done, Closed)`;

  const [openResponse, closedResponse] = await Promise.all([
    jira.searchIssues(openJql, Infinity, SUMMARY_FIELDS),
    jira.searchIssues(closedJql, Infinity, SUMMARY_FIELDS),
  ]);

  const issues = openResponse.issues;

  // Count by severity
  const bySeverity: Record<string, number> = {
    highest: 0,
    high: 0,
    medium: 0,
    low: 0,
    unprioritized: 0,
  };

  for (const issue of issues) {
    const severity = issue.fields.customfield_12500?.value?.toLowerCase() || 'unprioritized';
    if (severity in bySeverity) {
      bySeverity[severity]++;
    } else {
      bySeverity.unprioritized++;
    }
  }

  // Count by source
  const sources = { ghas: 0, wiz: 0 };
  for (const issue of issues) {
    const summary = issue.fields.summary.toLowerCase();
    if (summary.includes('ghas') || summary.includes('dependabot')) {
      sources.ghas++;
    } else if (summary.includes('wiz')) {
      sources.wiz++;
    }
  }

  // Get SLA status for open tickets
  const openKeys = issues.map(i => i.key);
  const openSlaResults = await tts.getIssueSLABatch(openKeys, 15);

  const slaHealth = { breached: 0, breachedClosed: 0, approaching: 0, within: 0 };
  for (const [_key, slaResponse] of openSlaResults) {
    const status = tts.parseSLAStatus(slaResponse);
    if (status.status === 'breached') {
      slaHealth.breached++;
    } else if (status.status === 'approaching') {
      slaHealth.approaching++;
    } else if (status.status === 'within') {
      slaHealth.within++;
    }
  }

  // Get SLA status for closed tickets to find breached-but-closed
  const closedKeys = closedResponse.issues.map(i => i.key);
  const closedSlaResults = await tts.getIssueSLABatch(closedKeys, 15);

  for (const [_key, slaResponse] of closedSlaResults) {
    const status = tts.parseSLAStatus(slaResponse);
    if (status.status === 'breached') {
      slaHealth.breachedClosed++;
    }
  }

  // Calculate 7-day trend
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  const sevenDaysAgoStr = sevenDaysAgo.toISOString().split('T')[0];

  const newJql = `${base}${squadClause} AND created >= "${sevenDaysAgoStr}"`;
  const resolvedJql = `${base}${squadClause} AND resolved >= "${sevenDaysAgoStr}"`;

  const [newResponse, resolvedResponse] = await Promise.all([
    jira.searchIssues(newJql, Infinity, TREND_FIELDS),
    jira.searchIssues(resolvedJql, Infinity, TREND_FIELDS),
  ]);

  const newCount = newResponse.total ?? newResponse.issues.length;
  const resolvedCount = resolvedResponse.total ?? resolvedResponse.issues.length;
  const trend7d = {
    new: newCount,
    resolved: resolvedCount,
    net: newCount - resolvedCount,
  };

  return {
    squad: squad || 'All PDE',
    openCount: issues.length,
    bySeverity,
    slaHealth,
    sources,
    trend7d,
  };
}
