// src/tools/team-summary.ts

import type { JiraClient } from '../clients/jira.js';
import { SUMMARY_FIELDS, TREND_FIELDS } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';
import type { TeamSummary } from '../types/index.js';
import { buildFromSquad } from '../correlation/engine.js';

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

  // Use correlation engine for open tickets (includes enrichment/criticality parsing)
  const { primaryTickets } = await buildFromSquad(jira, tts, squad, scope);

  // Query closed VUL tickets (for breached-but-closed SLA tracking)
  const closedJql = `${base}${squadClause} AND status IN (Done, Closed)`;
  const closedResponse = await jira.searchIssues(closedJql, Infinity, SUMMARY_FIELDS);

  // Count by severity
  const bySeverity: Record<string, number> = {
    highest: 0,
    high: 0,
    medium: 0,
    low: 0,
    unprioritized: 0,
  };

  for (const ticket of primaryTickets) {
    const severity = ticket.severity.toLowerCase() || 'unprioritized';
    if (severity in bySeverity) {
      bySeverity[severity]++;
    } else {
      bySeverity.unprioritized++;
    }
  }

  // Count by source
  const sources = { ghas: 0, wiz: 0 };
  for (const ticket of primaryTickets) {
    if (ticket.source === 'ghas') {
      sources.ghas++;
    } else if (ticket.source === 'wiz' || ticket.source === 'wiz-issue') {
      sources.wiz++;
    }
  }

  // SLA health from enriched tickets (already have SLA from correlation engine)
  const slaHealth = { breached: 0, breachedClosed: 0, approaching: 0, within: 0 };
  for (const ticket of primaryTickets) {
    if (ticket.sla?.status === 'breached') {
      slaHealth.breached++;
    } else if (ticket.sla?.status === 'approaching') {
      slaHealth.approaching++;
    } else if (ticket.sla?.status === 'within') {
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

  // Aggregate enrichment counts from parsed attachments
  let cisaKevTickets = 0;
  let highEpssTickets = 0;
  let internetExposedTickets = 0;

  for (const ticket of primaryTickets) {
    if (ticket.enrichment) {
      if (ticket.enrichment.cisaKevCount > 0) cisaKevTickets++;
      if (ticket.enrichment.highEpssCount > 0) highEpssTickets++;
    }
    if (ticket.criticality) {
      if (ticket.criticality.hasInternetExposure) internetExposedTickets++;
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
    openCount: primaryTickets.length,
    bySeverity,
    slaHealth,
    sources,
    trend7d,
    riskIndicators: {
      cisaKevTickets,
      highEpssTickets,
      internetExposedTickets,
    },
  };
}
