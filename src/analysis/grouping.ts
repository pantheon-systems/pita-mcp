// src/analysis/grouping.ts

import type { VulnerabilityFinding, RemediationGroup } from '../types/index.js';

export interface TicketFindings {
  ticketKey: string;
  summary: string;
  repo: string;
  findings: VulnerabilityFinding[];
}

export function groupByFix(tickets: TicketFindings[]): RemediationGroup[] {
  // Group by (packageName + fixedVersion) or (cve)
  const groups = new Map<string, {
    cves: Set<string>;
    packageName: string;
    fixedVersion: string;
    ticketKeys: Set<string>;
    repos: Set<string>;
    severity: string;
  }>();

  for (const ticket of tickets) {
    for (const finding of ticket.findings) {
      // Create group key
      const groupKey = finding.fixedVersion
        ? `${finding.packageName}@${finding.fixedVersion}`
        : finding.cve || finding.packageName;

      if (!groupKey) continue;

      if (!groups.has(groupKey)) {
        groups.set(groupKey, {
          cves: new Set(),
          packageName: finding.packageName,
          fixedVersion: finding.fixedVersion,
          ticketKeys: new Set(),
          repos: new Set(),
          severity: finding.severity,
        });
      }

      const group = groups.get(groupKey)!;
      if (finding.cve) group.cves.add(finding.cve);
      group.ticketKeys.add(ticket.ticketKey);
      if (ticket.repo) group.repos.add(ticket.repo);

      // Keep highest severity
      if (compareSeverity(finding.severity, group.severity) > 0) {
        group.severity = finding.severity;
      }
    }
  }

  // Convert to array and sort by impact
  const result: RemediationGroup[] = [];

  for (const [key, group] of groups) {
    const cveList = Array.from(group.cves);
    const ticketKeysArray = Array.from(group.ticketKeys);
    result.push({
      fix: group.fixedVersion
        ? `Update ${group.packageName} to ${group.fixedVersion}`
        : `Fix ${cveList[0] || group.packageName}`,
      cve: cveList[0] || '',
      packageName: group.packageName,
      fixedVersion: group.fixedVersion,
      ticketsResolved: ticketKeysArray.length,
      ticketsJql: `key in (${ticketKeysArray.join(', ')})`,
      reposAffected: Array.from(group.repos),
      severity: group.severity,
    });
  }

  // Sort by: tickets resolved × severity weight
  result.sort((a, b) => {
    const scoreA = a.ticketsResolved * severityWeight(a.severity);
    const scoreB = b.ticketsResolved * severityWeight(b.severity);
    return scoreB - scoreA;
  });

  return result;
}

function severityWeight(severity: string): number {
  const s = severity.toLowerCase();
  if (s === 'critical' || s === 'highest') return 4;
  if (s === 'high') return 3;
  if (s === 'medium') return 2;
  if (s === 'low') return 1;
  return 1;
}

function compareSeverity(a: string, b: string): number {
  return severityWeight(a) - severityWeight(b);
}
