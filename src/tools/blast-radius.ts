// src/tools/blast-radius.ts

import type { JiraClient } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';
import { buildFromCVE, buildFromPackage, buildFromTicket, correlateFindings } from '../correlation/engine.js';
import type { EnrichedTicket, CrossReference, CorrelationResult } from '../correlation/types.js';

export interface BlastRadiusResult {
  query: { cve?: string; package?: string; ticket_key?: string };
  summary: string;
  ghasTickets: BlastRadiusEntry[];
  wizTickets: BlastRadiusEntry[];
  crossSourceCorrelation: CrossReference[];
  slaImpact: {
    highestSeverity: string;
    mostUrgentDeadline: string | null;
    breachedCount: number;
  };
  enrichmentSummary: {
    cisaKevCount: number;
    criticalCvssCount: number;
    highEpssCount: number;
    internetExposedCount: number;
  } | null;
}

interface BlastRadiusEntry {
  key: string;
  source: string;
  repo: string | null;
  image: string | null;
  imageType: string | null;
  clusters: string[];
  squad: string | null;
  severity: string;
  sla: { status: string; deadline: string | null } | null;
  matchedCVEs: string[];
  matchedPackages: string[];
}

export async function getBlastRadius(
  jira: JiraClient,
  tts: TTSClient,
  ticketKey?: string,
  cve?: string,
  packageName?: string,
  scope = 'audit',
): Promise<BlastRadiusResult> {
  let result: CorrelationResult;

  if (ticketKey) {
    result = await buildFromTicket(jira, tts, ticketKey, scope);
  } else if (cve) {
    result = await buildFromCVE(jira, tts, cve, scope);
  } else if (packageName) {
    result = await buildFromPackage(jira, tts, packageName, scope);
  } else {
    throw new Error('At least one of ticket_key, cve, or package is required');
  }

  const tickets = result.primaryTickets;

  // For blast radius from ticket, also self-correlate primary tickets
  const crossRefs = ticketKey && tickets.length > 1
    ? correlateFindings(tickets, tickets)
    : result.crossReferences;

  // Split into GHAS and Wiz entries
  const ghasTickets: BlastRadiusEntry[] = [];
  const wizTickets: BlastRadiusEntry[] = [];

  for (const t of tickets) {
    const entry: BlastRadiusEntry = {
      key: t.key,
      source: t.source,
      repo: t.repo,
      image: t.image,
      imageType: t.imageType,
      clusters: t.clusters,
      squad: t.squad,
      severity: t.severity,
      sla: t.sla ? { status: t.sla.status, deadline: t.sla.deadline } : null,
      matchedCVEs: [...new Set(t.findings.map(f => f.cve).filter(c => c.startsWith('CVE-')))],
      matchedPackages: [...new Set(t.findings.map(f => f.packageName).filter(Boolean))],
    };

    if (t.source === 'ghas') {
      ghasTickets.push(entry);
    } else {
      wizTickets.push(entry);
    }
  }

  // Build summary
  const repos = new Set(tickets.map(t => t.repo).filter(Boolean));
  const images = new Set(tickets.map(t => t.image).filter(Boolean));
  const clusterCount = new Set(tickets.flatMap(t => t.clusters)).size;
  const summary = `This vulnerability appears in ${tickets.length} VUL ticket${tickets.length === 1 ? '' : 's'} across ${repos.size} repo${repos.size === 1 ? '' : 's'} and ${images.size} image${images.size === 1 ? '' : 's'}, affecting ${clusterCount} cluster deployment${clusterCount === 1 ? '' : 's'}.`;

  // SLA impact
  const severityOrder = ['critical', 'highest', 'high', 'medium', 'low', 'unknown'];
  const highestSeverity = tickets
    .map(t => t.severity)
    .sort((a, b) => severityOrder.indexOf(a.toLowerCase()) - severityOrder.indexOf(b.toLowerCase()))[0] || 'Unknown';

  const deadlines = tickets
    .filter(t => t.sla?.deadline)
    .sort((a, b) => (a.sla!.deadline! < b.sla!.deadline! ? -1 : 1));
  const mostUrgentDeadline = deadlines[0]?.sla?.deadline ?? null;

  const breachedCount = tickets.filter(t => t.sla?.status === 'breached').length;

  // Aggregate enrichment data across all affected tickets
  let enrichmentSummary = null;
  const hasEnrichment = tickets.some(t => t.enrichment || t.criticality);
  if (hasEnrichment) {
    enrichmentSummary = {
      cisaKevCount: tickets.filter(t => t.enrichment && t.enrichment.cisaKevCount > 0).length,
      criticalCvssCount: tickets.filter(t => t.enrichment && t.enrichment.criticalCvssCount > 0).length,
      highEpssCount: tickets.filter(t => t.enrichment && t.enrichment.highEpssCount > 0).length,
      internetExposedCount: tickets.filter(t => t.criticality?.hasInternetExposure).length,
    };
  }

  return {
    query: { cve, package: packageName, ticket_key: ticketKey },
    summary,
    ghasTickets,
    wizTickets,
    crossSourceCorrelation: crossRefs,
    slaImpact: { highestSeverity, mostUrgentDeadline, breachedCount },
    enrichmentSummary,
  };
}
