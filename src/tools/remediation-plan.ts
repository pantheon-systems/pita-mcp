// src/tools/remediation-plan.ts

import type { JiraClient } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';
import type {
  RepoCentricRemediationPlan,
  RepoRemediationEntry,
  ThirdPartyImageEntry,
  UnattributedEntry,
  RepoFix,
} from '../types/index.js';
import { buildFromSquad } from '../correlation/engine.js';
import type { EnrichedTicket, CrossReference } from '../correlation/types.js';

const SEVERITY_ORDER = ['critical', 'highest', 'high', 'medium', 'low', 'unknown'];

/** Score risk context for sorting: KEV and internet-exposed rank highest */
function riskScore(ctx: { hasCisaKev: boolean; hasHighEpss: boolean; hasCriticalCvss: boolean; isInternetExposed: boolean } | null): number {
  if (!ctx) return 0;
  let score = 0;
  if (ctx.hasCisaKev) score += 4;
  if (ctx.isInternetExposed) score += 3;
  if (ctx.hasCriticalCvss) score += 2;
  if (ctx.hasHighEpss) score += 1;
  return score;
}

export async function getRemediationPlan(
  jira: JiraClient,
  tts: TTSClient,
  squad?: string,
  limit = 10,
  scope = 'audit',
  _auditFilterId = '26914'
): Promise<RepoCentricRemediationPlan> {
  const { primaryTickets, crossReferences } = await buildFromSquad(jira, tts, squad, scope);

  // Build cross-reference lookup: ticketKey -> CrossReference[]
  const xrefByTicket = new Map<string, CrossReference[]>();
  for (const xref of crossReferences) {
    if (!xrefByTicket.has(xref.primaryTicketKey)) {
      xrefByTicket.set(xref.primaryTicketKey, []);
    }
    xrefByTicket.get(xref.primaryTicketKey)!.push(xref);
  }

  // Separate tickets into categories
  const pantheonRepoMap = new Map<string, { tickets: EnrichedTicket[]; xrefs: CrossReference[] }>();
  const thirdPartyMap = new Map<string, EnrichedTicket[]>();
  const unattributed: UnattributedEntry[] = [];

  for (const ticket of primaryTickets) {
    if (ticket.source === 'ghas' && ticket.repo) {
      // GHAS ticket — group by repo
      if (!pantheonRepoMap.has(ticket.repo)) {
        pantheonRepoMap.set(ticket.repo, { tickets: [], xrefs: [] });
      }
      pantheonRepoMap.get(ticket.repo)!.tickets.push(ticket);
      const xrefs = xrefByTicket.get(ticket.key) || [];
      pantheonRepoMap.get(ticket.repo)!.xrefs.push(...xrefs);
    } else if (ticket.source === 'wiz' && ticket.image && ticket.imageType === 'third-party') {
      // Third-party Wiz image
      if (!thirdPartyMap.has(ticket.image)) {
        thirdPartyMap.set(ticket.image, []);
      }
      thirdPartyMap.get(ticket.image)!.push(ticket);
    } else if (ticket.source === 'wiz' && ticket.image && ticket.imageType === 'pantheon-built') {
      // Pantheon-built Wiz image — try to group with repo
      // Check if any cross-reference links it to a GHAS repo
      const xrefs = xrefByTicket.get(ticket.key) || [];
      const sameArtifact = xrefs.find(x => x.relationship === 'same_artifact' && x.relatedRepo);
      if (sameArtifact && sameArtifact.relatedRepo) {
        if (!pantheonRepoMap.has(sameArtifact.relatedRepo)) {
          pantheonRepoMap.set(sameArtifact.relatedRepo, { tickets: [], xrefs: [] });
        }
        pantheonRepoMap.get(sameArtifact.relatedRepo)!.tickets.push(ticket);
      } else if (ticket.image) {
        // Use image name as pseudo-repo
        if (!pantheonRepoMap.has(ticket.image)) {
          pantheonRepoMap.set(ticket.image, { tickets: [], xrefs: [] });
        }
        pantheonRepoMap.get(ticket.image)!.tickets.push(ticket);
      } else {
        unattributed.push({
          ticketKey: ticket.key,
          summary: ticket.summary,
          resource: ticket.image,
          severity: ticket.severity,
          source: ticket.source,
        });
      }
    } else if (ticket.source === 'wiz-issue') {
      // Wiz Issue tickets — always unattributed (no CVE-level findings)
      unattributed.push({
        ticketKey: ticket.key,
        summary: ticket.summary,
        resource: ticket.image,
        severity: ticket.severity,
        source: 'wiz-issue',
      });
    } else {
      unattributed.push({
        ticketKey: ticket.key,
        summary: ticket.summary,
        resource: ticket.image || ticket.repo,
        severity: ticket.severity,
        source: ticket.source,
      });
    }
  }

  // Build Pantheon repo entries
  const pantheonRepos: RepoRemediationEntry[] = [];
  for (const [repo, data] of pantheonRepoMap) {
    const ghasTickets = data.tickets.filter(t => t.source === 'ghas').map(t => t.key);
    const wizTickets = data.tickets.filter(t => t.source === 'wiz').map(t => t.key);
    const allTicketKeys = data.tickets.map(t => t.key);

    // Build fixes from findings
    const fixMap = new Map<string, RepoFix>();
    for (const ticket of data.tickets) {
      for (const finding of ticket.findings) {
        if (!finding.fixedVersion) continue;
        const fixKey = `${finding.packageName}@${finding.fixedVersion}`;
        if (!fixMap.has(fixKey)) {
          const hasWizMatch = data.xrefs.some(
            x => x.sharedCVEs.includes(finding.cve) && x.relationship === 'same_artifact'
          );
          fixMap.set(fixKey, {
            packageName: finding.packageName,
            fixedVersion: finding.fixedVersion,
            cve: finding.cve,
            resolvesGhas: ticket.source === 'ghas',
            resolvesWiz: ticket.source === 'wiz' || hasWizMatch,
            note: hasWizMatch || ticket.source === 'wiz'
              ? 'GHAS finding + Wiz runtime finding both resolved'
              : 'GHAS finding resolved (no matching Wiz runtime finding)',
          });
        } else {
          const fix = fixMap.get(fixKey)!;
          if (ticket.source === 'ghas') fix.resolvesGhas = true;
          if (ticket.source === 'wiz') fix.resolvesWiz = true;
          if (fix.resolvesGhas && fix.resolvesWiz) {
            fix.note = 'GHAS finding + Wiz runtime finding both resolved';
          }
        }
      }
    }

    // Determine severity and SLA
    const highestSeverity = data.tickets
      .map(t => t.severity)
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.toLowerCase()) - SEVERITY_ORDER.indexOf(b.toLowerCase()))[0] || 'Unknown';

    const deadlines = data.tickets
      .filter(t => t.sla?.deadline)
      .sort((a, b) => (a.sla!.deadline! < b.sla!.deadline! ? -1 : 1));
    const slaUrgency = deadlines[0]?.sla?.deadline ?? null;

    const crossSourceNotes: string[] = [];
    for (const xref of data.xrefs) {
      if (xref.relationship === 'same_artifact') {
        crossSourceNotes.push(
          `${xref.relatedTicketKey} (Wiz) is the runtime view of this repo — fixing and redeploying resolves both`
        );
      } else if (xref.relationship === 'shared_cve') {
        crossSourceNotes.push(
          `${xref.relatedTicketKey} (${xref.relatedSquad || 'unassigned'}) has the same CVE independently`
        );
      }
    }

    // Aggregate risk context from enrichment/criticality data
    let riskContext = null;
    const hasEnrichmentData = data.tickets.some(t => t.enrichment || t.criticality);
    if (hasEnrichmentData) {
      riskContext = {
        hasCisaKev: data.tickets.some(t => t.enrichment && t.enrichment.cisaKevCount > 0),
        hasHighEpss: data.tickets.some(t => t.enrichment && t.enrichment.highEpssCount > 0),
        hasCriticalCvss: data.tickets.some(t => t.enrichment && t.enrichment.criticalCvssCount > 0),
        isInternetExposed: data.tickets.some(t => t.criticality?.hasInternetExposure),
      };
    }

    pantheonRepos.push({
      repo,
      ghasTickets,
      wizTickets,
      severity: highestSeverity,
      slaUrgency,
      fixes: Array.from(fixMap.values()),
      crossSourceNotes,
      ticketsJql: `key in (${allTicketKeys.join(', ')})`,
      riskContext,
    });
  }

  // Sort repos by risk indicators, then severity, then SLA urgency
  // KEV and internet-exposed findings rank highest
  pantheonRepos.sort((a, b) => {
    const aRiskScore = riskScore(a.riskContext);
    const bRiskScore = riskScore(b.riskContext);
    if (aRiskScore !== bRiskScore) return bRiskScore - aRiskScore;

    const sevDiff = SEVERITY_ORDER.indexOf(a.severity.toLowerCase()) - SEVERITY_ORDER.indexOf(b.severity.toLowerCase());
    if (sevDiff !== 0) return sevDiff;
    if (a.slaUrgency && b.slaUrgency) return a.slaUrgency < b.slaUrgency ? -1 : 1;
    return a.slaUrgency ? -1 : 1;
  });

  // Build third-party image entries
  const thirdPartyImages: ThirdPartyImageEntry[] = [];
  for (const [image, tickets] of thirdPartyMap) {
    const allClusters = [...new Set(tickets.flatMap(t => t.clusters))];
    const allKeys = tickets.map(t => t.key);

    const fixMap = new Map<string, RepoFix>();
    for (const ticket of tickets) {
      for (const finding of ticket.findings) {
        if (!finding.fixedVersion) continue;
        const fixKey = `${finding.packageName}@${finding.fixedVersion}`;
        if (!fixMap.has(fixKey)) {
          fixMap.set(fixKey, {
            packageName: finding.packageName,
            fixedVersion: finding.fixedVersion,
            cve: finding.cve,
            resolvesGhas: false,
            resolvesWiz: true,
            note: '',
          });
        }
      }
    }

    const highestSeverity = tickets
      .map(t => t.severity)
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.toLowerCase()) - SEVERITY_ORDER.indexOf(b.toLowerCase()))[0] || 'Unknown';

    thirdPartyImages.push({
      image,
      registry: tickets[0]?.summary || '',
      wizTickets: allKeys,
      severity: highestSeverity,
      clusters: allClusters,
      fixes: Array.from(fixMap.values()),
      action: 'Upgrade Helm chart or pin newer image version',
      ticketsJql: `key in (${allKeys.join(', ')})`,
    });
  }

  return {
    squad: squad || 'All PDE',
    pantheonRepos: pantheonRepos.slice(0, limit),
    thirdPartyImages,
    unattributed,
  };
}
