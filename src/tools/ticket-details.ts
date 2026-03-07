// src/tools/ticket-details.ts

import type { JiraClient } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';
import type { VulTicket, VulnerabilityFinding, EnrichmentData, CriticalityScore } from '../types/index.js';
import type { CrossReference } from '../correlation/types.js';
import { buildFromTicket } from '../correlation/engine.js';
import { extractRepo, extractImage } from '../correlation/extractors.js';

export interface EnhancedVulTicket extends VulTicket {
  repo: string | null;
  relatedTickets: RelatedTicketEntry[];
  enrichment: EnrichmentData | null;
  criticality: CriticalityScore | null;
}

export interface RelatedTicketEntry {
  key: string;
  source: string;
  relationship: string;
  sharedCVEs: string[];
  sharedPackages: string[];
  image: string | null;
  imageType: string | null;
  squad: string | null;
  note: string;
}

export async function getTicketDetails(
  jira: JiraClient,
  tts: TTSClient,
  ticketKey: string,
  scope = 'audit',
): Promise<EnhancedVulTicket> {
  const { primaryTickets, crossReferences } = await buildFromTicket(jira, tts, ticketKey, scope);

  const ticket = primaryTickets[0];
  if (!ticket) {
    throw new Error(`Ticket ${ticketKey} not found`);
  }

  // Map cross-references to the simpler output format
  const relatedTickets: RelatedTicketEntry[] = crossReferences.map(xref => ({
    key: xref.relatedTicketKey,
    source: xref.relatedSource,
    relationship: xref.relationship,
    sharedCVEs: xref.sharedCVEs,
    sharedPackages: xref.sharedPackages,
    image: xref.relatedImage,
    imageType: xref.relatedImageType,
    squad: xref.relatedSquad,
    note: xref.note,
  }));

  return {
    key: ticket.key,
    summary: ticket.summary,
    description: '', // Description already extracted during enrichment, keep output lean
    severity: ticket.severity,
    status: ticket.status,
    squad: ticket.squad,
    assignee: null, // Not tracked in EnrichedTicket, kept for interface compat
    created: '', // Not tracked in EnrichedTicket, kept for interface compat
    source: ticket.source === 'wiz-issue' ? 'wiz' : ticket.source,
    sla: ticket.sla,
    findings: ticket.findings,
    repo: ticket.repo,
    relatedTickets,
    enrichment: ticket.enrichment,
    criticality: ticket.criticality,
  };
}
