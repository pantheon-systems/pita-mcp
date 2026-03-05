// src/correlation/types.ts

import type { VulnerabilityFinding, SLAStatus, EnrichmentData, CriticalityScore } from '../types/index.js';

export type TicketSource = 'ghas' | 'wiz' | 'wiz-issue';
export type ImageType = 'pantheon-built' | 'third-party';
export type Relationship = 'same_artifact' | 'shared_cve';

export interface EnrichedTicket {
  key: string;
  summary: string;
  source: TicketSource;
  repo: string | null;
  image: string | null;
  imageType: ImageType | null;
  clusters: string[];
  squad: string | null;
  severity: string;
  status: string;
  sla: SLAStatus | null;
  findings: VulnerabilityFinding[];
  enrichment: EnrichmentData | null;
  criticality: CriticalityScore | null;
}

export interface CrossReference {
  primaryTicketKey: string;
  relatedTicketKey: string;
  relationship: Relationship;
  sharedCVEs: string[];
  sharedPackages: string[];
  relatedSource: TicketSource;
  relatedRepo: string | null;
  relatedImage: string | null;
  relatedImageType: ImageType | null;
  relatedSquad: string | null;
  note: string;
}

export interface CorrelationResult {
  primaryTickets: EnrichedTicket[];
  crossReferences: CrossReference[];
}
