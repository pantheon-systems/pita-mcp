// src/types/index.ts

// === Jira Types ===

export interface JiraIssue {
  key: string;
  id: string;
  fields: {
    summary: string;
    description: JiraADF | null;
    priority: { name: string } | null;
    status: { name: string };
    assignee: { emailAddress: string; displayName: string } | null;
    created: string;
    updated: string;
    labels: string[];
    attachment: JiraAttachment[];
    customfield_12050?: { value: string } | null; // Squad field
    customfield_12500?: { value: string } | null; // Severity field
  };
}

export interface JiraADF {
  type: string;
  content: JiraADFNode[];
}

export interface JiraADFNode {
  type: string;
  text?: string;
  content?: JiraADFNode[];
  marks?: { type: string; attrs?: Record<string, string> }[];
}

export interface JiraAttachment {
  id: string;
  filename: string;
  content: string; // URL to download
  mimeType: string;
  size: number;
  created: string;
}

export interface JiraSearchResponse {
  issues: JiraIssue[];
  nextPageToken?: string;
  isLast?: boolean;
  total?: number; // May not be present in new API
}

// === TTS (Time to SLA) Types ===

export interface TTSSLAResponse {
  slaName: string;
  slaStatus: 'STILL' | 'EXCEED' | 'PAUSED';
  startDate: number;
  deadline: number;
  remainingDuration: number;
  elapsedDuration: number;
  overdueDuration: number;
  inCriticalZone: boolean;
  isPaused: boolean;
}

// === VUL Ticket Types ===

export interface VulTicket {
  key: string;
  summary: string;
  description: string;
  severity: string;
  status: string;
  squad: string | null;
  assignee: string | null;
  created: string;
  source: 'ghas' | 'wiz' | 'unknown';
  sla: SLAStatus | null;
  findings: VulnerabilityFinding[];
}

export interface SLAStatus {
  status: 'breached' | 'approaching' | 'within' | 'unknown';
  daysRemaining: number | null;
  daysOverdue: number | null;
  deadline: string | null;
}

export interface VulnerabilityFinding {
  cve: string;
  packageName: string;
  description: string;
  severity: string;
  affectedVersion: string;
  fixedVersion: string;
  locationPath: string;
  detectionMethod: string;
  firstDetected: string;
  lastDetected: string;
}

// === Analysis Types ===

export interface TeamSummary {
  squad: string;
  openCount: number;
  bySeverity: Record<string, number>;
  slaHealth: {
    breached: number;
    breachedClosed: number;
    approaching: number;
    within: number;
  };
  sources: {
    ghas: number;
    wiz: number;
  };
  trend7d: {
    new: number;
    resolved: number;
    net: number;
  };
}

export interface RemediationGroup {
  fix: string;
  cve: string;
  packageName: string;
  fixedVersion: string;
  ticketsResolved: number;
  ticketsJql: string;
  pdeWideTickets?: number;
  pdeWideJql?: string;
  reposAffected: string[];
  severity: string;
}

export interface RemediationPlan {
  squad: string;
  highLeverageFixes: RemediationGroup[];
  standaloneFixes: {
    key: string;
    summary: string;
    fix: string;
  }[];
}

// === Risk Exception Types ===

export interface RiskExceptionDraft {
  summary: string;
  riskLevel: string;
  riskDescription: string;
  riskExposure: string;
  mitigationMeasures: string;
  targetPlan: string;
  disclaimer: string;
}

// === Enrichment Types ===

export interface CVEEnrichment {
  cveId: string;
  description: string;
  cvssScore: number;
  cvssSeverity: string;
  epssProbability: number;
  epssClassification: string;
  inCisaKev: boolean;
  attackVector: string;
  attackComplexity: string;
  privilegesRequired: string;
  userInteraction: string;
}

export interface EnrichmentData {
  resourceName: string;
  totalCves: number;
  cisaKevCount: number;
  highEpssCount: number;
  criticalCvssCount: number;
  cves: CVEEnrichment[];
}

export interface CriticalityScore {
  totalScore: number;
  criticalityRating: number;
  hasInternetExposure: boolean;
  hasWideInternetExposure: boolean;
  hasCrossSubscriptionAccess: boolean;
  hasCrossVnetAccess: boolean;
  hasVpnAccess: boolean;
  hasHighPrivileges: boolean;
  hasAdminPrivileges: boolean;
  hasSensitiveDataAccess: boolean;
  hasHighK8sPrivileges: boolean;
  hasAdminK8sPrivileges: boolean;
}
