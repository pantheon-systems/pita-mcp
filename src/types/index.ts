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

// === Repo-Centric Remediation Types ===

export interface RepoRemediationEntry {
  repo: string;
  ghasTickets: string[];
  wizTickets: string[];
  severity: string;
  slaUrgency: string | null;
  fixes: RepoFix[];
  crossSourceNotes: string[];
  ticketsJql: string;
}

export interface ThirdPartyImageEntry {
  image: string;
  registry: string;
  wizTickets: string[];
  severity: string;
  clusters: string[];
  fixes: RepoFix[];
  action: string;
  ticketsJql: string;
}

export interface UnattributedEntry {
  ticketKey: string;
  summary: string;
  resource: string | null;
  severity: string;
  source: string;
}

export interface RepoFix {
  packageName: string;
  fixedVersion: string;
  cve: string;
  resolvesGhas: boolean;
  resolvesWiz: boolean;
  note: string;
}

export interface RepoCentricRemediationPlan {
  squad: string;
  pantheonRepos: RepoRemediationEntry[];
  thirdPartyImages: ThirdPartyImageEntry[];
  unattributed: UnattributedEntry[];
}
