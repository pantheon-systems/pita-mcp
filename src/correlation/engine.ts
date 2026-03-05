// src/correlation/engine.ts

import type { JiraClient } from '../clients/jira.js';
import type { TTSClient } from '../clients/tts.js';
import type { JiraIssue, VulnerabilityFinding } from '../types/index.js';
import type { EnrichedTicket, CrossReference, CorrelationResult } from './types.js';
import {
  extractRepo,
  extractImage,
  extractClusters,
  extractRegistryUrl,
  classifyImageType,
  classifyTicketSource,
} from './extractors.js';
import { parseWizCSV } from '../parsers/wiz-csv.js';
import { parseGHASCSV } from '../parsers/ghas-csv.js';
import { parseGHASDescription } from '../parsers/ghas.js';
import { SUMMARY_FIELDS } from '../clients/jira.js';

const AUDIT_FILTER_ID = '26914';

/**
 * Build correlation from a squad's tickets.
 * Tier 1: fetch all tickets for the squad with full detail.
 * Tier 2: cross-reference CVEs found in those tickets against other squads.
 */
export async function buildFromSquad(
  jira: JiraClient,
  tts: TTSClient,
  squad: string | undefined,
  scope: string,
): Promise<CorrelationResult> {
  const base = scope === 'audit' ? `filter = ${AUDIT_FILTER_ID}` : 'project = VUL';
  const squadClause = squad ? ` AND "Squad" = "${squad}"` : '';
  const jql = `${base}${squadClause} AND status NOT IN (Done, Closed)`;

  const response = await jira.searchIssues(jql, Infinity);
  const primaryTickets = await enrichTickets(jira, tts, response.issues);

  // Tier 2: cross-reference
  const crossReferences = squad
    ? await crossReference(jira, tts, primaryTickets, squad, base)
    : [];

  return { primaryTickets, crossReferences };
}

/**
 * Build correlation from a specific CVE.
 * Searches broadly — no Tier 2 needed.
 */
export async function buildFromCVE(
  jira: JiraClient,
  tts: TTSClient,
  cve: string,
  scope: string,
): Promise<CorrelationResult> {
  const base = scope === 'audit' ? `filter = ${AUDIT_FILTER_ID}` : 'project = VUL';
  const jql = `${base} AND text ~ "${cve}"`;

  const response = await jira.searchIssues(jql, Infinity);
  const primaryTickets = await enrichTickets(jira, tts, response.issues);

  return { primaryTickets, crossReferences: [] };
}

/**
 * Build correlation from a package name.
 * Searches broadly — no Tier 2 needed.
 */
export async function buildFromPackage(
  jira: JiraClient,
  tts: TTSClient,
  packageName: string,
  scope: string,
): Promise<CorrelationResult> {
  const base = scope === 'audit' ? `filter = ${AUDIT_FILTER_ID}` : 'project = VUL';
  const jql = `${base} AND text ~ "${packageName}"`;

  const response = await jira.searchIssues(jql, Infinity);
  const primaryTickets = await enrichTickets(jira, tts, response.issues);

  return { primaryTickets, crossReferences: [] };
}

/**
 * Build correlation from a single ticket.
 * Tier 1: fetch the ticket.
 * Tier 2: cross-reference its CVEs against all other tickets.
 */
export async function buildFromTicket(
  jira: JiraClient,
  tts: TTSClient,
  ticketKey: string,
  scope: string,
): Promise<CorrelationResult> {
  const issue = await jira.getIssue(ticketKey);
  const primaryTickets = await enrichTickets(jira, tts, [issue]);

  // Extract CVEs for cross-reference
  const cves = new Set<string>();
  for (const ticket of primaryTickets) {
    for (const finding of ticket.findings) {
      if (finding.cve && finding.cve.startsWith('CVE-')) {
        cves.add(finding.cve);
      }
    }
  }

  let crossReferences: CrossReference[] = [];
  if (cves.size > 0) {
    const base = scope === 'audit' ? `filter = ${AUDIT_FILTER_ID}` : 'project = VUL';
    const cveQuery = Array.from(cves).map(c => `"${c}"`).join(' OR text ~ ');
    const jql = `${base} AND (text ~ ${cveQuery}) AND key != "${ticketKey}"`;

    const response = await jira.searchIssues(jql, 100, SUMMARY_FIELDS);
    // For Tier 2, we do a lighter enrichment — no CSV parsing unless needed
    const relatedTickets = await enrichTicketsLight(jira, response.issues, cves);
    crossReferences = correlateFindings(primaryTickets, relatedTickets);
  }

  return { primaryTickets, crossReferences };
}

/**
 * Core correlation logic: match primary tickets against related tickets
 * by shared CVEs. Exported for testing.
 */
export function correlateFindings(
  primary: EnrichedTicket[],
  related: EnrichedTicket[],
): CrossReference[] {
  const crossRefs: CrossReference[] = [];

  for (const pTicket of primary) {
    const pCVEs = new Set(pTicket.findings.map(f => f.cve).filter(c => c && c.startsWith('CVE-')));
    const pPackages = new Set(pTicket.findings.map(f => f.packageName).filter(Boolean));

    for (const rTicket of related) {
      if (rTicket.key === pTicket.key) continue; // no self-references

      const rCVEs = new Set(rTicket.findings.map(f => f.cve).filter(c => c && c.startsWith('CVE-')));

      const sharedCVEs = Array.from(pCVEs).filter(c => rCVEs.has(c));
      if (sharedCVEs.length === 0) continue;

      const rPackages = new Set(rTicket.findings.map(f => f.packageName).filter(Boolean));
      const sharedPackages = Array.from(pPackages).filter(p => rPackages.has(p));

      // Determine relationship
      const isSameArtifact = determineSameArtifact(pTicket, rTicket);
      const relationship = isSameArtifact ? 'same_artifact' : 'shared_cve';

      const note = isSameArtifact
        ? 'Wiz runtime finding for the same service — fixing and redeploying resolves both'
        : 'Same vulnerability found independently — each requires its own fix';

      crossRefs.push({
        primaryTicketKey: pTicket.key,
        relatedTicketKey: rTicket.key,
        relationship,
        sharedCVEs,
        sharedPackages,
        relatedSource: rTicket.source,
        relatedRepo: rTicket.repo,
        relatedImage: rTicket.image,
        relatedImageType: rTicket.imageType,
        relatedSquad: rTicket.squad,
        note,
      });
    }
  }

  return crossRefs;
}

/**
 * Determine if two tickets represent the same artifact scanned
 * at different layers (GHAS = source, Wiz = runtime).
 */
function determineSameArtifact(a: EnrichedTicket, b: EnrichedTicket): boolean {
  // Must be different sources (one GHAS, one Wiz)
  const sources = new Set([a.source, b.source]);
  if (!sources.has('ghas') || !sources.has('wiz')) return false;

  // Match repo name to image name
  const ghas = a.source === 'ghas' ? a : b;
  const wiz = a.source === 'wiz' ? a : b;

  if (!ghas.repo || !wiz.image) return false;

  // Check if repo name matches image name (e.g., "styx" === "styx")
  return ghas.repo.toLowerCase() === wiz.image.toLowerCase();
}

/**
 * Enrich Jira issues into EnrichedTickets with full finding parsing.
 */
async function enrichTickets(
  jira: JiraClient,
  tts: TTSClient,
  issues: JiraIssue[],
): Promise<EnrichedTicket[]> {
  const tickets: EnrichedTicket[] = [];

  for (const issue of issues) {
    const summary = issue.fields.summary;
    const description = jira.extractTextFromADF(issue.fields.description);
    const source = classifyTicketSource(summary);

    // Parse findings from CSV attachments
    let findings: VulnerabilityFinding[] = [];
    const csvAttachments = issue.fields.attachment.filter(
      a => a.filename.endsWith('.csv') && !a.filename.includes('criticality')
    );

    for (const csvAttachment of csvAttachments) {
      try {
        const csvContent = await jira.getAttachmentContent(csvAttachment.content);
        const parsed = csvContent.includes('package_name')
          ? parseGHASCSV(csvContent)
          : parseWizCSV(csvContent);
        findings.push(...parsed);
      } catch (e) {
        console.error(`Failed to parse CSV for ${issue.key}:`, e);
      }
    }

    // Fall back to description parsing for GHAS
    if (findings.length === 0 && source === 'ghas') {
      findings = parseGHASDescription(description);
    }

    // Extract mapping data
    const repo = extractRepo(summary);
    const image = extractImage(summary);
    const registryUrl = extractRegistryUrl(description) || (image ? summary : null);
    const imageType = classifyImageType(registryUrl);
    const clusters = extractClusters(description);

    // Get SLA
    let sla = null;
    try {
      const slaResponse = await tts.getIssueSLA(issue.key);
      sla = tts.parseSLAStatus(slaResponse);
    } catch {
      // SLA lookup failure is non-fatal
    }

    tickets.push({
      key: issue.key,
      summary,
      source,
      repo,
      image,
      imageType,
      clusters,
      squad: issue.fields.customfield_12050?.value ?? null,
      severity: issue.fields.customfield_12500?.value ?? 'Unknown',
      status: issue.fields.status.name,
      sla,
      findings,
    });
  }

  return tickets;
}

/**
 * Light enrichment for Tier 2 cross-reference results.
 * No CSV parsing — uses summary/description extraction only.
 * Matches CVEs from description text against the provided set.
 */
async function enrichTicketsLight(
  jira: JiraClient,
  issues: JiraIssue[],
  targetCVEs: Set<string>,
): Promise<EnrichedTicket[]> {
  const tickets: EnrichedTicket[] = [];

  for (const issue of issues) {
    const summary = issue.fields.summary;
    const description = jira.extractTextFromADF(issue.fields.description);
    const source = classifyTicketSource(summary);

    // Extract CVEs from description text (no CSV parsing)
    const cvePattern = /CVE-\d{4}-\d+/g;
    const allCves = description.match(cvePattern) || [];
    const matchedCves = allCves.filter(c => targetCVEs.has(c));

    const findings: VulnerabilityFinding[] = matchedCves.map(cve => ({
      cve,
      packageName: '',
      description: '',
      severity: '',
      affectedVersion: '',
      fixedVersion: '',
      locationPath: '',
      detectionMethod: source === 'ghas' ? 'GHAS' : 'Wiz',
      firstDetected: '',
      lastDetected: '',
    }));

    tickets.push({
      key: issue.key,
      summary,
      source,
      repo: extractRepo(summary),
      image: extractImage(summary),
      imageType: classifyImageType(extractRegistryUrl(description)),
      clusters: extractClusters(description),
      squad: issue.fields.customfield_12050?.value ?? null,
      severity: issue.fields.customfield_12500?.value ?? 'Unknown',
      status: issue.fields.status.name,
      sla: null,
      findings,
    });
  }

  return tickets;
}

/**
 * Tier 2 cross-reference: find tickets sharing CVEs with the primary set.
 */
async function crossReference(
  jira: JiraClient,
  tts: TTSClient,
  primaryTickets: EnrichedTicket[],
  squad: string,
  base: string,
): Promise<CrossReference[]> {
  // Collect unique CVEs from primary tickets
  const cves = new Set<string>();
  for (const ticket of primaryTickets) {
    for (const finding of ticket.findings) {
      if (finding.cve && finding.cve.startsWith('CVE-')) {
        cves.add(finding.cve);
      }
    }
  }

  if (cves.size === 0) return [];

  // Query for these CVEs outside the squad
  const cveQuery = Array.from(cves).map(c => `text ~ "${c}"`).join(' OR ');
  const jql = `${base} AND "Squad" != "${squad}" AND status NOT IN (Done, Closed) AND (${cveQuery})`;

  try {
    const response = await jira.searchIssues(jql, 100, SUMMARY_FIELDS);
    const relatedTickets = await enrichTicketsLight(jira, response.issues, cves);
    return correlateFindings(primaryTickets, relatedTickets);
  } catch (e) {
    console.error('Cross-reference query failed:', e);
    return [];
  }
}
