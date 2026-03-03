// src/tools/risk-exception.ts

import type { JiraClient } from '../clients/jira.js';
import type { RiskExceptionDraft, EnrichmentData, CriticalityScore } from '../types/index.js';
import { parseEnrichmentMd } from '../parsers/enrichment.js';
import { parseCriticalityCSV } from '../parsers/criticality.js';
import { parseWizCSV } from '../parsers/wiz-csv.js';
import { parseGHASCSV } from '../parsers/ghas-csv.js';

export async function draftRiskException(
  jira: JiraClient,
  ticketKey: string
): Promise<RiskExceptionDraft> {
  const issue = await jira.getIssue(ticketKey);
  const description = jira.extractTextFromADF(issue.fields.description);

  // Parse attachments
  let enrichment: EnrichmentData | null = null;
  let criticality: CriticalityScore | null = null;
  let findingsCount = 0;

  for (const att of issue.fields.attachment) {
    try {
      const content = await jira.getAttachmentContent(att.content);

      if (att.filename.endsWith('_enrichment.md')) {
        enrichment = parseEnrichmentMd(content);
      } else if (att.filename.startsWith('criticality') && att.filename.endsWith('.csv')) {
        criticality = parseCriticalityCSV(content);
      } else if (att.filename.endsWith('.csv')) {
        const findings = content.includes('package_name')
          ? parseGHASCSV(content)
          : parseWizCSV(content);
        findingsCount += findings.length;
      }
    } catch (e) {
      console.error(`Failed to parse ${att.filename}:`, e);
    }
  }

  // Build context for risk assessment
  const componentName = extractComponentName(issue.fields.summary);
  const priority = issue.fields.customfield_12500?.value || 'Unknown';
  const isHighSeverity = ['Highest', 'High', 'Critical'].includes(priority);

  // Generate draft content
  const summary = `Risk Exception for ${componentName} ${priority} vulnerability findings`;

  const riskLevel = determineRiskLevel(priority, enrichment, criticality);

  const riskDescription = generateRiskDescription(
    componentName,
    priority,
    enrichment,
    findingsCount
  );

  const riskExposure = generateRiskExposure(criticality, enrichment);

  const mitigationMeasures = generateMitigationMeasures(criticality, isHighSeverity);

  const targetPlan = generateTargetPlan(priority, componentName);

  return {
    summary,
    riskLevel,
    riskDescription,
    riskExposure,
    mitigationMeasures,
    targetPlan,
    disclaimer: 'AI-generated content - please review for accuracy before submitting',
  };
}

function extractComponentName(summary: string): string {
  // Try to extract component from summary
  if (summary.includes('Serverless Function')) {
    const match = summary.match(/Serverless Function ([^\s]+)/);
    return match ? match[1] : 'Unknown Component';
  }
  const parts = summary.split(' - ');
  return parts.length > 1 ? parts[parts.length - 1] : 'Unknown Component';
}

function determineRiskLevel(
  priority: string,
  enrichment: EnrichmentData | null,
  criticality: CriticalityScore | null
): string {
  if (enrichment?.cisaKevCount && enrichment.cisaKevCount > 0) return 'critical';
  if (priority === 'Highest' || priority === 'Critical') return 'critical';
  if (priority === 'High') return 'high';
  if (criticality && criticality.hasInternetExposure && criticality.hasHighPrivileges) return 'high';
  if (priority === 'Medium') return 'medium';
  return 'low';
}

function generateRiskDescription(
  componentName: string,
  priority: string,
  enrichment: EnrichmentData | null,
  findingsCount: number
): string {
  const parts: string[] = [];

  parts.push(`${componentName} has ${findingsCount || 'multiple'} vulnerability findings rated ${priority} priority.`);

  if (enrichment) {
    if (enrichment.cisaKevCount > 0) {
      parts.push(`WARNING: ${enrichment.cisaKevCount} CVE(s) are listed in CISA's Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild.`);
    }
    if (enrichment.criticalCvssCount > 0) {
      parts.push(`${enrichment.criticalCvssCount} vulnerabilities have Critical CVSS scores (9.0+).`);
    }
    if (enrichment.highEpssCount > 0) {
      parts.push(`${enrichment.highEpssCount} vulnerabilities have high EPSS probability (≥10%), indicating elevated exploitation likelihood.`);
    }
  }

  parts.push('Without remediation, these vulnerabilities could allow unauthorized access, data exfiltration, or service disruption.');

  return parts.join(' ');
}

function generateRiskExposure(
  criticality: CriticalityScore | null,
  enrichment: EnrichmentData | null
): string {
  const parts: string[] = [];

  if (criticality) {
    if (criticality.hasInternetExposure) {
      parts.push('The affected resource is exposed to the internet, increasing attack surface.');
    }
    if (criticality.hasHighPrivileges || criticality.hasAdminPrivileges) {
      parts.push('The resource has elevated privileges that could be leveraged for lateral movement.');
    }
    if (criticality.hasSensitiveDataAccess) {
      parts.push('The resource has access to sensitive data, increasing potential impact.');
    }
  }

  if (enrichment?.cves.length) {
    const networkCves = enrichment.cves.filter(c => c.attackVector === 'NETWORK');
    if (networkCves.length > 0) {
      parts.push(`${networkCves.length} vulnerabilities are exploitable over the network without physical access.`);
    }
  }

  if (parts.length === 0) {
    parts.push('Standard attack surface with network-accessible services.');
  }

  return parts.join(' ');
}

function generateMitigationMeasures(
  criticality: CriticalityScore | null,
  isHighSeverity: boolean
): string {
  const measures: string[] = [];

  measures.push('**Network Segmentation:** The affected system will be placed on a restricted network segment with enhanced firewall rules limiting inbound connections to authorized sources only.');

  if (isHighSeverity) {
    measures.push('**Enhanced Monitoring:** Additional logging and alerting will be enabled to detect exploitation attempts, with alerts routed to the security team.');
  }

  measures.push('**Access Restrictions:** Access to the affected resource will be limited to essential personnel only during the exception period.');

  if (criticality?.hasInternetExposure) {
    measures.push('**WAF Rules:** Web Application Firewall rules will be configured to block known exploitation patterns for the identified CVEs.');
  }

  return measures.join('\n\n');
}

function generateTargetPlan(priority: string, componentName: string): string {
  let timeline = '90 days';
  if (priority === 'Highest' || priority === 'Critical') {
    timeline = '30 days';
  } else if (priority === 'High') {
    timeline = '60 days';
  }

  return `**Remediation Approach:** Update vulnerable dependencies and apply security patches to ${componentName}.

**Timeline:** Target remediation within ${timeline} of exception approval.

**Tracking:** Work will be tracked via linked Jira epic with regular progress updates.

**Responsible Team:** The squad assigned to this VUL ticket will own remediation.`;
}
