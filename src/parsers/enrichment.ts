// src/parsers/enrichment.ts

import type { EnrichmentData, CVEEnrichment } from '../types/index.js';

export function parseEnrichmentMd(content: string): EnrichmentData {
  // Extract resource name
  const resourceMatch = content.match(/# CVE Enrichment Report: (.+)/);
  const resourceName = resourceMatch ? resourceMatch[1].trim() : 'Unknown';

  // Extract totals
  const totalMatch = content.match(/\*\*Total CVEs:\*\* (\d+)/);
  const totalCves = totalMatch ? parseInt(totalMatch[1], 10) : 0;

  const kevMatch = content.match(/In CISA KEV.*\| (\d+)/);
  const cisaKevCount = kevMatch ? parseInt(kevMatch[1], 10) : 0;

  const epssMatch = content.match(/High EPSS.*\| (\d+)/);
  const highEpssCount = epssMatch ? parseInt(epssMatch[1], 10) : 0;

  const cvssMatch = content.match(/Critical CVSS.*\| (\d+)/);
  const criticalCvssCount = cvssMatch ? parseInt(cvssMatch[1], 10) : 0;

  // Parse individual CVE sections
  const cves: CVEEnrichment[] = [];
  const cveSections = content.split(/### \d+\. (CVE-\d{4}-\d+)/);

  for (let i = 1; i < cveSections.length; i += 2) {
    if (i + 1 >= cveSections.length) break;

    const cveId = cveSections[i];
    const section = cveSections[i + 1];

    const descMatch = section.match(/\*\*Description:\*\* (.+?)(?:\n\n|\n\|)/s);
    const cvssScoreMatch = section.match(/CVSS Score \| \*\*([0-9.]+)\*\* \((\w+)\)/);
    const epssMatchInner = section.match(/EPSS Probability \| \*\*([0-9.]+)%\*\*/);
    const epssClassMatch = section.match(/EPSS Classification \| (\w+)/);
    const kevMatchInner = section.match(/In CISA KEV \| (\w+)/);
    const vectorMatch = section.match(/Attack Vector: (\w+)/);
    const complexityMatch = section.match(/Attack Complexity: (\w+)/);
    const privsMatch = section.match(/Privileges Required: (\w+)/);
    const interactionMatch = section.match(/User Interaction: (\w+)/);

    cves.push({
      cveId,
      description: descMatch ? descMatch[1].trim() : '',
      cvssScore: cvssScoreMatch ? parseFloat(cvssScoreMatch[1]) : 0,
      cvssSeverity: cvssScoreMatch ? cvssScoreMatch[2] : 'UNKNOWN',
      epssProbability: epssMatchInner ? parseFloat(epssMatchInner[1]) : 0,
      epssClassification: epssClassMatch ? epssClassMatch[1] : 'UNKNOWN',
      inCisaKev: kevMatchInner ? kevMatchInner[1].toLowerCase() === 'yes' : false,
      attackVector: vectorMatch ? vectorMatch[1] : 'UNKNOWN',
      attackComplexity: complexityMatch ? complexityMatch[1] : 'UNKNOWN',
      privilegesRequired: privsMatch ? privsMatch[1] : 'UNKNOWN',
      userInteraction: interactionMatch ? interactionMatch[1] : 'UNKNOWN',
    });
  }

  return {
    resourceName,
    totalCves,
    cisaKevCount,
    highEpssCount,
    criticalCvssCount,
    cves,
  };
}
