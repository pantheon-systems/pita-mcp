import { describe, it, expect } from 'vitest';
import { correlateFindings } from '../engine.js';
import type { EnrichedTicket } from '../types.js';

describe('correlateFindings', () => {
  it('finds shared_cve between GHAS and Wiz tickets with different repos/images', () => {
    const primary: EnrichedTicket[] = [
      {
        key: 'VUL-100',
        summary: 'GHAS 2026-03-03 - pantheon-ref',
        source: 'ghas',
        repo: 'pantheon-ref',
        image: null,
        imageType: null,
        clusters: [],
        squad: 'PIE',
        severity: 'High',
        status: 'Open',
        sla: null,
        findings: [{ cve: 'CVE-2026-1229', packageName: 'github.com/cloudflare/circl', description: '', severity: 'high', affectedVersion: '1.6.1', fixedVersion: '1.6.3', locationPath: '', detectionMethod: 'GHAS', firstDetected: '', lastDetected: '' }],
      },
    ];
    const related: EnrichedTicket[] = [
      {
        key: 'VUL-200',
        summary: 'Wiz 2026-03-03 - Container Image : gha-runner@abc123',
        source: 'wiz',
        repo: null,
        image: 'gha-runner',
        imageType: 'third-party',
        clusters: ['cicd-internal-01'],
        squad: 'Delivery Engineering',
        severity: 'Low',
        status: 'Open',
        sla: null,
        findings: [{ cve: 'CVE-2026-1229', packageName: 'github.com/cloudflare/circl', description: '', severity: 'LOW', affectedVersion: '1.6.1', fixedVersion: '1.6.3', locationPath: '/manager', detectionMethod: 'LIBRARY', firstDetected: '', lastDetected: '' }],
      },
    ];

    const xrefs = correlateFindings(primary, related);
    expect(xrefs).toHaveLength(1);
    expect(xrefs[0].relationship).toBe('shared_cve');
    expect(xrefs[0].primaryTicketKey).toBe('VUL-100');
    expect(xrefs[0].relatedTicketKey).toBe('VUL-200');
    expect(xrefs[0].sharedCVEs).toContain('CVE-2026-1229');
  });

  it('identifies same_artifact when GHAS repo matches Wiz image name', () => {
    const primary: EnrichedTicket[] = [
      {
        key: 'VUL-100',
        summary: 'GHAS 2026-03-03 - styx',
        source: 'ghas',
        repo: 'styx',
        image: null,
        imageType: null,
        clusters: [],
        squad: 'Edge Routing',
        severity: 'High',
        status: 'Open',
        sla: null,
        findings: [{ cve: 'CVE-2024-1019', packageName: 'ModSecurity', description: '', severity: 'high', affectedVersion: '3.0.9', fixedVersion: '3.0.12', locationPath: '', detectionMethod: 'GHAS', firstDetected: '', lastDetected: '' }],
      },
    ];
    const related: EnrichedTicket[] = [
      {
        key: 'VUL-200',
        summary: 'Wiz 2026-03-03 - Container Image : styx@731ca9fd',
        source: 'wiz',
        repo: null,
        image: 'styx',
        imageType: 'pantheon-built',
        clusters: ['dmz-04'],
        squad: 'Edge Routing',
        severity: 'Critical',
        status: 'Open',
        sla: null,
        findings: [{ cve: 'CVE-2024-1019', packageName: 'ModSecurity', description: '', severity: 'high', affectedVersion: '3.0.9', fixedVersion: '3.0.12', locationPath: '/usr/local/modsecurity/lib/libmodsecurity.so', detectionMethod: 'DetectionMethodFilePath', firstDetected: '', lastDetected: '' }],
      },
    ];

    const xrefs = correlateFindings(primary, related);
    expect(xrefs).toHaveLength(1);
    expect(xrefs[0].relationship).toBe('same_artifact');
    expect(xrefs[0].note).toContain('resolves both');
  });

  it('returns empty array when no CVEs overlap', () => {
    const primary: EnrichedTicket[] = [
      {
        key: 'VUL-100', summary: 'GHAS 2026-03-03 - foo', source: 'ghas',
        repo: 'foo', image: null, imageType: null, clusters: [],
        squad: 'PIE', severity: 'High', status: 'Open', sla: null,
        findings: [{ cve: 'CVE-2026-1111', packageName: 'pkg-a', description: '', severity: 'high', affectedVersion: '1.0', fixedVersion: '2.0', locationPath: '', detectionMethod: 'GHAS', firstDetected: '', lastDetected: '' }],
      },
    ];
    const related: EnrichedTicket[] = [
      {
        key: 'VUL-200', summary: 'Wiz 2026-03-03 - Container Image : bar@abc', source: 'wiz',
        repo: null, image: 'bar', imageType: 'pantheon-built', clusters: [],
        squad: 'PIE', severity: 'High', status: 'Open', sla: null,
        findings: [{ cve: 'CVE-2026-9999', packageName: 'pkg-b', description: '', severity: 'high', affectedVersion: '1.0', fixedVersion: '2.0', locationPath: '', detectionMethod: 'LIBRARY', firstDetected: '', lastDetected: '' }],
      },
    ];

    const xrefs = correlateFindings(primary, related);
    expect(xrefs).toHaveLength(0);
  });

  it('does not create self-references', () => {
    const ticket: EnrichedTicket = {
      key: 'VUL-100', summary: 'GHAS 2026-03-03 - foo', source: 'ghas',
      repo: 'foo', image: null, imageType: null, clusters: [],
      squad: 'PIE', severity: 'High', status: 'Open', sla: null,
      findings: [{ cve: 'CVE-2026-1111', packageName: 'pkg-a', description: '', severity: 'high', affectedVersion: '1.0', fixedVersion: '2.0', locationPath: '', detectionMethod: 'GHAS', firstDetected: '', lastDetected: '' }],
    };

    const xrefs = correlateFindings([ticket], [ticket]);
    expect(xrefs).toHaveLength(0);
  });
});
