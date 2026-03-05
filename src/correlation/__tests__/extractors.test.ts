import { describe, it, expect } from 'vitest';
import {
  extractRepo,
  extractImage,
  extractClusters,
  classifyImageType,
  classifyTicketSource,
} from '../extractors.js';

describe('extractRepo', () => {
  it('extracts repo from GHAS summary', () => {
    expect(extractRepo('GHAS 2026-03-03 - pantheon-ref')).toBe('pantheon-ref');
  });

  it('extracts repo from GHAS summary with spaces', () => {
    expect(extractRepo('GHAS 2026-03-03 - api-booklib')).toBe('api-booklib');
  });

  it('returns null for Wiz summaries', () => {
    expect(extractRepo('Wiz 2026-03-03 - Container Image : styx@731ca9fd')).toBeNull();
  });

  it('returns null for Wiz Issue summaries', () => {
    expect(extractRepo('Wiz Issue: Internet-facing container with high Kubernetes privileges')).toBeNull();
  });
});

describe('extractImage', () => {
  it('extracts image name from Wiz image scan summary', () => {
    expect(extractImage('Wiz 2026-03-03 - Container Image : styx@731ca9fd')).toBe('styx');
  });

  it('extracts image name from Wiz summary with long hash', () => {
    expect(extractImage('Wiz 2026-03-03 - Container Image : gha-runner-scale-set-controller@4b98af13')).toBe('gha-runner-scale-set-controller');
  });

  it('returns null for GHAS summaries', () => {
    expect(extractImage('GHAS 2026-03-03 - pantheon-ref')).toBeNull();
  });

  it('returns null for Wiz Issue summaries', () => {
    expect(extractImage('Wiz Issue: Publicly exposed container')).toBeNull();
  });
});

describe('extractClusters', () => {
  it('extracts cluster paths from Wiz image scan description', () => {
    const desc = `This image is hosted at: ghcr.io/actions/gha-runner-scale-set-controller
Wiz indicates that this container is in use in the following clusters:
cicd-pantheon-internal/locations/us-central1/clusters/cicd-internal-01/pod/pan-arc/int-pan-tf-1-10-86bc86bf-listener
cicd-pantheon-dmz/locations/us-central1/clusters/cicd-dmz-01/pod/pan-arc/dmz-pan-node-20-76c9cbd6-listener`;
    const clusters = extractClusters(desc);
    expect(clusters).toContain('cicd-internal-01');
    expect(clusters).toContain('cicd-dmz-01');
  });

  it('extracts cluster name from Wiz Issue description', () => {
    const desc = 'Resource:\tstyx-fe1fe2-h Type : Deployment Cloud Platform : Kubernetes kubernetes_clusterName: dmz-04';
    const clusters = extractClusters(desc);
    expect(clusters).toContain('dmz-04');
  });

  it('returns empty array when no clusters found', () => {
    expect(extractClusters('Some random description')).toEqual([]);
  });
});

describe('classifyImageType', () => {
  it('classifies Pantheon Artifact Registry images', () => {
    expect(classifyImageType('us-docker.pkg.dev/pantheon-artifacts/internal/styx@731ca9fd')).toBe('pantheon-built');
  });

  it('classifies GCR Pantheon images', () => {
    expect(classifyImageType('gcr.io/pantheon-internal/styx:latest')).toBe('pantheon-built');
  });

  it('classifies GitHub Container Registry images as third-party', () => {
    expect(classifyImageType('ghcr.io/actions/gha-runner-scale-set-controller@4b98af13')).toBe('third-party');
  });

  it('classifies Docker Hub images as third-party', () => {
    expect(classifyImageType('docker.io/library/nginx:latest')).toBe('third-party');
  });

  it('returns null for unknown registries', () => {
    expect(classifyImageType('styx@731ca9fd')).toBeNull();
  });

  it('returns null for null input', () => {
    expect(classifyImageType(null)).toBeNull();
  });
});

describe('classifyTicketSource', () => {
  it('identifies GHAS tickets', () => {
    expect(classifyTicketSource('GHAS 2026-03-03 - pantheon-ref')).toBe('ghas');
  });

  it('identifies Dependabot tickets as GHAS', () => {
    expect(classifyTicketSource('Dependabot alert: pantheon-ref')).toBe('ghas');
  });

  it('identifies Wiz Issue tickets', () => {
    expect(classifyTicketSource('Wiz Issue: Internet-facing container')).toBe('wiz-issue');
  });

  it('identifies Wiz image scan tickets', () => {
    expect(classifyTicketSource('Wiz 2026-03-03 - Container Image : styx@731ca9fd')).toBe('wiz');
  });
});
