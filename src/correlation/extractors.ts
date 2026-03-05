// src/correlation/extractors.ts

import type { TicketSource, ImageType } from './types.js';

/**
 * Extract repo name from a GHAS ticket summary.
 * Format: "GHAS YYYY-MM-DD - <repo-name>"
 */
export function extractRepo(summary: string): string | null {
  const match = summary.match(/^GHAS\s+[\d-]+\s+-\s+(.+)/i);
  return match ? match[1].trim() : null;
}

/**
 * Extract image/service name from a Wiz image scan ticket summary.
 * Format: "Wiz YYYY-MM-DD - Container Image : <image-name>@<hash>"
 */
export function extractImage(summary: string): string | null {
  const match = summary.match(/Container Image\s*:\s*(\S+?)@/i);
  return match ? match[1].trim() : null;
}

/**
 * Extract cluster names from a Wiz ticket description.
 * Looks for cluster paths like ".../clusters/<name>/..." and
 * kubernetes_clusterName fields.
 */
export function extractClusters(description: string): string[] {
  const clusters = new Set<string>();

  // Match cluster paths: .../clusters/<cluster-name>/...
  const pathMatches = description.matchAll(/\/clusters\/([^/\s]+)/g);
  for (const m of pathMatches) {
    clusters.add(m[1]);
  }

  // Match kubernetes_clusterName: <name>
  const nameMatch = description.match(/kubernetes_clusterName[:\s]+["']?(\S+?)["']?(?:\s|$)/i);
  if (nameMatch) {
    clusters.add(nameMatch[1]);
  }

  return Array.from(clusters);
}

/**
 * Extract the full image registry URL from a Wiz ticket description.
 * Looks for patterns like "us-docker.pkg.dev/..." or "ghcr.io/..."
 */
export function extractRegistryUrl(description: string): string | null {
  // Match common container registry URL patterns
  const match = description.match(
    /((?:us-docker\.pkg\.dev|gcr\.io|ghcr\.io|docker\.io)\/[^\s,)]+)/i
  );
  return match ? match[1] : null;
}

/**
 * Classify an image as Pantheon-built or third-party based on registry URL.
 */
export function classifyImageType(imageRef: string | null): ImageType | null {
  if (!imageRef) return null;
  const lower = imageRef.toLowerCase();

  if (lower.includes('pantheon-artifacts') || lower.includes('pantheon-internal') ||
      lower.includes('pantheon-dmz') || lower.includes('pantheon-')) {
    if (lower.startsWith('us-docker.pkg.dev/') || lower.startsWith('gcr.io/')) {
      return 'pantheon-built';
    }
  }

  if (lower.startsWith('ghcr.io/')) return 'third-party';
  if (lower.startsWith('docker.io/')) return 'third-party';

  return null;
}

/**
 * Classify ticket source from summary text.
 */
export function classifyTicketSource(summary: string): TicketSource {
  const lower = summary.toLowerCase();
  if (lower.includes('ghas') || lower.includes('dependabot')) return 'ghas';
  if (lower.startsWith('wiz issue')) return 'wiz-issue';
  if (lower.startsWith('wiz ')) return 'wiz';
  return 'wiz'; // default for unrecognized Wiz formats
}
