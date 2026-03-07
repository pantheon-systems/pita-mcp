// src/parsers/criticality.ts

import type { CriticalityScore } from '../types/index.js';

export function parseCriticalityCSV(content: string): CriticalityScore {
  const lines = content.split('\n');

  const flags: Record<string, boolean> = {
    hasInternetExposure: false,
    hasWideInternetExposure: false,
    isAccessibleFromOtherSubscriptions: false,
    isAccessibleFromOtherVnets: false,
    isAccessibleFromVPN: false,
    hasHighPrivileges: false,
    hasAdminPrivileges: false,
    hasAccessToSensitiveData: false,
    hasHighKubernetesPrivileges: false,
    hasAdminKubernetesPrivileges: false,
  };

  let totalScore = 0;
  let criticalityRating = 0;

  for (const line of lines) {
    const cols = line.split(',').map(c => c.trim());
    if (cols.length < 3) continue;

    const flag = cols[0];
    const detected = cols[1]?.toLowerCase() === 'yes';
    const desc = cols[2] || '';

    if (flag in flags) {
      (flags as Record<string, boolean>)[flag] = detected;
    }

    if (desc.includes('Total Raw Score')) {
      totalScore = parseFloat(cols[1]) || 0;
    } else if (desc.includes('Criticality Score')) {
      criticalityRating = parseFloat(cols[1]) || 0;
    }
  }

  return {
    totalScore,
    criticalityRating,
    hasInternetExposure: flags.hasInternetExposure,
    hasWideInternetExposure: flags.hasWideInternetExposure,
    hasCrossSubscriptionAccess: flags.isAccessibleFromOtherSubscriptions,
    hasCrossVnetAccess: flags.isAccessibleFromOtherVnets,
    hasVpnAccess: flags.isAccessibleFromVPN,
    hasHighPrivileges: flags.hasHighPrivileges,
    hasAdminPrivileges: flags.hasAdminPrivileges,
    hasSensitiveDataAccess: flags.hasAccessToSensitiveData,
    hasHighK8sPrivileges: flags.hasHighKubernetesPrivileges,
    hasAdminK8sPrivileges: flags.hasAdminKubernetesPrivileges,
  };
}
