// src/clients/tts.ts

import type { TTSSLAResponse, SLAStatus } from '../types/index.js';

export interface TTSClientConfig {
  apiUrl: string;
  apiToken: string;
}

export class TTSClient {
  private apiUrl: string;
  private apiToken: string;

  constructor(config: TTSClientConfig) {
    this.apiUrl = config.apiUrl.replace(/\/$/, '');
    this.apiToken = config.apiToken;
  }

  static fromEnv(): TTSClient {
    const apiUrl = process.env.TTS_API_URL || 'https://tts.snapbytesapps.com/api';
    const apiToken = process.env.TTS_API_TOKEN;

    if (!apiToken) {
      throw new Error('Missing required environment variable: TTS_API_TOKEN');
    }

    return new TTSClient({ apiUrl, apiToken });
  }

  async getIssueSLA(issueKey: string): Promise<TTSSLAResponse | null> {
    try {
      const response = await fetch(`${this.apiUrl}/issue-sla/${issueKey}`, {
        headers: {
          'Authorization': `Bearer ${this.apiToken}`,
        },
      });

      if (!response.ok) {
        console.error(`TTS API error for ${issueKey}: ${response.status}`);
        return null;
      }

      const data = await response.json() as TTSSLAResponse[];
      return data[0] || null;
    } catch (error) {
      console.error(`TTS API error for ${issueKey}:`, error);
      return null;
    }
  }

  async getIssueSLABatch(issueKeys: string[], concurrency = 10): Promise<Map<string, TTSSLAResponse | null>> {
    const results = new Map<string, TTSSLAResponse | null>();

    // Process in batches
    for (let i = 0; i < issueKeys.length; i += concurrency) {
      const batch = issueKeys.slice(i, i + concurrency);
      const promises = batch.map(async (key) => {
        const sla = await this.getIssueSLA(key);
        results.set(key, sla);
      });
      await Promise.all(promises);
    }

    return results;
  }

  parseSLAStatus(ttsResponse: TTSSLAResponse | null): SLAStatus {
    if (!ttsResponse) {
      return {
        status: 'unknown',
        daysRemaining: null,
        daysOverdue: null,
        deadline: null,
      };
    }

    const msPerDay = 86400000;

    if (ttsResponse.slaStatus === 'EXCEED') {
      return {
        status: 'breached',
        daysRemaining: null,
        daysOverdue: Math.floor(ttsResponse.overdueDuration / msPerDay),
        deadline: ttsResponse.deadline ? new Date(ttsResponse.deadline).toISOString().split('T')[0] : null,
      };
    }

    const daysRemaining = Math.floor(ttsResponse.remainingDuration / msPerDay);

    if (ttsResponse.inCriticalZone) {
      return {
        status: 'approaching',
        daysRemaining,
        daysOverdue: null,
        deadline: ttsResponse.deadline ? new Date(ttsResponse.deadline).toISOString().split('T')[0] : null,
      };
    }

    return {
      status: 'within',
      daysRemaining,
      daysOverdue: null,
      deadline: ttsResponse.deadline ? new Date(ttsResponse.deadline).toISOString().split('T')[0] : null,
    };
  }
}
