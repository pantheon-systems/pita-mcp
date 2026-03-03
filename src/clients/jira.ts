// src/clients/jira.ts

import type {
  JiraIssue,
  JiraSearchResponse,
  JiraADF,
  JiraADFNode,
} from '../types/index.js';

export interface JiraClientConfig {
  baseUrl: string;
  email: string;
  apiToken: string;
}

// Default fields for full issue data
const ALL_FIELDS = [
  'summary',
  'description',
  'priority',
  'status',
  'assignee',
  'created',
  'updated',
  'labels',
  'attachment',
  'customfield_12050', // Squad
  'customfield_12500', // Severity
];

// Minimal fields for counting/aggregation queries
export const SUMMARY_FIELDS = [
  'summary',
  'status',
  'assignee',
  'created',
  'updated',
  'customfield_12050', // Squad
  'customfield_12500', // Severity
];

// Fields needed for SLA status (no description/attachment)
export const SLA_FIELDS = [
  'summary',
  'status',
  'assignee',
  'customfield_12050',
  'customfield_12500',
];

// Minimal fields for trend counting
export const TREND_FIELDS = [
  'created',
  'updated',
];

export class JiraClient {
  private baseUrl: string;
  private authHeader: string;

  constructor(config: JiraClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    const credentials = Buffer.from(`${config.email}:${config.apiToken}`).toString('base64');
    this.authHeader = `Basic ${credentials}`;
  }

  static fromEnv(): JiraClient {
    const baseUrl = process.env.ATLASSIAN_INSTANCE_URL;
    const email = process.env.ATLASSIAN_EMAIL;
    const apiToken = process.env.ATLASSIAN_API_TOKEN;

    if (!baseUrl || !email || !apiToken) {
      throw new Error(
        'Missing required environment variables: ATLASSIAN_INSTANCE_URL, ATLASSIAN_EMAIL, ATLASSIAN_API_TOKEN'
      );
    }

    return new JiraClient({ baseUrl, email, apiToken });
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`;

    // Retry with backoff on 429
    for (let attempt = 0; attempt < 3; attempt++) {
      const response = await fetch(url, {
        ...options,
        headers: {
          'Authorization': this.authHeader,
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });

      if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get('retry-after') || '', 10);
        const waitMs = (retryAfter || (attempt + 1) * 5) * 1000;
        console.error(`Rate limited, waiting ${waitMs / 1000}s (attempt ${attempt + 1}/3)`);
        await new Promise(resolve => setTimeout(resolve, waitMs));
        continue;
      }

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Jira API error: ${response.status} ${response.statusText} - ${text}`);
      }

      return response.json() as Promise<T>;
    }

    throw new Error('Jira API rate limit exceeded after 3 retries');
  }

  async searchIssues(jql: string, maxResults = 100, fields?: string[]): Promise<JiraSearchResponse> {
    const queryFields = fields || ALL_FIELDS;

    // Fetch pages using cursor-based pagination with large page size
    const allIssues: JiraIssue[] = [];
    let nextPageToken: string | undefined;
    const pageSize = Math.min(maxResults, 5000);

    do {
      const body: Record<string, unknown> = { jql, maxResults: pageSize, fields: queryFields };
      if (nextPageToken) {
        body.nextPageToken = nextPageToken;
      }

      const response = await this.request<JiraSearchResponse>('/rest/api/3/search/jql', {
        method: 'POST',
        body: JSON.stringify(body),
      });

      allIssues.push(...response.issues);
      nextPageToken = response.nextPageToken;

      // Stop if we've collected enough or reached the last page
      if (allIssues.length >= maxResults || response.isLast) {
        break;
      }
    } while (nextPageToken);

    return {
      issues: allIssues.slice(0, maxResults),
      total: allIssues.length,
      isLast: true,
    };
  }

  async getIssue(issueKey: string): Promise<JiraIssue> {
    const fields = ALL_FIELDS.join(',');
    return this.request<JiraIssue>(`/rest/api/3/issue/${issueKey}?fields=${fields}&expand=attachment`);
  }

  async getAttachmentContent(attachmentUrl: string): Promise<string> {
    const response = await fetch(attachmentUrl, {
      headers: {
        'Authorization': this.authHeader,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to download attachment: ${response.status}`);
    }

    return response.text();
  }

  extractTextFromADF(adf: JiraADF | null): string {
    if (!adf) return '';

    const texts: string[] = [];

    const walk = (node: JiraADFNode | JiraADF): void => {
      if ('text' in node && node.text) {
        texts.push(node.text);
      }
      if ('content' in node && node.content) {
        for (const child of node.content) {
          walk(child);
        }
      }
    };

    walk(adf);
    return texts.join(' ');
  }
}
