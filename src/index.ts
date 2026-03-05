// src/index.ts

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { JiraClient } from './clients/jira.js';
import { TTSClient } from './clients/tts.js';
import { getTeamSummary } from './tools/team-summary.js';
import { getSLAStatus } from './tools/sla-status.js';
import { getTicketDetails } from './tools/ticket-details.js';
import { getRemediationPlan } from './tools/remediation-plan.js';
import { getTrend } from './tools/trend.js';
import { draftRiskException } from './tools/risk-exception.js';
import { getBlastRadius } from './tools/blast-radius.js';

// Audit year filter (SOC2 audit year starting 12/1/2025)
const AUDIT_FILTER_ID = '26914';

// Scope parameter shared across squad-based tools
const SCOPE_PROPERTY = {
  scope: {
    type: 'string',
    description: 'Data scope: "audit" (current SOC2 audit year, default) or "all" (full history)',
  },
};

// Tool definitions
const TOOLS = [
  {
    name: 'pita_team_summary',
    description: "Get a squad's vulnerability dashboard including open counts, SLA health, and 7-day trend. Omit squad for PDE-wide view.",
    inputSchema: {
      type: 'object' as const,
      properties: {
        squad: {
          type: 'string',
          description: 'Squad name (e.g., "Data Platform", "Platform Infrastructure Engineering"). Omit for PDE-wide summary.',
        },
        ...SCOPE_PROPERTY,
      },
    },
  },
  {
    name: 'pita_sla_status',
    description: 'Get breached and approaching SLA tickets for a squad. Omit squad for PDE-wide view.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        squad: {
          type: 'string',
          description: 'Squad name. Omit for PDE-wide view.',
        },
        priority_filter: {
          type: 'string',
          description: 'Comma-separated severities to include (e.g., "highest,high"). Default: all',
        },
        ...SCOPE_PROPERTY,
      },
    },
  },
  {
    name: 'pita_ticket_details',
    description: 'Get detailed information for a single VUL ticket including parsed findings and cross-source related tickets',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ticket_key: {
          type: 'string',
          description: 'VUL ticket key (e.g., "VUL-3385")',
        },
        ...SCOPE_PROPERTY,
      },
      required: ['ticket_key'],
    },
  },
  {
    name: 'pita_trend',
    description: 'Get week-over-week vulnerability metrics for a squad. Omit squad for PDE-wide view.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        squad: {
          type: 'string',
          description: 'Squad name. Omit for PDE-wide view.',
        },
        period: {
          type: 'string',
          description: 'Time period (e.g., "7d", "30d"). Default: "30d"',
        },
        ...SCOPE_PROPERTY,
      },
    },
  },
  {
    name: 'pita_remediation_plan',
    description: 'Get repo-centric remediation plan with cross-source correlation. Groups fixes by Pantheon repo, third-party images, and unattributed findings. Omit squad for PDE-wide view.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        squad: {
          type: 'string',
          description: 'Squad name. Omit for PDE-wide view.',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of high-leverage fixes to return. Default: 10',
        },
        ...SCOPE_PROPERTY,
      },
    },
  },
  {
    name: 'pita_blast_radius',
    description: 'Show how widespread a CVE, package vulnerability, or ticket finding is across repos, images, and clusters. Entry point for understanding vulnerability spread.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ticket_key: {
          type: 'string',
          description: 'VUL ticket key to analyze (e.g., "VUL-3982"). Shows blast radius for all CVEs in this ticket.',
        },
        cve: {
          type: 'string',
          description: 'CVE identifier (e.g., "CVE-2026-1229"). Shows all tickets with this CVE.',
        },
        package: {
          type: 'string',
          description: 'Package name (e.g., "github.com/cloudflare/circl"). Shows all tickets with this package.',
        },
        ...SCOPE_PROPERTY,
      },
    },
  },
  {
    name: 'pita_draft_risk_exception',
    description: 'Generate an AI-drafted risk exception for a VUL ticket',
    inputSchema: {
      type: 'object' as const,
      properties: {
        ticket_key: {
          type: 'string',
          description: 'VUL ticket key (e.g., "VUL-3385")',
        },
      },
      required: ['ticket_key'],
    },
  },
];

class PITAServer {
  private server: Server;
  private jira: JiraClient;
  private tts: TTSClient;

  constructor() {
    this.server = new Server(
      {
        name: 'pantheon-pita-mcp',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.jira = JiraClient.fromEnv();
    this.tts = TTSClient.fromEnv();

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // List tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: TOOLS,
    }));

    // Call tool
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'pita_team_summary':
            return await this.handleTeamSummary(args as { squad?: string; scope?: string });

          case 'pita_sla_status':
            return await this.handleSLAStatus(args as { squad?: string; priority_filter?: string; scope?: string });

          case 'pita_ticket_details':
            return await this.handleTicketDetails(args as { ticket_key: string; scope?: string });

          case 'pita_trend':
            return await this.handleTrend(args as { squad?: string; period?: string; scope?: string });

          case 'pita_remediation_plan':
            return await this.handleRemediationPlan(args as { squad?: string; limit?: number; scope?: string });

          case 'pita_blast_radius':
            return await this.handleBlastRadius(args as { ticket_key?: string; cve?: string; package?: string; scope?: string });

          case 'pita_draft_risk_exception':
            return await this.handleRiskException(args as { ticket_key: string });

          default:
            return {
              content: [{ type: 'text', text: `Unknown tool: ${name}` }],
              isError: true,
            };
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: 'text', text: `Error: ${message}` }],
          isError: true,
        };
      }
    });
  }

  // Tool handlers - Phase 1 implementations

  private async handleTeamSummary(args: { squad?: string; scope?: string }) {
    const scope = args.scope || 'audit';
    const summary = await getTeamSummary(this.jira, this.tts, args.squad, scope, AUDIT_FILTER_ID);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(summary, null, 2),
      }],
    };
  }

  private async handleSLAStatus(args: { squad?: string; priority_filter?: string; scope?: string }) {
    const scope = args.scope || 'audit';
    const result = await getSLAStatus(this.jira, this.tts, args.squad, args.priority_filter, scope, AUDIT_FILTER_ID);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  private async handleTicketDetails(args: { ticket_key: string; scope?: string }) {
    const scope = args.scope || 'audit';
    const result = await getTicketDetails(this.jira, this.tts, args.ticket_key, scope);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  private async handleTrend(args: { squad?: string; period?: string; scope?: string }) {
    const scope = args.scope || 'audit';
    const result = await getTrend(this.jira, args.squad, args.period ?? '30d', scope, AUDIT_FILTER_ID);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  private async handleRemediationPlan(args: { squad?: string; limit?: number; scope?: string }) {
    const scope = args.scope || 'audit';
    const result = await getRemediationPlan(this.jira, this.tts, args.squad, args.limit ?? 10, scope, AUDIT_FILTER_ID);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  private async handleBlastRadius(args: { ticket_key?: string; cve?: string; package?: string; scope?: string }) {
    const scope = args.scope || 'audit';
    const result = await getBlastRadius(this.jira, this.tts, args.ticket_key, args.cve, args.package, scope);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  private async handleRiskException(args: { ticket_key: string }) {
    const result = await draftRiskException(this.jira, args.ticket_key);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('PITA MCP server running on stdio');
  }
}

const server = new PITAServer();
server.run().catch(console.error);
