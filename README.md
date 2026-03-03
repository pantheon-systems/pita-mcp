# PITA - Pantheon Intelligent Threat Analyzer

MCP server for vulnerability management at Pantheon. Gives Claude structured access to the VUL project, parses vulnerability findings from Wiz and GHAS attachments, and generates prioritized remediation plans with cross-org impact analysis.

## Setup

### Install

```bash
npm install
npm run build
```

### Environment Variables

```bash
export ATLASSIAN_EMAIL=your.email@pantheon.io
export ATLASSIAN_API_TOKEN=your-api-token
export ATLASSIAN_INSTANCE_URL=https://getpantheon.atlassian.net
export TTS_API_TOKEN=your-tts-token
```

### Add to Claude Code

```bash
claude mcp add -s user pantheon-pita -- node /path/to/pantheon-pita-mcp/dist/index.js
```

Environment variables are inherited from your shell profile.

## Tools

All squad-based tools accept an optional `squad` parameter. Omit it for a PDE-wide view. All default to the current SOC2 audit year (`scope: "audit"`); pass `scope: "all"` for full history.

| Tool | Description |
|------|-------------|
| `pita_team_summary` | Open counts by severity, SLA health (breached open + breached closed), source breakdown, 7-day trend |
| `pita_sla_status` | Breached and approaching SLA tickets. Optional `priority_filter` (comma-separated severities) |
| `pita_ticket_details` | Single VUL ticket with parsed findings from CSV attachments, SLA status, source detection |
| `pita_remediation_plan` | Groups vulnerabilities by shared fix, ranked by impact. Shows squad tickets + PDE-wide ticket counts with JQL links |
| `pita_trend` | New vs resolved over configurable `period` (e.g. "7d", "30d"), broken down by week |
| `pita_draft_risk_exception` | Template-based risk exception draft using ticket data, enrichment, and criticality attachments |

## Usage Examples

```
"What's the vulnerability status for Data Platform?"
"Show me breached SLAs for Platform Infrastructure Engineering"
"Give me the PDE-wide team summary"
"What's the most impactful fix for Workspace Management?"
"Show me the 30-day trend for Developer Experience"
"Get details on VUL-3385"
"Draft a risk exception for VUL-1950"
```

## Data Sources

| Source | Data | Access |
|--------|------|--------|
| Jira VUL Project | Tickets, squad assignments, severity, status | REST API v3 (`/rest/api/3/search/jql`) |
| Wiz CSV Attachments | CVE, package, version, fix, severity, detection dates | Jira attachment API |
| GHAS CSV Attachments | Package, patched version, vulnerable range, GitHub links | Jira attachment API |
| Enrichment.md | CVSS scores, EPSS probability, CISA KEV status | Jira attachment API |
| Criticality CSV | Internet exposure, privilege levels, sensitive data access | Jira attachment API |
| TTS API | SLA status (breached/approaching/within), deadline, days overdue | REST API |

## Key Design Decisions

- **Severity field** (`customfield_12500`) is used instead of Jira's Priority field
- **Squad field** is `customfield_12050`
- **Audit scope** defaults to Jira filter 26914 (SOC2 audit year starting 12/1/2025)
- **SLA breaches** are split into open (needs action) and closed (audit record) to match TTS reports
- **Remediation plans** show both squad-level and PDE-wide ticket counts, with JQL queries for drill-down
- **Page size** of 5000 reduces API calls; retry with backoff handles rate limits

## Architecture

```
src/
├── index.ts                  # MCP server, tool definitions, handlers
├── clients/
│   ├── jira.ts               # Search, issue fetch, attachments, retry logic
│   └── tts.ts                # SLA status (single + batch)
├── parsers/
│   ├── wiz-csv.ts            # Wiz CSV (handles multi-line quoted fields)
│   ├── ghas-csv.ts           # GHAS/Dependabot CSV
│   ├── ghas.ts               # GHAS description fallback parser
│   ├── enrichment.ts         # Enrichment.md (CVSS, EPSS, KEV)
│   └── criticality.ts        # Criticality score CSV
├── analysis/
│   └── grouping.ts           # Group findings by fix, rank by impact
├── tools/
│   ├── team-summary.ts       # Dashboard with severity, SLA, sources, trend
│   ├── sla-status.ts         # Breached (open + closed) and approaching
│   ├── ticket-details.ts     # Single ticket with parsed findings
│   ├── remediation-plan.ts   # Grouped fixes with PDE-wide enrichment
│   ├── trend.ts              # Weekly new vs resolved
│   └── risk-exception.ts     # Risk exception draft generator
└── types/
    └── index.ts              # Shared TypeScript interfaces
```
