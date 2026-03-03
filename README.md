# PITA - Pantheon Intelligent Threat Analyzer

MCP server for vulnerability management at Pantheon. Gives Claude structured access to the VUL project, parses vulnerability findings from Wiz and GHAS attachments, and generates prioritized remediation plans with cross-org impact analysis.

## Setup

### 1. Clone and build

```bash
git clone git@github.com:pantheon-systems/pita-mcp.git
cd pita-mcp
npm install
npm run build
```

### 2. Set environment variables

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
export ATLASSIAN_EMAIL=your.email@pantheon.io
export ATLASSIAN_API_TOKEN=your-api-token
export ATLASSIAN_INSTANCE_URL=https://getpantheon.atlassian.net
export TTS_API_TOKEN=your-tts-token
```

### 3. Add MCP to Claude Code

```bash
claude mcp add -s user pantheon-pita -- node /path/to/pita-mcp/dist/index.js
```

### 4. Install the `/pita` skill (optional, recommended)

```bash
ln -s /path/to/pita-mcp/skills/pita ~/.claude/skills/pita
```

This gives Claude presentation rules, audience awareness, and codex integration for richer output. Without it, the MCP tools still work -- you just get raw JSON.

### 5. Install the Pantheon Codex (optional)

For tech stack context in remediation plans:

```bash
gh repo clone pantheon-systems/pantheon-codex ~/Projects/pantheon-codex
```

## Tools

All squad-based tools accept an optional `squad` parameter. Omit it for a PDE-wide view. All default to the current SOC2 audit year (`scope: "audit"`); pass `scope: "all"` for full history.

| Tool | Description |
|------|-------------|
| `pita_team_summary` | Open counts by severity, SLA health (breached open + closed), source breakdown, 7-day trend |
| `pita_sla_status` | Breached and approaching SLA tickets. Optional `priority_filter` (comma-separated severities) |
| `pita_ticket_details` | Single VUL ticket with parsed findings from CSV attachments, SLA status, source detection |
| `pita_remediation_plan` | Groups vulnerabilities by shared fix, ranked by impact. Shows squad + PDE-wide ticket counts with JQL links |
| `pita_trend` | New vs resolved over configurable `period` (e.g. "7d", "30d"), broken down by week |
| `pita_draft_risk_exception` | Template-based risk exception draft using ticket data, enrichment, and criticality attachments |

## Usage

With the `/pita` skill installed, just ask naturally:

```
/pita give me the full analysis for Data Platform
/pita what's breaching SLA for Workspace Management?
/pita what's the most impactful fix across PDE?
/pita draft a risk exception for VUL-1950
```

Without the skill, call tools directly:

```
Use pita_team_summary for Data Platform
Use pita_remediation_plan with no squad for PDE-wide
```

## Data Sources

| Source | Data | Access |
|--------|------|--------|
| Jira VUL Project | Tickets, squad, severity, status, attachments | REST API v3 |
| Wiz CSV Attachments | CVE, package, version, fix, severity, dates | Jira attachment API |
| GHAS CSV Attachments | Package, patched version, vulnerable range, GitHub links | Jira attachment API |
| Enrichment.md | CVSS scores, EPSS probability, CISA KEV status | Jira attachment API |
| Criticality CSV | Internet exposure, privilege levels, sensitive data access | Jira attachment API |
| TTS API | SLA status, deadline, days overdue/remaining | REST API |

## Design Decisions

- **Severity** (`customfield_12500`) is used instead of Jira Priority
- **Squad** is `customfield_12050`
- **Audit scope** defaults to Jira filter 26914 (SOC2 audit year, 12/1/2025+)
- **SLA breaches** split into open (needs action) and closed (audit record) to match TTS reports
- **Remediation plans** show squad + PDE-wide counts with JQL for drill-down
- **API optimization**: 5000 page size, per-tool field lists, retry with backoff on 429s

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
├── types/
│   └── index.ts              # Shared TypeScript interfaces
└── skills/
    └── pita/SKILL.md          # /pita skill for Claude Code
```
