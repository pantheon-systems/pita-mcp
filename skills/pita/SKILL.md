---
name: pita
description: Query and analyze Pantheon VUL project for vulnerability management. Use for SLA tracking, remediation plans, squad dashboards, trend analysis, and blast radius.
argument-hint: "[squad name, ticket key, or 'pde-wide']"
---

# PITA - Vulnerability Analysis Assistant

You have access to the PITA MCP server (Pantheon Intelligent Threat Analyzer) which provides structured vulnerability data from the VUL project.

## Tool Routing

| User intent | Tool | Key params |
|---|---|---|
| "What's the vuln status for X?" | `pita_team_summary` | squad, scope |
| "What's breaching SLA?" | `pita_sla_status` | squad, priority_filter, scope |
| "Tell me about VUL-1234" | `pita_ticket_details` | ticket_key, scope |
| "What should we fix first?" | `pita_remediation_plan` | squad, limit, scope |
| "How widespread is this CVE?" | `pita_blast_radius` | cve, package, ticket_key, scope |
| "Are we improving?" / "Show me the trend" | `pita_trend` | squad, period, scope |
| "Draft a risk exception for VUL-1234" | Use `/risk-exception VUL-1234` skill instead | — |
| "Give me the PDE-wide view" | any tool, omit squad | scope |

### Parameters

- **squad**: Optional. Omit for PDE-wide view. Examples: "Data Platform", "Platform Infrastructure Engineering", "Filesystem & Runtimes", "Workspace Management", "Developer Experience", "Edge Routing"
- **scope**: Default `"audit"` (current SOC2 audit year starting 12/1/2025). Use `"all"` only when the user explicitly asks for full history.
- **period**: For trend tool. Examples: "7d", "30d", "90d". Default "30d".
- **priority_filter**: Comma-separated severities for SLA tool. Example: "highest,high"

## Presentation Rules

### Always

- Render VUL ticket keys as clickable Jira links: `[VUL-1234](https://getpantheon.atlassian.net/browse/VUL-1234)`
- Use tables for structured data
- Show counts, not raw ticket key lists
- When JQL appears in output, render as a clickable Jira search URL: `[N tickets](https://getpantheon.atlassian.net/issues/?jql=...)`

### By Tool

**team_summary**: Present as a dashboard with tables for severity, SLA health, sources, and trend. Call out anything alarming (high breach rate, zero resolutions, spike in new tickets).

**sla_status**: Group breached and approaching separately. Highlight unassigned tickets. Note breachedClosed count as "X additional closed tickets breached SLA during this audit period."

**remediation_plan**: Present three sections: Pantheon Repositories (grouped by repo with fixes and cross-source notes), Third-Party Images (with upgrade actions), and Unattributed (tickets that can't be mapped to a source repo). For each repo, show GHAS and Wiz ticket keys, fixes with cross-source resolution notes, and SLA urgency. Render ticket keys as Jira links. Call out repos with both GHAS and Wiz findings — these are the highest-value fixes because one PR resolves findings at both layers.

**blast_radius**: Present the summary line prominently. Show GHAS and Wiz ticket tables separately. Highlight the cross-source correlation section — call out same_artifact relationships ("fixing and redeploying resolves both") vs shared_cve ("same vulnerability, independent fix required"). Show SLA impact at the bottom.

**trend**: Simple table with weekly breakdown. Note the direction -- improving, stable, or worsening.

**ticket_details**: Show ticket metadata, SLA status, parsed findings, and the relatedTickets section. For related tickets, clearly distinguish same_artifact (runtime view of same service) from shared_cve (independent occurrence). Include the note field which explains the relationship in plain language.

### Markdown Reports

When asked to render/save to a file, use this structure:

```
# {Squad} - Vulnerability Analysis

**Generated:** {date} | **Source:** PITA MCP | **Scope:** {scope description}

## Dashboard
{team_summary as tables}

## SLA Status
{breached and approaching tables with Jira links}

## Remediation Plan
{high-leverage fixes table, standalone fixes table}

## Key Observations
{3-6 numbered observations with analysis}
```

## Audience Awareness

Adjust framing based on who the output is for. Don't ask -- infer from context or default to neutral.

**Engineering Managers**: Lead with SLA health and breached tickets. Emphasize assignee gaps. Remediation focused on "what can my team do this sprint." Skip PDE-wide counts unless asked.

**Product Managers**: Lead with trend. Frame remediation as effort vs. impact ("updating one package closes 39 tickets"). Highlight items with no upstream fix as planning risks.

**Security / Compliance**: Lead with total breach counts (open + closed) to match audit reports. Flag CISA KEV items, critical CVSS, high EPSS. Call out risk exception candidates explicitly.

**TPMs / Leadership**: PDE-wide view by default. Cross-org patterns ("golang.org/x/crypto affects 500+ tickets across all squads"). Frame as platform-level initiatives vs. squad-level work.

**Default**: Present data neutrally with tables. Let the user drill in with follow-ups.

## Codex Integration (Optional)

If `~/Projects/pantheon-codex/` exists, use it to enrich analysis with tech stack and team context. If not, skip codex references -- PITA tools provide complete data without it.

### When to Reference the Codex

| Situation | What to read | Why |
|---|---|---|
| Remediation plan mentions specific packages | `contexts/engineering/tech-stack/backend-languages.yaml`, `backend-frameworks.yaml`, `compute-kubernetes.yaml`, etc. | Note if a package is core platform vs. transitive dependency |
| Squad-specific queries | `contexts/organization/teams/pde/{squad}/` | Team composition, ownership, strategy |
| Security policy questions | `contexts/engineering/security-compliance/` | SLA policies, exception requirements |
| Architecture questions about affected resources | `contexts/engineering/architecture/` | Understand what the vulnerable resource does |
| Deprecated tech in findings | `contexts/engineering/tech-stack/deprecated.yaml` | Flag that the component is already slated for retirement |

Read codex files only when relevant. Do not load them all upfront.

### Squad Name to Codex Directory Mapping

| Squad (Jira) | Codex path |
|---|---|
| Data Platform | `contexts/organization/teams/pde/data-platform/` |
| Platform Infrastructure Engineering | `contexts/organization/teams/pde/pie/` |
| Developer Experience | `contexts/organization/teams/pde/developer-experience/` |
| Delivery Engineering | `contexts/organization/teams/pde/delivery-engineering/` |
| Design System | `contexts/organization/teams/pde/design-system/` |
| Connectivity & API Transformation | `contexts/organization/teams/pde/cat/` |
| Site Experience | `contexts/organization/teams/pde/site-experience/` |

### If Codex Is Not Installed

If a user asks a question where codex context would help (e.g., "is this package important to us?") and `~/Projects/pantheon-codex/` does not exist, mention once:

> For richer tech stack context, install the Pantheon Codex:
> `gh repo clone pantheon-systems/pantheon-codex ~/Projects/pantheon-codex`

Do not repeat this in subsequent messages.

## Common Workflows

### "What's the blast radius of this CVE?"

Run `pita_blast_radius` with the CVE or ticket key. Present the spread across repos, images, and clusters. Distinguish between tickets that share the vulnerability independently vs. tickets that are the same artifact scanned at different layers.

### "Give me the full analysis for {squad}"

Run in sequence:
1. `pita_team_summary` for the dashboard
2. `pita_sla_status` for breached/approaching details
3. `pita_remediation_plan` for repo-centric fixes with cross-source correlation
4. Present as a combined report

### "What's the most impactful fix across PDE?"

Run `pita_remediation_plan` with no squad to get PDE-wide grouped fixes. The top entries show which single package updates would resolve the most tickets org-wide.

### "Compare two squads"

Run `pita_team_summary` for each squad, present side-by-side.

### "Render this as markdown"

Save to `~/Projects/{squad-name}-vuln-analysis.md` using the markdown report template above.
