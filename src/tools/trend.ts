// src/tools/trend.ts

import type { JiraClient } from '../clients/jira.js';
import { TREND_FIELDS } from '../clients/jira.js';

export interface TrendResult {
  squad: string;
  period: string;
  new: number;
  resolved: number;
  net: number;
  byWeek: {
    week: string;
    new: number;
    resolved: number;
  }[];
}

export async function getTrend(
  jira: JiraClient,
  squad?: string,
  period = '30d',
  scope = 'audit',
  auditFilterId = '26914'
): Promise<TrendResult> {
  // Parse period
  const days = parseInt(period.replace('d', ''), 10) || 30;
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  const startDateStr = startDate.toISOString().split('T')[0];

  const base = scope === 'audit' ? `filter = ${auditFilterId}` : 'project = VUL';
  const squadClause = squad ? ` AND "Squad" = "${squad}"` : '';

  // Get new and resolved counts
  const newJql = `${base}${squadClause} AND created >= "${startDateStr}"`;
  const resolvedJql = `${base}${squadClause} AND resolved >= "${startDateStr}"`;

  const [newResponse, resolvedResponse] = await Promise.all([
    jira.searchIssues(newJql, Infinity, TREND_FIELDS),
    jira.searchIssues(resolvedJql, Infinity, TREND_FIELDS),
  ]);

  // Group by week
  const weeklyNew = new Map<string, number>();
  const weeklyResolved = new Map<string, number>();

  for (const issue of newResponse.issues) {
    const week = getWeekString(new Date(issue.fields.created));
    weeklyNew.set(week, (weeklyNew.get(week) || 0) + 1);
  }

  for (const issue of resolvedResponse.issues) {
    const updated = issue.fields.updated;
    const week = getWeekString(new Date(updated));
    weeklyResolved.set(week, (weeklyResolved.get(week) || 0) + 1);
  }

  // Combine weeks
  const allWeeks = new Set([...weeklyNew.keys(), ...weeklyResolved.keys()]);
  const byWeek = Array.from(allWeeks)
    .sort()
    .reverse()
    .map(week => ({
      week,
      new: weeklyNew.get(week) || 0,
      resolved: weeklyResolved.get(week) || 0,
    }));

  const newCount = newResponse.total ?? newResponse.issues.length;
  const resolvedCount = resolvedResponse.total ?? resolvedResponse.issues.length;

  return {
    squad: squad || 'All PDE',
    period,
    new: newCount,
    resolved: resolvedCount,
    net: newCount - resolvedCount,
    byWeek,
  };
}

function getWeekString(date: Date): string {
  const year = date.getFullYear();
  const onejan = new Date(year, 0, 1);
  const weekNum = Math.ceil(((date.getTime() - onejan.getTime()) / 86400000 + onejan.getDay() + 1) / 7);
  return `${year}-W${String(weekNum).padStart(2, '0')}`;
}
