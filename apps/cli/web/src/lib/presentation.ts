import type { Finding, RunProgress, RunStatus, Severity } from '../types/api';

const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severityDifference = severityRank[left.severity] - severityRank[right.severity];
    return severityDifference || left.title.localeCompare(right.title);
  });
}

export function clampProgress(progress: RunProgress): number {
  if (Number.isFinite(progress.percent)) {
    return Math.min(100, Math.max(0, Math.round(progress.percent)));
  }
  if (progress.total <= 0) return 0;
  return Math.min(100, Math.max(0, Math.round((progress.completed / progress.total) * 100)));
}

export function formatDuration(milliseconds?: number): string {
  if (milliseconds === undefined || !Number.isFinite(milliseconds)) return '—';
  const totalSeconds = Math.max(0, Math.floor(milliseconds / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

export function formatCost(cost?: number): string {
  if (cost === undefined || !Number.isFinite(cost)) return '—';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: cost < 1 ? 3 : 2,
    maximumFractionDigits: cost < 1 ? 3 : 2,
  }).format(cost);
}

export function formatTimestamp(timestamp?: string): string {
  if (!timestamp) return '—';
  const date = new Date(timestamp);
  if (Number.isNaN(date.valueOf())) return '—';
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date);
}

export function statusLabel(status: RunStatus): string {
  return status.replaceAll('-', ' ');
}

export function safeMarkdownUrl(url: string): string {
  if (url.startsWith('/api/v1/')) return url;
  try {
    const parsed = new URL(url, window.location.origin);
    if (parsed.origin === window.location.origin || parsed.protocol === 'https:') return parsed.href;
  } catch {
    return '';
  }
  return '';
}
