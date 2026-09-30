/**
 * Temporal owns whole-agent retries. Pi retains provider transport retries so a
 * transient 408/409/429/5xx does not replay an entire paid agent session.
 */
export const PI_RETRY_SETTINGS = {
  enabled: false,
  provider: { maxRetries: 8 },
} as const;
