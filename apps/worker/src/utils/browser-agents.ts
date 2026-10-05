export const BROWSER_AGENTS: ReadonlySet<string> = new Set([
  'recon',
  'injection-vuln',
  'xss-vuln',
  'auth-vuln',
  'ssrf-vuln',
  'authz-vuln',
  'injection-exploit',
  'xss-exploit',
  'auth-exploit',
  'ssrf-exploit',
  'authz-exploit',
  'validate-authentication',
  'verify-exploit',
]);

export function isBrowserAgent(agentName: string | null | undefined): boolean {
  return agentName != null && BROWSER_AGENTS.has(agentName);
}
