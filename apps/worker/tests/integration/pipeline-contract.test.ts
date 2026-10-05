import { describe, expect, it } from 'vitest';
import { computeExpectedAgents, normalizeSourceContext } from '../../src/temporal/shared.js';

describe('Docker pipeline smoke prerequisites', () => {
  it('constructs a complete URL-only dynamic plan without a repository', () => {
    const source = normalizeSourceContext({
      webUrl: 'https://authorized-target.test',
      sourceMode: 'url-only',
      workingDirectory: '/app/target',
    });
    const plan = computeExpectedAgents('url-only', ['injection', 'xss', 'auth', 'authz', 'ssrf'], true);
    expect(source).not.toHaveProperty('repoPath');
    expect(plan).toEqual([
      'recon',
      'injection-vuln',
      'injection-exploit',
      'xss-vuln',
      'xss-exploit',
      'auth-vuln',
      'auth-exploit',
      'authz-vuln',
      'authz-exploit',
      'ssrf-vuln',
      'ssrf-exploit',
      'triage',
      'report',
    ]);
  });

  it('retains the source-assisted pre-recon regression contract', () => {
    const source = normalizeSourceContext({ webUrl: 'https://authorized-target.test', repoPath: '/repos/target' });
    expect(source).toMatchObject({
      sourceMode: 'source-assisted',
      repoPath: '/repos/target',
      workingDirectory: '/repos/target',
    });
    expect(computeExpectedAgents('source-assisted', ['injection'], true)[0]).toBe('pre-recon');
  });
});
