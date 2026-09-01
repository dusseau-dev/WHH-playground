import { describe, expect, it } from 'vitest';
import {
  computeExpectedAgents,
  DEFAULT_URL_ONLY_WORKING_DIRECTORY,
  normalizeCliPipelineInput,
  normalizeSourceContext,
  resolveSafeDemonstrationInput,
} from '../src/temporal/shared.js';

describe('source context normalization', () => {
  it('preserves the legacy repository-only input as source-assisted', () => {
    expect(normalizeSourceContext({ webUrl: 'https://example.test', repoPath: '/repos/app' })).toEqual({
      sourceMode: 'source-assisted',
      repoPath: '/repos/app',
      workingDirectory: '/repos/app',
    });
  });

  it('normalizes a URL-only workspace without inventing a repository', () => {
    expect(
      normalizeSourceContext({
        webUrl: 'https://example.test',
        sourceMode: 'url-only',
        workingDirectory: '/app/target',
      }),
    ).toEqual({ sourceMode: 'url-only', workingDirectory: '/app/target' });
  });

  it('rejects contradictory or unsafe source inputs', () => {
    expect(() =>
      normalizeSourceContext({
        webUrl: 'https://example.test',
        sourceMode: 'url-only',
        repoPath: '/repos/app',
        workingDirectory: '/app/target',
      }),
    ).toThrow(/must not include repoPath/);
    expect(() =>
      normalizeSourceContext({
        webUrl: 'https://example.test',
        sourceMode: 'source-assisted',
        workingDirectory: '/repos/app',
      }),
    ).toThrow(/requires repoPath/);
    expect(() =>
      normalizeSourceContext({
        webUrl: 'https://example.test',
        sourceMode: 'url-only',
        workingDirectory: '../target',
      }),
    ).toThrow(/absolute path required/);
  });
});

describe('CLI pipeline normalization', () => {
  it('keeps legacy repository input source-assisted', () => {
    expect(normalizeCliPipelineInput({ webUrl: 'https://example.test', repoPath: '/repos/app' })).toMatchObject({
      webUrl: 'https://example.test',
      sourceMode: 'source-assisted',
      repoPath: '/repos/app',
      workingDirectory: '/repos/app',
    });
  });

  it('defaults URL-only CLI input to the container workspace', () => {
    expect(normalizeCliPipelineInput({ webUrl: 'https://example.test' })).toMatchObject({
      webUrl: 'https://example.test',
      sourceMode: 'url-only',
      workingDirectory: DEFAULT_URL_ONLY_WORKING_DIRECTORY,
    });
  });

  it('rejects contradictory CLI mode and repository inputs', () => {
    expect(() =>
      normalizeCliPipelineInput({
        webUrl: 'https://example.test',
        sourceMode: 'url-only',
        repoPath: '/repos/app',
      }),
    ).toThrow(/must not include repoPath/);
    expect(() =>
      normalizeCliPipelineInput({
        webUrl: 'https://example.test',
        sourceMode: 'source-assisted',
      }),
    ).toThrow(/requires repoPath/);
  });

  it('normalizes canonical and legacy safe demonstration flags', () => {
    expect(normalizeCliPipelineInput({ webUrl: 'https://example.test', safeDemonstration: false })).toMatchObject({
      safeDemonstration: false,
    });
    expect(normalizeCliPipelineInput({ webUrl: 'https://example.test', exploit: false })).toMatchObject({
      safeDemonstration: false,
    });
    expect(resolveSafeDemonstrationInput({ safeDemonstration: true, exploit: true })).toBe(true);
    expect(() => resolveSafeDemonstrationInput({ safeDemonstration: true, exploit: false })).toThrow(/conflicts/);
  });
});

describe('execution plans', () => {
  it('skips only source pre-recon in URL-only mode', () => {
    expect(computeExpectedAgents('url-only', ['injection', 'authz'], true)).toEqual([
      'recon',
      'injection-vuln',
      'injection-exploit',
      'authz-vuln',
      'authz-exploit',
      'triage',
      'report',
    ]);
  });

  it('retains source pre-recon and honors disabled demonstrations', () => {
    expect(computeExpectedAgents('source-assisted', ['xss'], false)).toEqual([
      'pre-recon',
      'recon',
      'xss-vuln',
      'triage',
      'report',
    ]);
  });
});
