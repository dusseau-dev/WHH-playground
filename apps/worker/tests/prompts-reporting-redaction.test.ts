import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { AuditSession } from '../src/audit/index.js';
import { generatePromptPath } from '../src/audit/utils.js';
import { loadPrompt, promptDirectoryCandidates } from '../src/services/prompt-manager.js';
import { createExactValueRedactor } from '../src/services/redaction.js';
import {
  injectAssessmentModeSections,
  renderAssessmentModeSections,
  URL_ONLY_COVERAGE_NOTICE,
} from '../src/services/reporting.js';
import { REPORT_MARKDOWN_FILENAME, writeReportMarkdownFiles } from '../src/services/structured-report.js';
import type { ActivityLogger } from '../src/types/activity-logger.js';
import type { DistributedConfig } from '../src/types/config.js';
import { redactSecrets } from '../src/utils/redactSecrets.js';

const promptsRoot = fileURLToPath(new URL('../prompts', import.meta.url));
const promptNames = [
  'recon',
  'vuln-injection',
  'vuln-xss',
  'vuln-auth',
  'vuln-authz',
  'vuln-ssrf',
  'exploit-injection',
  'exploit-xss',
  'exploit-auth',
  'exploit-authz',
  'exploit-ssrf',
  'triage-verdict',
  'report-executive',
  'validate-authentication',
] as const;
const logger: ActivityLogger = { info: () => undefined, warn: () => undefined, error: () => undefined };
const tempRoots: string[] = [];
const forbiddenUrlOnlyPromptText =
  /source file|code line|repo path|pre[-_ ]?recon|nmap|whatweb|source-code|source code|code-location|code path|repository|implementation|line numbers|\{\{EXPLOITATION\}\}/i;
const promptConfig: DistributedConfig = {
  avoid: [],
  focus: [],
  authentication: {
    login_type: 'form',
    login_url: 'https://target.example/login',
    credentials: { username: 'operator' },
    success_condition: { type: 'url_contains', value: '/dashboard' },
  },
  description: 'Authorized target',
  vuln_classes: ['injection', 'xss', 'auth', 'authz', 'ssrf'],
  test_scopes: ['object-access', 'ssrf', 'security-headers', 'transport-session-protection', 'sql-nosql-injection'],
  test_surfaces: ['browser', 'api-graphql'],
  safeDemonstration: false,
  report: {},
  rules_of_engagement: '',
};

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
});

async function listPromptFiles(directory: string): Promise<string[]> {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) return listPromptFiles(fullPath);
      return entry.isFile() && entry.name.endsWith('.txt') ? [fullPath] : [];
    }),
  );
  return files.flat();
}

describe('URL-only prompt isolation', () => {
  it('requires structured report tools and exact triage queue IDs in every prompt family', async () => {
    for (const family of ['', 'url-only', 'pipeline-testing', path.join('pipeline-testing', 'url-only')]) {
      const report = await fs.readFile(path.join(promptsRoot, family, 'report-executive.txt'), 'utf8');
      expect(report).toContain('set_report_meta');
      expect(report).toContain('add_finding');
      expect(report).not.toContain('comprehensive_security_assessment_report.md');

      const triage = await fs.readFile(path.join(promptsRoot, family, 'triage-verdict.txt'), 'utf8');
      expect(triage).toMatch(/exact(?:ly|, byte-for-byte)/i);
      expect(triage).toMatch(/queue `?ID`?/i);
    }
  });

  it('ends every vuln and authentication prompt with its captured submit tool', async () => {
    for (const family of ['', 'url-only', 'pipeline-testing', path.join('pipeline-testing', 'url-only')]) {
      for (const name of promptNames.filter((candidate) => candidate.startsWith('vuln-'))) {
        const contents = (await fs.readFile(path.join(promptsRoot, family, `${name}.txt`), 'utf8')).trim();
        expect(contents).toMatch(/final action must be one call to submit_exploitation_queue\.$/);
      }
      const authPrompt = (
        await fs.readFile(path.join(promptsRoot, family, 'validate-authentication.txt'), 'utf8')
      ).trim();
      expect(authPrompt).toMatch(/final action must be one call to submit_auth_result\.$/);
    }
  });

  it('selects only URL-only prompt roots, including test fallback', () => {
    expect(promptDirectoryCandidates('/prompts', false, 'url-only')).toEqual(['/prompts/url-only']);
    expect(promptDirectoryCandidates('/prompts', true, 'url-only')).toEqual([
      '/prompts/pipeline-testing/url-only',
      '/prompts/url-only',
    ]);
  });

  it('ships a complete prompt set with no source pre-recon dependency', async () => {
    for (const promptFile of [
      ...(await listPromptFiles(path.join(promptsRoot, 'url-only'))),
      ...(await listPromptFiles(path.join(promptsRoot, 'pipeline-testing', 'url-only'))),
    ]) {
      expect(await fs.readFile(promptFile, 'utf8')).not.toMatch(forbiddenUrlOnlyPromptText);
    }

    for (const name of promptNames) {
      await expect(
        fs.access(path.join(promptsRoot, 'pipeline-testing', 'url-only', `${name}.txt`)),
      ).resolves.toBeUndefined();
    }
  });

  it('interpolates the writable workspace and never falls back to a source prompt', async () => {
    const prompt = await loadPrompt(
      'recon',
      {
        webUrl: 'https://target.example',
        workingDirectory: '/app/target',
        AUTH_STATE_FILE: '/app/target/.auth.json',
      },
      null,
      true,
      logger,
      promptsRoot,
      'url-only',
    );
    expect(prompt).toContain('/app/target');
    expect(prompt).toContain('URL-only');
    expect(prompt).not.toContain('{{WORKING_DIRECTORY}}');
  });

  it('interpolates every URL-only prompt without source-only language or legacy placeholders', async () => {
    for (const name of promptNames) {
      const prompt = await loadPrompt(
        name,
        {
          webUrl: 'https://target.example',
          workingDirectory: '/app/target',
          AUTH_STATE_FILE: '/app/target/.auth.json',
        },
        promptConfig,
        false,
        logger,
        promptsRoot,
        'url-only',
      );
      expect(prompt).not.toMatch(forbiddenUrlOnlyPromptText);
      expect(prompt).not.toMatch(/\{\{[^}]+\}\}/);
    }
  });

  it('makes the selected per-agent checks and surfaces authoritative', async () => {
    const prompt = await loadPrompt(
      'vuln-injection',
      {
        webUrl: 'https://target.example',
        workingDirectory: '/app/target',
        AUTH_STATE_FILE: '/app/target/.auth.json',
      },
      {
        ...promptConfig,
        vuln_classes: ['injection'],
        test_scopes: ['xxe'],
        test_surfaces: ['api-graphql'],
      },
      false,
      logger,
      promptsRoot,
      'url-only',
    );

    const scopeBlock = prompt.match(/<assessment_scope>[\s\S]*?<\/assessment_scope>/)?.[0] ?? '';
    expect(scopeBlock).toContain('Only perform the checks listed below');
    expect(scopeBlock).toContain('XML external entities (`xxe`)');
    expect(scopeBlock).toContain('API and GraphQL (`api-graphql`)');
    expect(scopeBlock).not.toContain('Command injection (`command-injection`)');
  });

  it('applies the authoritative per-agent scope in every prompt mode', async () => {
    for (const sourceMode of ['source-assisted', 'url-only'] as const) {
      for (const pipelineTestingMode of [false, true]) {
        const prompt = await loadPrompt(
          'vuln-injection',
          {
            webUrl: 'https://target.example',
            workingDirectory: '/app/target',
            ...(sourceMode === 'source-assisted' && { repoPath: '/app/target' }),
            AUTH_STATE_FILE: '/app/target/.auth.json',
          },
          {
            ...promptConfig,
            vuln_classes: ['injection'],
            test_scopes: ['xxe'],
            test_surfaces: ['api-graphql'],
          },
          pipelineTestingMode,
          logger,
          promptsRoot,
          sourceMode,
        );
        const scopeBlock = prompt.match(/<assessment_scope>[\s\S]*?<\/assessment_scope>/)?.[0] ?? '';
        expect(scopeBlock).toContain('XML external entities (`xxe`)');
        expect(scopeBlock).toContain('API and GraphQL (`api-graphql`)');
        expect(scopeBlock).not.toContain('Command injection (`command-injection`)');
        expect(prompt).not.toMatch(
          /\{\{(?:WEB_URL|REPO_PATH|WORKING_DIRECTORY|SAFE_DEMONSTRATION|ASSESSMENT_SCOPES|ASSESSMENT_SURFACES)\}\}/,
        );
      }
    }
  });
});

describe('coverage reporting', () => {
  it('inserts URL-only mode and coverage sections after the report title exactly once', () => {
    const once = renderAssessmentModeSections('# Security Assessment\n\nBody', 'url-only');
    const twice = renderAssessmentModeSections(once, 'url-only');
    expect(once).toContain(
      '# Security Assessment\n\n## Mode\n\nURL-Only\n\n## Coverage\n\nThis assessment used browser and API observations',
    );
    expect(twice).toBe(once);
  });

  it('inserts Source-Assisted mode and neutral coverage wording', () => {
    const report = renderAssessmentModeSections('# Security Assessment\n\nBody', 'source-assisted');
    expect(report).toContain('## Mode\n\nSource-Assisted');
    expect(report).toContain('do not assert complete source coverage');
  });

  it('replaces the old URL-only notice with deterministic sections', () => {
    const report = renderAssessmentModeSections(
      `# Security Assessment\n\n${URL_ONLY_COVERAGE_NOTICE}\n\nBody`,
      'url-only',
    );
    expect(report).toContain('## Mode\n\nURL-Only');
    expect(report).not.toContain('[!IMPORTANT]');
  });

  it('redacts secrets and PII before persisted Markdown report artifacts are written', async () => {
    const deliverablesPath = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-report-redaction-'));
    tempRoots.push(deliverablesPath);
    await writeReportMarkdownFiles(
      deliverablesPath,
      [
        '# Report',
        'Contact: analyst@example.com',
        'Authorization: Bearer abcdefghijklmnopqrstuvwxyz',
        'OpenRouter key: sk-or-v1-abcdefghijklmnopqrstuvwxyz1234567890',
      ].join('\n'),
    );

    const markdown = await fs.readFile(path.join(deliverablesPath, REPORT_MARKDOWN_FILENAME), 'utf8');
    expect(markdown).toContain('[REDACTED]');
    expect(markdown).not.toContain('analyst@example.com');
    expect(markdown).not.toContain('abcdefghijklmnopqrstuvwxyz');
    expect(markdown).not.toContain('sk-or-v1');
  });

  it('redacts existing legacy Markdown reports even when mode sections are already present', async () => {
    const workingDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-report-injection-redaction-'));
    tempRoots.push(workingDirectory);
    const deliverablesPath = path.join(workingDirectory, '.shannon', 'deliverables');
    await fs.mkdir(deliverablesPath, { recursive: true });
    await fs.writeFile(
      path.join(deliverablesPath, REPORT_MARKDOWN_FILENAME),
      renderAssessmentModeSections('# Report\n\nContact analyst@example.com', 'url-only'),
    );

    await injectAssessmentModeSections(workingDirectory, undefined, 'url-only', logger);

    const markdown = await fs.readFile(path.join(deliverablesPath, REPORT_MARKDOWN_FILENAME), 'utf8');
    expect(markdown).toContain('[REDACTED]');
    expect(markdown).not.toContain('analyst@example.com');
  });
});

describe('secret redaction', () => {
  it('redacts exact values in nested logs and errors without mutating the live value', () => {
    const secret = 'target-secret-123';
    const input = { prompt: `Authenticate with ${secret}`, nested: [new Error(`failed ${secret}`)] };
    const redactor = createExactValueRedactor([secret]);
    const output = redactor.redactValue(input);
    expect(JSON.stringify(output)).not.toContain(secret);
    expect(JSON.stringify(output)).toContain('[REDACTED]');
    expect(input.prompt).toContain(secret);
  });

  it('redacts key-name secrets, tokens, cookies, query params, PII, errors, and circular values', () => {
    const value: Record<string, unknown> = {
      authorization: 'Bearer abcdefghijklmnopqrstuvwxyz',
      url: 'https://target.example/reset?token=abc123&email=user@example.com',
      cookie: 'sessionid=secret-cookie',
      jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiMTIzNDU2Nzg5MCJ9.sgn4tureabcdefghi',
      nested: {
        apiKey: 'sk-proj-abcdefghijklmnop',
        phone: '212-555-1212',
        ssn: '123-45-6789',
        error: new Error('failed with password=hunter2 for user@example.com'),
      },
    };
    value.self = value;

    const redacted = redactSecrets(value, { exactValues: ['secret-cookie'] }) as Record<string, unknown>;
    const serialized = JSON.stringify(redacted);
    expect(serialized).toContain('[REDACTED]');
    expect(serialized).toContain('[Circular]');
    expect(serialized).not.toContain('hunter2');
    expect(serialized).not.toContain('secret-cookie');
    expect(serialized).not.toContain('eyJhbGci');
    expect(serialized).not.toContain('sk-proj-abcdefghijklmnop');
    expect(serialized).not.toContain('user@example.com');
    expect(serialized).not.toContain('212-555-1212');
    expect(serialized).not.toContain('123-45-6789');
    expect(value.cookie).toBe('sessionid=secret-cookie');
  });

  it('redacts prompt snapshots before persistence', async () => {
    const outputPath = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-prompt-redaction-'));
    tempRoots.push(outputPath);
    const sessionMetadata = {
      id: 'redaction-session',
      webUrl: 'https://target.example/reset?token=target-token&email=user@example.com',
      outputPath,
    };
    const auditSession = new AuditSession(sessionMetadata);
    auditSession.setRedactionSecrets(['exact-secret-123']);
    await auditSession.initialize('workflow-redaction');
    await auditSession.startAgent('recon', 'Use password=hunter2 and exact-secret-123 for user@example.com', 1);
    await auditSession.endAgent('recon', {
      attemptNumber: 1,
      duration_ms: 1,
      cost_usd: 0,
      success: true,
    });

    const snapshot = await fs.readFile(generatePromptPath(sessionMetadata, 'recon'), 'utf8');
    expect(snapshot).toContain('[REDACTED]');
    expect(snapshot).not.toContain('hunter2');
    expect(snapshot).not.toContain('exact-secret-123');
    expect(snapshot).not.toContain('user@example.com');
    expect(snapshot).not.toContain('target-token');
  });
});
