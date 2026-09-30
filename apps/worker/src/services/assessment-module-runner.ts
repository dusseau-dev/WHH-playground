import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs/promises';
import path from 'node:path';
import tls from 'node:tls';
import { promisify } from 'node:util';
import yaml from 'js-yaml';
import type { SourceMode } from '../types/config.js';
import {
  ASSESSMENT_MODULE_REGISTRY,
  type AssessmentModule,
  type ModuleExecutionResult,
  type ModuleExecutionStatus,
  type ModuleSafetyConfig,
  normalizeAssessmentModules,
} from '../types/scopes.js';
import { atomicWrite, ensureDirectory, fileExists } from '../utils/file-io.js';
import { redactSecrets, sanitizeUrlForDiagnostics } from '../utils/redactSecrets.js';

const execFileAsync = promisify(execFile);
const MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_PASSIVE_BODY_BYTES = 1024 * 1024;

export const CURATED_NUCLEI_TEMPLATES = [
  'http/misconfiguration/http-missing-security-headers.yaml',
  'http/exposures/configs/nextjs-vite-public-env.yaml',
  'http/exposures/configs/git-config.yaml',
  'http/exposures/configs/package-json.yaml',
  'http/technologies/tech-detect.yaml',
] as const;

const NUCLEI_TEMPLATE_ROOT = process.env.SHANNON_NUCLEI_TEMPLATE_DIR ?? '/opt/nuclei-templates';

const MODULE_ENV_ALLOWLIST = [
  'PATH',
  'HOME',
  'TMPDIR',
  'JAVA_HOME',
  'LANG',
  'LC_ALL',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'NODE_EXTRA_CA_CERTS',
  'XDG_CACHE_HOME',
  'XDG_CONFIG_HOME',
  'npm_config_cache',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
  'no_proxy',
] as const;

/** Build a scanner environment without inheriting model, cloud, or other worker credentials. */
export function buildModuleCommandEnvironment(
  overrides: Readonly<Record<string, string>> = {},
): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const name of MODULE_ENV_ALLOWLIST) {
    const value = process.env[name];
    if (value !== undefined) environment[name] = value;
  }
  return { ...environment, ...overrides };
}

export interface ModuleCommandSpec {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
  readonly acceptableExitCodes?: readonly number[];
}

export interface ModuleCommandResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly unavailable?: boolean;
}

export type ModuleCommandRunner = (spec: ModuleCommandSpec) => Promise<ModuleCommandResult>;

export interface AssessmentModuleRunOptions {
  readonly webUrl: string;
  readonly workingDirectory: string;
  readonly deliverablesPath: string;
  readonly sourceMode: SourceMode;
  readonly assessmentModules: readonly AssessmentModule[];
  readonly moduleSafety: ModuleSafetyConfig;
  /** Cookie header reconstructed from the validated browser state. Never written to evidence. */
  readonly authenticationCookie?: string;
}

export interface AssessmentModuleRunnerDependencies {
  readonly commandRunner?: ModuleCommandRunner;
  readonly fetch?: typeof fetch;
  readonly now?: () => Date;
}

type CheckStatus = 'passed' | 'finding' | 'error' | 'skipped' | 'unavailable';

interface ModuleCheckEvidence {
  readonly id: string;
  readonly status: CheckStatus;
  readonly summary: string;
  readonly artifact?: string;
  readonly output_sha256?: string;
}

interface ModuleEvidence {
  readonly schema_version: 1;
  readonly module: AssessmentModule;
  readonly status: ModuleExecutionStatus;
  readonly target: string;
  readonly started_at: string;
  readonly completed_at: string;
  readonly safety: {
    readonly target_environment: ModuleSafetyConfig['targetEnvironment'];
    readonly max_requests_per_second: number;
    readonly max_concurrency: number;
  };
  readonly checks: readonly ModuleCheckEvidence[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Load only module results whose canonical evidence file exists and agrees with the manifest. */
export async function loadAssessmentModuleResults(deliverablesPath: string): Promise<ModuleExecutionResult[]> {
  const manifestPath = path.join(deliverablesPath, 'modules', 'manifest.json');
  if (!(await fileExists(manifestPath))) return [];

  try {
    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8')) as unknown;
    if (!isRecord(manifest) || !Array.isArray(manifest.results)) return [];
    const statuses = new Set<ModuleExecutionStatus>(['completed', 'partial', 'failed', 'skipped', 'unavailable']);
    const entries = new Map<string, Record<string, unknown>>();
    for (const candidate of manifest.results) {
      if (isRecord(candidate) && typeof candidate.id === 'string') entries.set(candidate.id, candidate);
    }

    const results: ModuleExecutionResult[] = [];
    for (const { id } of ASSESSMENT_MODULE_REGISTRY) {
      const entry = entries.get(id);
      const expectedEvidencePath = `modules/${id}.json`;
      if (
        !entry ||
        !statuses.has(entry.status as ModuleExecutionStatus) ||
        entry.evidencePath !== expectedEvidencePath
      ) {
        continue;
      }
      const evidencePath = path.join(deliverablesPath, expectedEvidencePath);
      if (!(await fileExists(evidencePath))) continue;
      const evidence = JSON.parse(await fs.readFile(evidencePath, 'utf8')) as unknown;
      if (
        !isRecord(evidence) ||
        evidence.schema_version !== 1 ||
        evidence.module !== id ||
        evidence.status !== entry.status
      ) {
        continue;
      }
      results.push({ id, status: entry.status as ModuleExecutionStatus, evidencePath: expectedEvidencePath });
    }
    return results;
  } catch {
    return [];
  }
}

export interface K6Stage {
  readonly target: number;
  readonly duration: string;
}

/** Build the canonical 1 → 5 → 10 → 25 ramp, capped by the authorized concurrency. */
export function buildK6Stages(maxConcurrency: number, durationSeconds: number): K6Stage[] {
  const targets = [...new Set([1, 5, 10, 25].map((value) => Math.min(value, maxConcurrency)))];
  return targets.map((target) => ({ target, duration: `${durationSeconds}s` }));
}

/** Nuclei never runs its unrestricted template corpus. */
export function buildNucleiArgs(
  targetFile: string,
  safety: ModuleSafetyConfig,
  outputPath: string,
  configPath?: string,
): string[] {
  return [
    '-list',
    targetFile,
    '-jsonl-export',
    outputPath,
    '-rl',
    String(safety.maxRequestsPerSecond),
    '-c',
    String(safety.maxConcurrency),
    '-timeout',
    '5',
    '-retries',
    '0',
    '-exclude-tags',
    'dos,fuzz,intrusive,headless',
    '-ni',
    ...(configPath ? ['-config', configPath] : []),
    ...CURATED_NUCLEI_TEMPLATES.flatMap((template) => ['-t', path.join(NUCLEI_TEMPLATE_ROOT, template)]),
  ];
}

const defaultCommandRunner: ModuleCommandRunner = async (spec) => {
  try {
    const result = await execFileAsync(spec.command, [...spec.args], {
      cwd: spec.cwd,
      env: buildModuleCommandEnvironment(spec.env),
      timeout: spec.timeoutMs ?? 15 * 60_000,
      maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
      encoding: 'utf8',
    });
    return { exitCode: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const failure = error as NodeJS.ErrnoException & { stdout?: string; stderr?: string; code?: string | number };
    if (failure.code === 'ENOENT') return { exitCode: null, stdout: '', stderr: '', unavailable: true };
    return {
      exitCode: typeof failure.code === 'number' ? failure.code : 1,
      stdout: failure.stdout ?? '',
      stderr: failure.stderr ?? failure.message,
    };
  }
};

function outputHash(result: ModuleCommandResult): string {
  return crypto.createHash('sha256').update(result.stdout).update('\0').update(result.stderr).digest('hex');
}

async function commandCheck(
  id: string,
  spec: ModuleCommandSpec,
  runner: ModuleCommandRunner,
  artifact?: string,
): Promise<ModuleCheckEvidence> {
  const result = await runner(spec);
  if (result.unavailable) return { id, status: 'unavailable', summary: `${spec.command} is not installed` };
  const acceptable = spec.acceptableExitCodes ?? [0];
  if (result.exitCode !== null && acceptable.includes(result.exitCode)) {
    return {
      id,
      status: result.exitCode === 0 ? 'passed' : 'finding',
      summary: `${spec.command} completed with exit code ${result.exitCode}`,
      ...(artifact && { artifact }),
      output_sha256: outputHash(result),
    };
  }
  return {
    id,
    status: 'error',
    summary: `${spec.command} failed with exit code ${result.exitCode ?? 'unknown'}`,
    output_sha256: outputHash(result),
  };
}

function aggregateStatus(checks: readonly ModuleCheckEvidence[]): ModuleExecutionStatus {
  const attempted = checks.filter(({ status }) => status !== 'skipped');
  if (attempted.length === 0) return 'skipped';
  if (attempted.every(({ status }) => status === 'unavailable')) return 'unavailable';
  const successes = attempted.filter(({ status }) => status === 'passed' || status === 'finding').length;
  if (successes === 0) return 'failed';
  if (attempted.some(({ status }) => status === 'error' || status === 'unavailable')) return 'partial';
  return 'completed';
}

async function readLimited(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  while (bytes < MAX_PASSIVE_BODY_BYTES) {
    const next = await reader.read();
    if (next.done) break;
    const remaining = MAX_PASSIVE_BODY_BYTES - bytes;
    const chunk = next.value.byteLength > remaining ? next.value.slice(0, remaining) : next.value;
    chunks.push(chunk);
    bytes += chunk.byteLength;
    if (next.value.byteLength > remaining) {
      await reader.cancel();
      break;
    }
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

async function fetchText(fetchImpl: typeof fetch, url: string): Promise<{ response: Response; body: string }> {
  const response = await fetchImpl(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
    headers: { 'user-agent': 'Shannon-Passive-Exposure/1.0' },
  });
  return { response, body: await readLimited(response) };
}

async function tlsCheck(url: URL): Promise<ModuleCheckEvidence> {
  if (url.protocol !== 'https:')
    return { id: 'tls-certificate', status: 'finding', summary: 'Target does not use HTTPS' };
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: url.hostname,
      rejectUnauthorized: true,
      timeout: 8_000,
    });
    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate();
      const protocol = socket.getProtocol() ?? 'unknown';
      socket.end();
      resolve({
        id: 'tls-certificate',
        status: 'passed',
        summary: `Certificate validated; protocol ${protocol}; expires ${certificate.valid_to || 'unknown'}`,
      });
    });
    socket.once('timeout', () => socket.destroy(new Error('TLS connection timed out')));
    socket.once('error', (error) => {
      resolve({ id: 'tls-certificate', status: 'error', summary: `TLS validation failed: ${error.message}` });
    });
  });
}

const SECURITY_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
] as const;

const SECRET_INDICATORS: ReadonlyArray<{ name: string; pattern: RegExp }> = [
  { name: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'private key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'provider token', pattern: /\b(?:gh[pousr]_|sk-(?:proj-|ant-)?|xox[pbar]-)[A-Za-z0-9._-]{12,}\b/ },
];

async function runPassiveExposure(
  options: AssessmentModuleRunOptions,
  fetchImpl: typeof fetch,
): Promise<ModuleCheckEvidence[]> {
  const target = new URL(options.webUrl);
  const checks: ModuleCheckEvidence[] = [];
  try {
    const addresses = await dns.lookup(target.hostname, { all: true });
    checks.push({
      id: 'dns',
      status: 'passed',
      summary: `Resolved ${addresses.length} address record${addresses.length === 1 ? '' : 's'}`,
    });
  } catch (error) {
    checks.push({
      id: 'dns',
      status: 'error',
      summary: `DNS lookup failed: ${error instanceof Error ? error.message : String(error)}`,
    });
  }
  checks.push(await tlsCheck(target));

  let page: Awaited<ReturnType<typeof fetchText>>;
  try {
    page = await fetchText(fetchImpl, target.href);
  } catch (error) {
    checks.push({
      id: 'http-response',
      status: 'error',
      summary: `Target request failed: ${error instanceof Error ? error.message : String(error)}`,
    });
    return checks;
  }
  checks.push({
    id: 'http-response',
    status: page.response.ok ? 'passed' : 'finding',
    summary: `Target returned HTTP ${page.response.status}`,
  });
  const missingHeaders = SECURITY_HEADERS.filter((header) => !page.response.headers.has(header));
  checks.push({
    id: 'security-headers',
    status: missingHeaders.length === 0 ? 'passed' : 'finding',
    summary:
      missingHeaders.length === 0
        ? 'All baseline security headers are present'
        : `Missing: ${missingHeaders.join(', ')}`,
  });

  try {
    const robotsUrl = new URL('/robots.txt', target.origin).href;
    const robots = await fetchText(fetchImpl, robotsUrl);
    const entries = robots.body.match(/^\s*(?:allow|disallow|sitemap)\s*:/gim)?.length ?? 0;
    checks.push({
      id: 'robots-txt',
      status: 'passed',
      summary: `robots.txt returned ${robots.response.status}; ${entries} directive(s)`,
    });
  } catch (error) {
    checks.push({
      id: 'robots-txt',
      status: 'error',
      summary: `robots.txt request failed: ${error instanceof Error ? error.message : String(error)}`,
    });
  }

  const scriptMatches = [...page.body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((match) => match[1]);
  const scriptUrls = [...new Set(scriptMatches)]
    .flatMap((value) => {
      if (!value) return [];
      try {
        const resolved = new URL(value, page.response.url || target.href);
        return resolved.origin === target.origin ? [resolved.href] : [];
      } catch {
        return [];
      }
    })
    .slice(0, 6);
  const secretIndicators = new Set<string>();
  const apiRoutes = new Set<string>();
  const sourceMapUrls = new Set<string>();
  for (const scriptUrl of scriptUrls) {
    try {
      const script = await fetchText(fetchImpl, scriptUrl);
      for (const indicator of SECRET_INDICATORS)
        if (indicator.pattern.test(script.body)) secretIndicators.add(indicator.name);
      for (const match of script.body.matchAll(/sourceMappingURL\s*=\s*([^\s*]+)/g)) {
        if (!match[1] || match[1].startsWith('data:')) continue;
        try {
          const mapUrl = new URL(match[1], scriptUrl);
          if (mapUrl.origin === target.origin) sourceMapUrls.add(mapUrl.href);
        } catch {
          // Invalid source map references are ignored.
        }
      }
      for (const route of script.body.matchAll(/["'`]((?:\/api\/|\/graphql\b)[^"'`\s]*)["'`]/g)) {
        if (route[1]) apiRoutes.add(route[1].slice(0, 200));
      }
    } catch {
      // A public asset disappearing between discovery and retrieval is recorded in the aggregate count only.
    }
  }
  let accessibleSourceMaps = 0;
  for (const sourceMapUrl of [...sourceMapUrls].slice(0, 2)) {
    try {
      const sourceMap = await fetchText(fetchImpl, sourceMapUrl);
      if (sourceMap.response.ok) accessibleSourceMaps++;
    } catch {
      // A referenced map that is not retrievable is not publicly exposed.
    }
  }
  checks.push({
    id: 'public-javascript',
    status: secretIndicators.size > 0 ? 'finding' : 'passed',
    summary: `Reviewed ${scriptUrls.length} same-origin script(s); secret indicators: ${[...secretIndicators].join(', ') || 'none'}`,
  });
  checks.push({
    id: 'source-maps',
    status: accessibleSourceMaps > 0 ? 'finding' : 'passed',
    summary: `${sourceMapUrls.size} source-map reference(s); ${accessibleSourceMaps} publicly retrievable`,
  });
  checks.push({
    id: 'passive-api-discovery',
    status: apiRoutes.size > 0 ? 'finding' : 'passed',
    summary: `${apiRoutes.size} API route indicator(s) found in public JavaScript`,
  });
  return checks;
}

function scannerEnvironment(cookie: string | undefined): Record<string, string> | undefined {
  return cookie ? { SHANNON_AUTH_COOKIE: cookie } : undefined;
}

async function writeNucleiAuthConfig(modulesDir: string, cookie: string | undefined): Promise<string | undefined> {
  if (!cookie) return;
  const configPath = path.join(modulesDir, '.nuclei-auth.yaml');
  await fs.writeFile(configPath, `header:\n  - ${JSON.stringify(`Cookie: ${cookie}`)}\n`, { mode: 0o600 });
  return configPath;
}

async function writeNucleiTargetFile(modulesDir: string, target: string): Promise<string> {
  const targetFile = path.join(modulesDir, '.nuclei-targets.txt');
  await fs.writeFile(targetFile, `${target}\n`, { mode: 0o600 });
  return targetFile;
}

async function writeZapAutomationPlan(
  modulesDir: string,
  assetsDir: string,
  target: string,
  safety: ModuleSafetyConfig,
  active: boolean,
  authenticated: boolean,
): Promise<string> {
  const targetUrl = new URL(target);
  const reportName = active ? 'zap-active' : 'zap-passive';
  const jobs: Array<Record<string, unknown>> = [];
  if (authenticated) {
    jobs.push({
      type: 'replacer',
      parameters: { deleteAllRules: true },
      rules: [
        {
          description: 'shannon-auth-cookie',
          url: `^${targetUrl.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}.*$`,
          matchType: 'req_header',
          matchString: 'Cookie',
          matchRegex: false,
          replacementString: `\${SHANNON_AUTH_COOKIE}`,
        },
      ],
    });
  }
  jobs.push(
    {
      type: 'spider',
      parameters: {
        context: 'shannon-target',
        url: target,
        maxDuration: 1,
        maxDepth: 5,
        maxChildren: 20,
        threadCount: 1,
      },
    },
    { type: 'passiveScan-wait', parameters: { maxDuration: 5 } },
  );
  if (active) {
    jobs.push({
      type: 'activeScan',
      parameters: {
        context: 'shannon-target',
        url: target,
        defaultStrength: 'Low',
        defaultThreshold: 'Medium',
        maxRuleDurationInMins: 1,
        maxScanDurationInMins: 10,
        maxAlertsPerRule: 10,
        threadPerHost: safety.maxConcurrency,
        delayInMs: Math.ceil((safety.maxConcurrency * 1_000) / safety.maxRequestsPerSecond),
      },
    });
  }
  jobs.push({
    type: 'report',
    parameters: {
      template: 'traditional-json',
      reportDir: assetsDir,
      reportFile: `${reportName}.json`,
      reportTitle: active ? 'Shannon bounded active ZAP scan' : 'Shannon passive ZAP scan',
    },
  });
  const plan = {
    env: {
      contexts: [
        {
          name: 'shannon-target',
          urls: [target],
          includePaths: [`${targetUrl.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}.*`],
        },
      ],
      parameters: { failOnError: true, failOnWarning: false, progressToStdout: true },
    },
    jobs,
  };
  const planPath = path.join(modulesDir, `.${reportName}-plan.yaml`);
  await fs.writeFile(planPath, yaml.dump(plan, { noRefs: true }), { mode: 0o600 });
  return planPath;
}

async function runDast(
  options: AssessmentModuleRunOptions,
  modulesDir: string,
  commandRunner: ModuleCommandRunner,
): Promise<ModuleCheckEvidence[]> {
  const assetsDir = path.join(modulesDir, 'automated-dast');
  await ensureDirectory(assetsDir);
  const target = new URL(options.webUrl).href;
  const env = scannerEnvironment(options.authenticationCookie);
  const nucleiConfig = await writeNucleiAuthConfig(modulesDir, options.authenticationCookie);
  const nucleiTargetFile = await writeNucleiTargetFile(modulesDir, target);
  const passivePlan = await writeZapAutomationPlan(
    modulesDir,
    assetsDir,
    target,
    options.moduleSafety,
    false,
    Boolean(options.authenticationCookie),
  );
  const activePlan = options.moduleSafety.allowActiveDast
    ? await writeZapAutomationPlan(
        modulesDir,
        assetsDir,
        target,
        options.moduleSafety,
        true,
        Boolean(options.authenticationCookie),
      )
    : undefined;
  const checks: ModuleCheckEvidence[] = [];
  try {
    checks.push(
      await commandCheck(
        'zap-passive',
        {
          command: 'zap.sh',
          args: ['-cmd', '-autorun', passivePlan],
          cwd: options.workingDirectory,
          ...(env && { env }),
          timeoutMs: 20 * 60_000,
          acceptableExitCodes: [0, 2],
        },
        commandRunner,
        'modules/automated-dast/zap-passive.json',
      ),
    );
    checks.push(
      await commandCheck(
        'nuclei-curated',
        {
          command: 'nuclei',
          args: buildNucleiArgs(
            nucleiTargetFile,
            options.moduleSafety,
            path.join(assetsDir, 'nuclei.jsonl'),
            nucleiConfig,
          ),
          cwd: options.workingDirectory,
          timeoutMs: 20 * 60_000,
          acceptableExitCodes: [0],
        },
        commandRunner,
        'modules/automated-dast/nuclei.jsonl',
      ),
    );
    if (activePlan) {
      checks.push(
        await commandCheck(
          'zap-active',
          {
            command: 'zap.sh',
            args: ['-cmd', '-autorun', activePlan],
            cwd: options.workingDirectory,
            ...(env && { env }),
            timeoutMs: 30 * 60_000,
            acceptableExitCodes: [0, 2],
          },
          commandRunner,
          'modules/automated-dast/zap-active.json',
        ),
      );
    } else {
      checks.push({ id: 'zap-active', status: 'skipped', summary: 'Active DAST was not authorized' });
    }
  } finally {
    if (options.authenticationCookie) {
      for (const filename of ['zap-passive.json', 'nuclei.jsonl', 'zap-active.json']) {
        const artifactPath = path.join(assetsDir, filename);
        try {
          const stat = await fs.stat(artifactPath);
          if (stat.size > 50 * 1024 * 1024) continue;
          const content = await fs.readFile(artifactPath, 'utf8');
          await atomicWrite(
            artifactPath,
            redactSecrets(content, { exactValues: [options.authenticationCookie], redactPii: false }),
          );
        } catch {
          // The scanner may not produce a report when unavailable or when it fails early.
        }
      }
    }
    if (nucleiConfig) await fs.rm(nucleiConfig, { force: true });
    await fs.rm(nucleiTargetFile, { force: true });
    await fs.rm(passivePlan, { force: true });
    if (activePlan) await fs.rm(activePlan, { force: true });
  }
  return checks;
}

async function lockfileReview(workingDirectory: string): Promise<ModuleCheckEvidence> {
  const lockfiles = ['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'bun.lock', 'bun.lockb'];
  const present: string[] = [];
  let insecureSources = 0;
  let gitSources = 0;
  for (const filename of lockfiles) {
    const file = path.join(workingDirectory, filename);
    if (!(await fileExists(file))) continue;
    present.push(filename);
    const stat = await fs.stat(file);
    if (stat.size > 10 * 1024 * 1024) continue;
    const content = await fs.readFile(file, 'utf8');
    insecureSources += content.match(/\bhttp:\/\//g)?.length ?? 0;
    gitSources += content.match(/\bgit(?:\+|:)/g)?.length ?? 0;
  }
  return {
    id: 'lockfile-review',
    status: insecureSources > 0 || gitSources > 0 ? 'finding' : 'passed',
    summary: `${present.length} lockfile(s) reviewed; ${insecureSources} insecure URL(s), ${gitSources} git source(s)`,
  };
}

function packageAuditSpec(workingDirectory: string): ModuleCommandSpec | undefined {
  const choices: Array<{ file: string; command: string; args: string[] }> = [
    { file: 'pnpm-lock.yaml', command: 'pnpm', args: ['audit', '--json'] },
    { file: 'package-lock.json', command: 'npm', args: ['audit', '--json'] },
    { file: 'yarn.lock', command: 'yarn', args: ['npm', 'audit', '--json'] },
  ];
  const selected = choices.find(
    ({ file }) => path.isAbsolute(workingDirectory) && requireFile(path.join(workingDirectory, file)),
  );
  return selected
    ? {
        command: selected.command,
        args: selected.args,
        cwd: workingDirectory,
        acceptableExitCodes: [0, 1],
        timeoutMs: 10 * 60_000,
      }
    : undefined;
}

function requireFile(file: string): boolean {
  try {
    return Boolean(process.getBuiltinModule('node:fs').existsSync(file));
  } catch {
    return false;
  }
}

async function runSupplyChain(
  options: AssessmentModuleRunOptions,
  modulesDir: string,
  commandRunner: ModuleCommandRunner,
): Promise<ModuleCheckEvidence[]> {
  const assetsDir = path.join(modulesDir, 'supply-chain');
  await ensureDirectory(assetsDir);
  const checks: ModuleCheckEvidence[] = [await lockfileReview(options.workingDirectory)];
  const audit = packageAuditSpec(options.workingDirectory);
  checks.push(
    audit
      ? await commandCheck('package-audit', audit, commandRunner)
      : { id: 'package-audit', status: 'skipped', summary: 'No supported JavaScript lockfile found' },
  );
  checks.push(
    await commandCheck(
      'secret-scan',
      {
        command: 'gitleaks',
        args: [
          'detect',
          '--source',
          options.workingDirectory,
          '--no-git',
          '--redact',
          '--report-format',
          'json',
          '--report-path',
          path.join(assetsDir, 'gitleaks.json'),
        ],
        cwd: options.workingDirectory,
        acceptableExitCodes: [0, 1],
      },
      commandRunner,
      'modules/supply-chain/gitleaks.json',
    ),
  );

  const dependabot = await fileExists(path.join(options.workingDirectory, '.github', 'dependabot.yml'));
  const workflowsDir = path.join(options.workingDirectory, '.github', 'workflows');
  let codeqlWorkflow = false;
  try {
    const workflowFiles = await fs.readdir(workflowsDir);
    for (const filename of workflowFiles) {
      const content = await fs.readFile(path.join(workflowsDir, filename), 'utf8');
      if (content.includes('github/codeql-action')) codeqlWorkflow = true;
    }
  } catch {
    // Missing workflow directory is a reportable configuration finding.
  }
  checks.push({
    id: 'repository-security-configuration',
    status: dependabot && codeqlWorkflow ? 'passed' : 'finding',
    summary: `Dependabot: ${dependabot ? 'configured' : 'missing'}; CodeQL workflow: ${codeqlWorkflow ? 'configured' : 'missing'}`,
  });

  const codeqlDb = path.join(modulesDir, '.codeql-db');
  const codeqlCreate = await commandCheck(
    'codeql-database',
    {
      command: 'codeql',
      args: [
        'database',
        'create',
        codeqlDb,
        '--language=javascript-typescript',
        `--source-root=${options.workingDirectory}`,
        '--overwrite',
      ],
      cwd: options.workingDirectory,
      timeoutMs: 30 * 60_000,
    },
    commandRunner,
  );
  if (codeqlCreate.status === 'passed') {
    checks.push(
      await commandCheck(
        'codeql-analysis',
        {
          command: 'codeql',
          args: [
            'database',
            'analyze',
            codeqlDb,
            'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
            '--format=sarif-latest',
            `--output=${path.join(assetsDir, 'codeql.sarif')}`,
          ],
          cwd: options.workingDirectory,
          timeoutMs: 30 * 60_000,
        },
        commandRunner,
        'modules/supply-chain/codeql.sarif',
      ),
    );
  } else {
    checks.push({ id: 'codeql-analysis', status: codeqlCreate.status, summary: codeqlCreate.summary });
  }
  await fs.rm(codeqlDb, { recursive: true, force: true });
  return checks;
}

async function runLoad(
  options: AssessmentModuleRunOptions,
  modulesDir: string,
  commandRunner: ModuleCommandRunner,
): Promise<ModuleCheckEvidence[]> {
  const assetsDir = path.join(modulesDir, 'http-load-capacity');
  await ensureDirectory(assetsDir);
  const stages = buildK6Stages(options.moduleSafety.maxConcurrency, options.moduleSafety.loadStageDurationSeconds);
  const thresholds = {
    http_req_failed: [
      {
        threshold: `rate<${options.moduleSafety.loadErrorRateThreshold}`,
        abortOnFail: true,
        delayAbortEval: '10s',
      },
    ],
    http_req_duration: [
      {
        threshold: `p(95)<${options.moduleSafety.loadP95LatencyMsThreshold}`,
        abortOnFail: true,
        delayAbortEval: '10s',
      },
    ],
  };
  const scriptPath = path.resolve(import.meta.dirname, '../../scripts/k6-controlled-load.js');
  return [
    await commandCheck(
      'k6-controlled-ramp',
      {
        command: 'k6',
        args: ['run', '--quiet', '--summary-export', path.join(assetsDir, 'summary.json'), scriptPath],
        cwd: options.workingDirectory,
        env: {
          SHANNON_TARGET_URL: new URL(options.webUrl).href,
          SHANNON_K6_STAGES: JSON.stringify(stages),
          SHANNON_K6_THRESHOLDS: JSON.stringify(thresholds),
          SHANNON_MAX_REQUESTS_PER_SECOND: String(options.moduleSafety.maxRequestsPerSecond),
          ...(options.authenticationCookie && { SHANNON_AUTH_COOKIE: options.authenticationCookie }),
        },
        timeoutMs: stages.length * options.moduleSafety.loadStageDurationSeconds * 1_000 + 60_000,
      },
      commandRunner,
      'modules/http-load-capacity/summary.json',
    ),
  ];
}

async function writeEvidence(
  options: AssessmentModuleRunOptions,
  module: AssessmentModule,
  checks: readonly ModuleCheckEvidence[],
  startedAt: Date,
  completedAt: Date,
): Promise<ModuleExecutionResult> {
  const status = aggregateStatus(checks);
  const relativePath = `modules/${module}.json`;
  const evidence: ModuleEvidence = {
    schema_version: 1,
    module,
    status,
    target: sanitizeUrlForDiagnostics(options.webUrl),
    started_at: startedAt.toISOString(),
    completed_at: completedAt.toISOString(),
    safety: {
      target_environment: options.moduleSafety.targetEnvironment,
      max_requests_per_second: options.moduleSafety.maxRequestsPerSecond,
      max_concurrency: options.moduleSafety.maxConcurrency,
    },
    checks: redactSecrets(checks, { exactValues: [options.authenticationCookie] }),
  };
  await atomicWrite(path.join(options.deliverablesPath, relativePath), evidence);
  return { id: module, status, evidencePath: relativePath };
}

/** Execute selected methods sequentially and persist evidence before returning coverage results. */
export async function runAssessmentModules(
  options: AssessmentModuleRunOptions,
  dependencies: AssessmentModuleRunnerDependencies = {},
): Promise<ModuleExecutionResult[]> {
  const normalized = normalizeAssessmentModules({
    assessmentModules: options.assessmentModules,
    moduleSafety: options.moduleSafety,
    sourceMode: options.sourceMode,
  });
  const normalizedOptions: AssessmentModuleRunOptions = {
    ...options,
    assessmentModules: normalized.assessmentModules,
    moduleSafety: normalized.moduleSafety,
  };
  const commandRunner = dependencies.commandRunner ?? defaultCommandRunner;
  const fetchImpl = dependencies.fetch ?? fetch;
  const now = dependencies.now ?? (() => new Date());
  const modulesDir = path.join(options.deliverablesPath, 'modules');
  await ensureDirectory(modulesDir);
  const results: ModuleExecutionResult[] = [];

  for (const module of normalized.assessmentModules) {
    const startedAt = now();
    let checks: ModuleCheckEvidence[];
    switch (module) {
      case 'passive-exposure':
        checks = await runPassiveExposure(normalizedOptions, fetchImpl);
        break;
      case 'automated-dast':
        checks = await runDast(normalizedOptions, modulesDir, commandRunner);
        break;
      case 'supply-chain':
        checks = await runSupplyChain(normalizedOptions, modulesDir, commandRunner);
        break;
      case 'http-load-capacity':
        checks = await runLoad(normalizedOptions, modulesDir, commandRunner);
        break;
    }
    results.push(await writeEvidence(normalizedOptions, module, checks, startedAt, now()));
  }

  await atomicWrite(path.join(modulesDir, 'manifest.json'), {
    schema_version: 1,
    selected_modules: normalized.assessmentModules,
    results,
  });
  return results;
}
