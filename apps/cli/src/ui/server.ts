import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { streamSSE } from 'hono/streaming';
import { z } from 'zod';
import {
  AssessmentConfigSchema,
  ProfileDraftSchema,
  type ProfileReference,
  REPORT_ARTIFACT_KINDS,
  type ReportArtifactKind,
  ResumeRunRequestSchema,
  type SecretReferences,
  StartRunRequestSchema,
  type TargetSecrets,
} from '../contracts.js';
import { loadEnv } from '../env.js';
import { describeConfiguredModel, listConfiguredModels } from '../model-catalog.js';
import { ProfileStore } from '../profiles.js';
import { safeErrorMessage } from '../redaction.js';
import { ScanController } from '../scan-controller.js';
import { createSecretStore } from '../secret-store.js';
import { pathExists, resolveExistingContainedPath } from '../storage.js';

const API_PREFIX = '/api/v1';
const SESSION_COOKIE = 'shannon_session';
const MAX_IMPORT_BYTES = 512 * 1024;
const DEFAULT_PORT = 8787;

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
};

const MIME_TYPES: Readonly<Record<string, string>> = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

export interface CreateAppOptions {
  controller: ScanController;
  profiles: ProfileStore;
  version?: string;
  assetsDir?: string;
  sessionToken?: string;
  csrfToken?: string;
  eventIntervalMs?: number;
}

export interface StartUiServerOptions {
  version: string;
  port?: number;
  open?: boolean;
  controller?: ScanController;
  profiles?: ProfileStore;
  assetsDir?: string;
}

export interface UiServerHandle {
  hostname: '127.0.0.1';
  port: number;
  url: string;
  close(): Promise<void>;
}

class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
  }
}

function defaultAssetsDir(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'ui');
}

function validHost(host: string): boolean {
  return /^(?:127\.0\.0\.1|localhost)(?::\d{1,5})?$/.test(host);
}

function validOrigin(origin: string, host: string): boolean {
  try {
    const parsed = new URL(origin);
    return parsed.protocol === 'http:' && parsed.host === host && validHost(parsed.host);
  } catch {
    return false;
  }
}

function isMutation(method: string): boolean {
  return method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
}

function contentType(filePath: string): string {
  return MIME_TYPES[path.extname(filePath).toLowerCase()] ?? 'application/octet-stream';
}

async function parseJson<T>(request: Request, schema: z.ZodType<T>): Promise<T> {
  const contentLength = Number(request.headers.get('content-length') ?? '0');
  if (contentLength > MAX_IMPORT_BYTES) throw new ApiError('Request body is too large', 413, 'body_too_large');
  try {
    return schema.parse(await request.json());
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof z.ZodError) {
      throw new ApiError(error.issues.map((issue) => issue.message).join('; '), 400, 'validation_error');
    }
    throw new ApiError('Request body must be valid JSON', 400, 'invalid_json');
  }
}

function mergeSecrets(primary: TargetSecrets, overrides: TargetSecrets | undefined): TargetSecrets {
  return { ...primary, ...overrides };
}

function openBrowser(url: string): void {
  const command = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  const child = spawn(command, args, { detached: true, stdio: 'ignore' });
  child.unref();
}

async function availablePort(start: number): Promise<number> {
  for (let port = start; port < start + 100; port++) {
    const available = await new Promise<boolean>((resolve) => {
      const tester = net.createServer();
      tester.once('error', () => resolve(false));
      tester.listen(port, '127.0.0.1', () => tester.close(() => resolve(true)));
    });
    if (available) return port;
  }
  throw new Error(`No available loopback port found from ${start}`);
}

export function createApp(options: CreateAppOptions): Hono {
  const app = new Hono();
  const controller = options.controller;
  const profiles = options.profiles;
  const assetsDir = options.assetsDir ?? defaultAssetsDir();
  const sessionToken = options.sessionToken ?? crypto.randomBytes(32).toString('base64url');
  const csrfToken = options.csrfToken ?? crypto.randomBytes(32).toString('base64url');
  const eventIntervalMs = options.eventIntervalMs ?? 2000;

  app.use('*', async (context, next) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) context.header(name, value);
    context.header(
      'Cache-Control',
      context.req.path.startsWith('/assets/') ? 'public, max-age=31536000, immutable' : 'no-store',
    );

    const host = context.req.header('host') ?? '';
    if (!validHost(host))
      return context.json({ error: { code: 'invalid_host', message: 'Loopback Host required' } }, 403);

    const bootstrap = context.req.path === `${API_PREFIX}/bootstrap`;
    const health = context.req.path === `${API_PREFIX}/health`;
    const spaRequest = !context.req.path.startsWith('/api/');
    const currentSession = getCookie(context, SESSION_COOKIE);

    if ((bootstrap || spaRequest) && currentSession !== sessionToken) {
      setCookie(context, SESSION_COOKIE, sessionToken, {
        httpOnly: true,
        path: '/',
        sameSite: 'Strict',
        secure: false,
      });
    } else if (!health && currentSession !== sessionToken) {
      return context.json({ error: { code: 'invalid_session', message: 'Local UI session required' } }, 401);
    }

    if (context.req.path.startsWith(API_PREFIX) && isMutation(context.req.method)) {
      const origin = context.req.header('origin') ?? '';
      if (!validOrigin(origin, host)) {
        return context.json({ error: { code: 'invalid_origin', message: 'Same-origin request required' } }, 403);
      }
      if (context.req.header('x-shannon-csrf') !== csrfToken) {
        return context.json({ error: { code: 'invalid_csrf', message: 'CSRF token is missing or invalid' } }, 403);
      }
    }
    return await next();
  });

  app.onError((error) => {
    const apiError = error instanceof ApiError ? error : new ApiError(safeErrorMessage(error), 500, 'internal_error');
    return new Response(JSON.stringify({ error: { code: apiError.code, message: safeErrorMessage(apiError) } }), {
      status: apiError.status,
      headers: { 'Content-Type': 'application/json; charset=utf-8', ...SECURITY_HEADERS },
    });
  });

  app.get(`${API_PREFIX}/health`, (context) =>
    context.json({ data: { status: 'ok', apiVersion: 1, bind: '127.0.0.1' } }),
  );

  app.get(`${API_PREFIX}/bootstrap`, async (context) =>
    context.json({
      data: {
        apiVersion: 1,
        csrfToken,
        version: options.version ?? 'development',
        platform: process.platform,
        secretStore: {
          persistence: profiles.secretPersistence,
          available: profiles.secretPersistence === 'keychain',
        },
        model: describeConfiguredModel(),
        profiles: await profiles.list(),
        runs: await controller.listRuns(),
      },
    }),
  );

  app.get(`${API_PREFIX}/models`, async (context) => {
    try {
      return context.json({ data: { provider: describeConfiguredModel(), items: await listConfiguredModels() } });
    } catch {
      throw new ApiError('The configured provider model catalog is unavailable', 502, 'model_catalog_unavailable');
    }
  });

  app.get(`${API_PREFIX}/profiles`, async (context) => context.json({ data: await profiles.list() }));
  app.get(`${API_PREFIX}/profiles/:id`, async (context) =>
    context.json({ data: await profiles.get(context.req.param('id')) }),
  );
  app.post(`${API_PREFIX}/profiles`, async (context) => {
    const draft = await parseJson(context.req.raw, ProfileDraftSchema);
    return context.json({ data: await profiles.create(draft) }, 201);
  });
  app.put(`${API_PREFIX}/profiles/:id`, async (context) => {
    const draft = await parseJson(context.req.raw, ProfileDraftSchema);
    return context.json({ data: await profiles.update(context.req.param('id'), draft) });
  });
  app.delete(`${API_PREFIX}/profiles/:id`, async (context) => {
    await profiles.delete(context.req.param('id'));
    return context.body(null, 204);
  });
  app.post(`${API_PREFIX}/profiles/import`, async (context) => {
    const body = await parseJson(context.req.raw, z.object({ yaml: z.string().min(1).max(MAX_IMPORT_BYTES) }).strict());
    try {
      return context.json({ data: await profiles.importYaml(body.yaml) }, 201);
    } catch (error) {
      throw new ApiError(`Profile YAML is invalid: ${safeErrorMessage(error)}`, 400, 'invalid_profile_yaml');
    }
  });
  app.get(`${API_PREFIX}/profiles/:id/export`, async (context) => {
    const id = context.req.param('id');
    return context.body(await profiles.exportYaml(id), 200, {
      'Content-Disposition': `attachment; filename="${id}.yaml"`,
      'Content-Type': 'application/yaml; charset=utf-8',
    });
  });

  app.get(`${API_PREFIX}/runs`, async (context) => context.json({ data: await controller.listRuns() }));
  app.post(`${API_PREFIX}/runs`, async (context) => {
    const request = await parseJson(context.req.raw, StartRunRequestSchema);
    let targetUrl = request.targetUrl;
    let sourceMode = request.sourceMode;
    let repoPath = request.repoPath;
    let config = request.config ?? AssessmentConfigSchema.parse({});
    let secrets = request.secrets ?? {};
    let profileRef: ProfileReference | undefined;
    let secretRefs: SecretReferences = {};

    if (request.profileId) {
      const resolved = await profiles.resolve(request.profileId);
      targetUrl ??= resolved.profile.targetUrl;
      sourceMode ??= resolved.profile.sourceMode;
      repoPath ??= resolved.profile.repoPath;
      if (!request.config) config = resolved.profile.config;
      secrets = mergeSecrets(resolved.secrets, request.secrets);
      profileRef = {
        id: resolved.profile.id,
        version: resolved.profile.version,
        updatedAt: resolved.profile.updatedAt,
      };
      secretRefs = resolved.secretRefs;
      const unresolved = resolved.missingSecretFields.filter((field) => !secrets[field]);
      if (unresolved.length > 0) {
        throw new ApiError(`Target secrets must be re-entered: ${unresolved.join(', ')}`, 409, 'missing_secrets');
      }
    }
    if (!targetUrl || !sourceMode)
      throw new ApiError('Target URL and source mode are required', 400, 'validation_error');

    const run = await controller.startRun({
      targetUrl,
      sourceMode,
      ...(repoPath && { repoPath }),
      ...(profileRef && { profileRef }),
      config,
      secrets,
      secretRefs,
      ...(request.providerConfig && { providerConfig: request.providerConfig }),
      ...(request.workspace && { workspace: request.workspace }),
      ...(request.outputPath && { outputPath: request.outputPath }),
      ...(request.pipelineTesting !== undefined && { pipelineTesting: request.pipelineTesting }),
      ...(request.debug !== undefined && { debug: request.debug }),
      authorizationConfirmed: request.authorizationConfirmed,
      ...(request.elevatedLoadConfirmed && { elevatedLoadConfirmed: true }),
    });
    return context.json({ data: run }, 202);
  });

  app.get(`${API_PREFIX}/runs/:id`, async (context) =>
    context.json({ data: await controller.getRunDetail(context.req.param('id')) }),
  );
  app.post(`${API_PREFIX}/runs/:id/cancel`, async (context) =>
    context.json({ data: await controller.cancelRun(context.req.param('id')) }),
  );
  app.post(`${API_PREFIX}/runs/:id/resume`, async (context) => {
    const request = await parseJson(context.req.raw, ResumeRunRequestSchema);
    try {
      return context.json(
        {
          data: await controller.resumeRun(context.req.param('id'), request.secrets ?? {}, request.providerConfig, {
            authorizationConfirmed: request.authorizationConfirmed === true,
            elevatedLoadConfirmed: request.elevatedLoadConfirmed === true,
          }),
        },
        202,
      );
    } catch (error) {
      const message = safeErrorMessage(error);
      if (message.includes('Target secrets must be supplied again') || message.includes('Provider credentials')) {
        throw new ApiError(message, 409, 'missing_secrets');
      }
      throw error;
    }
  });

  app.get(`${API_PREFIX}/runs/:id/events`, (context) => {
    const workspace = context.req.param('id');
    const lastEventId = Number(context.req.header('last-event-id') ?? '0');
    return streamSSE(context, async (stream) => {
      let offset = Number.isSafeInteger(lastEventId) && lastEventId >= 0 ? lastEventId : 0;
      let aborted = false;
      let lastHeartbeat = Date.now();
      stream.onAbort(() => {
        aborted = true;
      });

      while (!aborted) {
        const detail = await controller.getRunDetail(workspace);
        await stream.writeSSE({ event: 'snapshot', data: JSON.stringify(detail), id: String(offset) });
        const activity = await controller.readActivity(workspace, offset);
        if (activity.text) {
          offset = activity.offset;
          await stream.writeSSE({ event: 'activity', data: JSON.stringify(activity), id: String(offset) });
        }
        if (activity.done) break;
        if (Date.now() - lastHeartbeat >= 15_000) {
          await stream.writeSSE({ event: 'heartbeat', data: '{}', id: String(offset) });
          lastHeartbeat = Date.now();
        }
        await new Promise((resolve) => setTimeout(resolve, eventIntervalMs));
      }
    });
  });

  app.get(`${API_PREFIX}/runs/:id/report`, async (context) => {
    const report = await controller.getReport(context.req.param('id'));
    if (context.req.query('download') === '1') {
      return context.body(report.markdown, 200, {
        'Content-Disposition': `attachment; filename="${report.filename}"`,
        'Content-Type': 'text/markdown; charset=utf-8',
      });
    }
    return context.json({ data: report });
  });
  app.get(`${API_PREFIX}/runs/:id/reports/:kind`, async (context) => {
    const requestedKind = context.req.param('kind');
    if (!REPORT_ARTIFACT_KINDS.includes(requestedKind as ReportArtifactKind)) {
      throw new ApiError('Unknown report artifact kind', 404, 'not_found');
    }
    const kind = requestedKind as ReportArtifactKind;
    const contentTypes: Readonly<Record<ReportArtifactKind, string>> = {
      markdown: 'text/markdown; charset=utf-8',
      pdf: 'application/pdf',
      sarif: 'application/sarif+json; charset=utf-8',
    };
    if (kind === 'markdown') {
      const report = await controller.getReport(context.req.param('id'));
      return new Response(report.markdown, {
        headers: {
          'Content-Disposition': `attachment; filename="${report.filename}"`,
          'Content-Type': contentTypes.markdown,
          ...SECURITY_HEADERS,
        },
      });
    }

    const filePath = await controller.getReportArtifactPath(context.req.param('id'), kind);
    return new Response(await fs.readFile(filePath), {
      headers: {
        'Content-Disposition': `attachment; filename="${path.basename(filePath)}"`,
        'Content-Type': contentTypes[kind],
        ...SECURITY_HEADERS,
      },
    });
  });
  app.get(`${API_PREFIX}/runs/:id/artifacts/:filename`, async (context) => {
    const filePath = await controller.getArtifactPath(context.req.param('id'), context.req.param('filename'));
    const body = await fs.readFile(filePath);
    return new Response(body, {
      headers: {
        'Content-Disposition': `attachment; filename="${path.basename(filePath)}"`,
        'Content-Type': contentType(filePath),
        ...SECURITY_HEADERS,
      },
    });
  });

  app.get('*', async (context) => {
    const requestedPath = context.req.path === '/' ? 'index.html' : context.req.path.replace(/^\/+/, '');
    let filePath: string;
    try {
      filePath = await resolveExistingContainedPath(assetsDir, requestedPath);
    } catch {
      const indexPath = path.join(assetsDir, 'index.html');
      if (!(await pathExists(indexPath))) {
        throw new ApiError(
          'Shannon UI assets are not installed. Build the CLI web client first.',
          503,
          'ui_unavailable',
        );
      }
      filePath = await resolveExistingContainedPath(assetsDir, 'index.html');
    }
    return new Response(await fs.readFile(filePath), {
      headers: { 'Content-Type': contentType(filePath), ...SECURITY_HEADERS },
    });
  });

  return app;
}

export async function startUiServer(options: StartUiServerOptions): Promise<UiServerHandle> {
  loadEnv();
  const secretStore = await createSecretStore();
  const profiles = options.profiles ?? new ProfileStore({ secretStore });
  const controller =
    options.controller ??
    new ScanController({
      version: options.version,
      secretResolver: (references) => profiles.resolveSecretReferences(references),
    });
  await Promise.all([profiles.initialize(), controller.initialize()]);

  const port = await availablePort(options.port ?? DEFAULT_PORT);
  const hostname = '127.0.0.1' as const;
  const app = createApp({
    controller,
    profiles,
    version: options.version,
    ...(options.assetsDir && { assetsDir: options.assetsDir }),
  });
  const server = serve({ fetch: app.fetch, hostname, port });
  const url = `http://${hostname}:${port}`;
  if (options.open !== false) openBrowser(url);

  return {
    hostname,
    port,
    url,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}
