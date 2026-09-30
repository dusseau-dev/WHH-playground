export const REDACTION_MARKER = '[REDACTED]';

/**
 * Return a URL suitable for diagnostics without URL-embedded credentials.
 * The original value remains available to request code; only this display copy
 * drops userinfo, query parameters, and fragments.
 */
export function sanitizeUrlForDiagnostics(value: string): string {
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.href;
  } catch {
    return '[invalid URL]';
  }
}

export interface RedactSecretsOptions {
  /** Exact runtime secrets to redact in addition to pattern and key based matches. */
  readonly exactValues?: ReadonlyArray<string | undefined>;
  /** Redaction is enabled by default; this exists for tests and controlled internal callers. */
  readonly enabled?: boolean;
  /** Replacement text used for redacted values. */
  readonly marker?: string;
  /** Override the default sensitive-key matcher for object values. */
  readonly sensitiveKeyPattern?: RegExp;
  /** Redact common PII patterns such as emails, US phone numbers, and SSNs. Default: true. */
  readonly redactPii?: boolean;
}

const DEFAULT_SENSITIVE_KEY_PATTERN =
  /(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|credential|session|totp|private[_-]?key)/i;

const SECRET_PATTERNS: readonly RegExp[] = [
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b(?:xox[pbar]-|gh[pousr]_|sk-ant-|sk-proj-|sk-or-v1-|sk-or-)[A-Za-z0-9._~+/=-]{12,}\b/g,
  /(bearer\s+)[A-Za-z0-9._~+/=-]+/gi,
  /(basic\s+)[A-Za-z0-9._~+/=-]+/gi,
  /((?:password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*)[^\s,;]+/gi,
  /([?&](?:password|passwd|pwd|secret|token|api[_-]?key|authorization)=)[^&#\s]+/gi,
  /(cookie\s*:\s*)[^\r\n]+/gi,
  /(set-cookie\s*:\s*)[^\r\n]+/gi,
];

const PII_PATTERNS: readonly RegExp[] = [
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  /\b\d{3}-\d{2}-\d{4}\b/g,
  /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
];

function uniqueSecrets(values: ReadonlyArray<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => typeof value === 'string' && value.length >= 3))].sort(
    (a, b) => b.length - a.length,
  );
}

function redactText(
  value: string,
  options: Required<Pick<RedactSecretsOptions, 'marker' | 'redactPii'>> & RedactSecretsOptions,
): string {
  let redacted = value;
  for (const secret of uniqueSecrets(options.exactValues ?? [])) {
    redacted = redacted.split(secret).join(options.marker);
  }
  for (const pattern of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, (...args: string[]) => {
      const firstCapture = args.length > 2 ? args[1] : undefined;
      return typeof firstCapture === 'string' && firstCapture.length > 0
        ? `${firstCapture}${options.marker}`
        : options.marker;
    });
  }
  if (options.redactPii) {
    for (const pattern of PII_PATTERNS) redacted = redacted.replace(pattern, options.marker);
  }
  return redacted;
}

function normalizeOptions(
  options: RedactSecretsOptions = {},
): Required<Pick<RedactSecretsOptions, 'enabled' | 'marker' | 'redactPii' | 'sensitiveKeyPattern'>> &
  RedactSecretsOptions {
  return {
    enabled: options.enabled ?? true,
    marker: options.marker ?? REDACTION_MARKER,
    redactPii: options.redactPii ?? true,
    sensitiveKeyPattern: options.sensitiveKeyPattern ?? DEFAULT_SENSITIVE_KEY_PATTERN,
    ...(options.exactValues !== undefined && { exactValues: options.exactValues }),
  };
}

function redactUnknown(value: unknown, options: ReturnType<typeof normalizeOptions>, seen: WeakSet<object>): unknown {
  if (!options.enabled) return value;
  if (typeof value === 'string') return redactText(value, options);
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);

  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactText(value.message, options),
      ...(value.stack && { stack: redactText(value.stack, options) }),
    };
  }
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((entry) => redactUnknown(entry, options, seen));

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      options.sensitiveKeyPattern.test(key) ? options.marker : redactUnknown(entry, options, seen),
    ]),
  );
}

/**
 * Redact secrets and common PII from strings or structured log-like values.
 *
 * The input value is never mutated. Objects are cloned, circular references are
 * replaced with `[Circular]`, and `Error` objects are converted to plain objects
 * with redacted message and stack fields.
 */
export function redactSecrets<T>(value: T, options?: RedactSecretsOptions): T {
  const normalized = normalizeOptions(options);
  return redactUnknown(value, normalized, new WeakSet<object>()) as T;
}

/** Redact and flatten a value for single-line log/error contexts. */
export function redactLogText(value: unknown, options?: RedactSecretsOptions): string {
  const text = typeof value === 'string' ? value : value instanceof Error ? value.message : String(value);
  return redactSecrets(text, options).replace(/[\r\n]+/g, ' ');
}
