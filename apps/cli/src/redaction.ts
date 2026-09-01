const SENSITIVE_KEY = /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)/i;
const INLINE_SECRET_PATTERNS = [
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b(?:xox[pbar]-|gh[pousr]_|sk-ant-|sk-proj-|sk-or-v1-|sk-or-)[A-Za-z0-9._~+/=-]{12,}\b/g,
  /(bearer\s+)[a-z0-9._~+/=-]+/gi,
  /(basic\s+)[a-z0-9._~+/=-]+/gi,
  /((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,;]+/gi,
  /([?&](?:password|passwd|secret|token|api[_-]?key)=)[^&#\s]+/gi,
  /(cookie\s*:\s*)[^\r\n]+/gi,
  /(set-cookie\s*:\s*)[^\r\n]+/gi,
] as const;
const PII_PATTERNS = [
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  /\b\d{3}-\d{2}-\d{4}\b/g,
  /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
] as const;

export const REDACTED = '[REDACTED]';

export class SecretRedactor {
  private readonly secrets: string[];

  constructor(secrets: Iterable<string | undefined> = []) {
    this.secrets = [...secrets]
      .filter((value): value is string => typeof value === 'string' && value.length >= 3)
      .sort((left, right) => right.length - left.length);
  }

  redactText(value: string): string {
    let redacted = value;
    for (const secret of this.secrets) redacted = redacted.split(secret).join(REDACTED);
    for (const pattern of INLINE_SECRET_PATTERNS) {
      redacted = redacted.replace(pattern, (...args: string[]) => {
        const firstCapture = args.length > 2 ? args[1] : undefined;
        return typeof firstCapture === 'string' && firstCapture.length > 0 ? `${firstCapture}${REDACTED}` : REDACTED;
      });
    }
    for (const pattern of PII_PATTERNS) redacted = redacted.replace(pattern, REDACTED);
    return redacted;
  }

  redactValue(value: unknown, seen = new WeakSet<object>()): unknown {
    if (typeof value === 'string') return this.redactText(value);
    if (Array.isArray(value)) return value.map((entry) => this.redactValue(entry, seen));
    if (!value || typeof value !== 'object') return value;
    if (seen.has(value)) return '[Circular]';
    seen.add(value);

    const output: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      output[key] = SENSITIVE_KEY.test(key) ? REDACTED : this.redactValue(entry, seen);
    }
    return output;
  }
}

export function safeErrorMessage(error: unknown, redactor = new SecretRedactor()): string {
  const message = error instanceof Error ? error.message : String(error);
  return redactor
    .redactText(message)
    .replace(/[\r\n]+/g, ' ')
    .slice(0, 1000);
}

export function sanitizeReportMarkdown(markdown: string, redactor = new SecretRedactor()): string {
  const withoutDangerousBlocks = markdown.replace(
    /<(script|style|iframe|object|embed|form|svg|math)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,
    '',
  );
  const withoutHtml = withoutDangerousBlocks.replace(/<[^>]+>/g, '');
  const withoutJavascriptLinks = withoutHtml.replace(/\]\(\s*javascript:[^)]+\)/gi, '](#)');
  return redactor.redactText(withoutJavascriptLinks.replace(/\0/g, ''));
}
