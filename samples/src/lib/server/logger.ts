import "server-only";

/**
 * Structured logging with PII redaction.
 *
 * The requirement is blunt: redact email and phone from all logs, including
 * platform request logs. Registration payloads carry names, emails and phone
 * numbers, and on Vercel anything written to stdout is retained by the
 * platform. So redaction cannot be a convention that call sites remember - it
 * has to be structural, which is why every value passed here goes through
 * `redact()` before serialisation and there is no escape hatch that bypasses it.
 *
 * Log lines are JSON so the platform can index them, and each carries a
 * `requestId` for tracing a single request across service and repository calls.
 */

type Level = "debug" | "info" | "warn" | "error";

/** Keys whose values are replaced wholesale, regardless of content. */
const SENSITIVE_KEYS = new Set([
  "email",
  "mail",
  "useremail",
  "customeremail",
  "mobile",
  "mobileintl",
  "phone",
  "tel",
  "password",
  "newpassword",
  "oldpassword",
  "confirmpassword",
  "passwordhash",
  "token",
  "checkouttoken",
  "authorization",
  "cookie",
  "secret",
  "apipassword",
  "cardnumber",
  "cvv",
  "turnstiletoken",
]);

const EMAIL_PATTERN = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
/** Long digit runs with optional separators - phone numbers and card-like values. */
const PHONE_PATTERN = /(?:\+?\d[\d\s()-]{6,}\d)/g;

/**
 * Partially masks an email so logs stay useful for correlation without
 * carrying the address itself: `jane@example.com` becomes `j***@example.com`.
 * Enough to tell two users apart in a trace; not enough to contact anyone.
 */
function maskEmail(value: string): string {
  const at = value.indexOf("@");
  if (at <= 0) return "[redacted]";
  return `${value[0]}***${value.slice(at)}`;
}

function redactString(value: string): string {
  return value
    .replace(EMAIL_PATTERN, (m) => maskEmail(m))
    .replace(PHONE_PATTERN, "[phone]");
}

/**
 * Recursively redacts a value. Depth-limited because log payloads occasionally
 * contain cyclic or very deep objects (a Drizzle row with relations, an Error
 * with a cause chain) and a logger must never be the thing that throws.
 */
function redact(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[depth-limit]";
  if (value === null || value === undefined) return value;

  if (typeof value === "string") return redactString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();

  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactString(value.message),
      // Stacks can embed interpolated values, so they are redacted too.
      stack: value.stack ? redactString(value.stack) : undefined,
    };
  }

  if (Array.isArray(value)) return value.map((entry) => redact(entry, depth + 1));

  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SENSITIVE_KEYS.has(key.toLowerCase())
        ? "[redacted]"
        : redact(entry, depth + 1);
    }
    return out;
  }

  return "[unserialisable]";
}

export interface LogContext {
  requestId?: string;
  route?: string;
  [key: string]: unknown;
}

function write(level: Level, message: string, context?: LogContext) {
  // Test runs stay quiet unless explicitly debugging; assertion output is the
  // signal there, and redaction is verified by its own unit tests.
  if (process.env.NODE_ENV === "test" && !process.env.LOG_IN_TESTS) return;

  const line = JSON.stringify({
    level,
    time: new Date().toISOString(),
    message: redactString(message),
    ...(context ? (redact(context) as Record<string, unknown>) : {}),
  });

  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export const logger = {
  debug: (message: string, context?: LogContext) => write("debug", message, context),
  info: (message: string, context?: LogContext) => write("info", message, context),
  warn: (message: string, context?: LogContext) => write("warn", message, context),
  error: (message: string, context?: LogContext) => write("error", message, context),
};

/** Exported for the unit tests that prove redaction actually holds. */
export const __testing = { redact, redactString, maskEmail };

/** Correlation ID for tracing one request through every layer it touches. */
export function newRequestId(): string {
  return crypto.randomUUID();
}
