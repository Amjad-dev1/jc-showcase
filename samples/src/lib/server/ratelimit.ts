import "server-only";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { rateLimitConfig } from "./config";
import { AppError, ERROR_CODES } from "../shared/errors";
import { logger } from "./logger";

/**
 * Rate limiting.
 *
 * **Why Redis and not a counter in module scope.** On Vercel each invocation may
 * run in a fresh instance with its own memory, so an in-process counter resets
 * constantly and the limit never actually applies. This is among the
 * new attack surfaces the stack introduces: "In-memory counters reset per
 * serverless instance, so limits never apply." Upstash is a shared store every
 * instance sees.
 *
 * The four required limiters are check-email, contact, payment-session and
 * admin sign-in. Check-email deserves the most attention - it is an
 * unauthenticated oracle revealing whether an address is registered for an
 * event, and throttling is the only thing standing between it and enumeration.
 *
 * When Upstash is not configured the limiter falls back to an in-process
 * counter that is explicitly labelled development-only. It is genuinely weaker,
 * so `assertRateLimitReady()` exists for a production start-up check that
 * refuses to pretend otherwise.
 */

type LimiterName = "checkEmail" | "contact" | "paymentSession" | "login";

interface LimitDecision {
  success: boolean;
  remaining: number;
  reset: number;
}

interface Limiter {
  limit(key: string): Promise<LimitDecision>;
}

/**
 * Development fallback: a fixed window held in module scope.
 *
 * Deliberately simple, because making it clever would disguise the fact that it
 * does not work across instances. It keeps local development and tests
 * functional without Redis and nothing more.
 */
class InMemoryLimiter implements Limiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  async limit(key: string): Promise<LimitDecision> {
    const now = Date.now();
    const entry = this.hits.get(key);

    if (!entry || entry.resetAt <= now) {
      const resetAt = now + this.windowMs;
      this.hits.set(key, { count: 1, resetAt });
      // Opportunistic sweep: without it the map grows unbounded across a long
      // dev session, since every distinct IP+event key gets an entry.
      if (this.hits.size > 5_000) {
        for (const [existingKey, value] of this.hits) {
          if (value.resetAt <= now) this.hits.delete(existingKey);
        }
      }
      return { success: true, remaining: this.max - 1, reset: resetAt };
    }

    entry.count += 1;
    return {
      success: entry.count <= this.max,
      remaining: Math.max(0, this.max - entry.count),
      reset: entry.resetAt,
    };
  }
}

interface LimiterGlobal {
  __jcLimiters?: Map<LimiterName, Limiter>;
}

const globalRef = globalThis as unknown as LimiterGlobal;

/** Window per limiter. */
const WINDOWS: Record<LimiterName, { window: `${number} ${"s" | "m" | "h"}`; ms: number }> = {
  checkEmail: { window: "1 m", ms: 60_000 },
  contact: { window: "1 h", ms: 3_600_000 },
  paymentSession: { window: "1 m", ms: 60_000 },
  login: { window: "15 m", ms: 900_000 },
};

function buildLimiter(name: LimiterName): Limiter {
  const config = rateLimitConfig();
  const max = config[name];
  const { window, ms } = WINDOWS[name];

  if (!config.enabled) {
    logger.warn("Rate limiter falling back to in-memory counters", { limiter: name });
    return new InMemoryLimiter(max, ms);
  }

  const redis = new Redis({ url: config.url!, token: config.token! });
  return new Ratelimit({
    redis,
    // Sliding window rather than fixed: a fixed window lets an attacker send
    // `max` requests at the end of one window and `max` more at the start of
    // the next, doubling the effective rate at the boundary.
    limiter: Ratelimit.slidingWindow(max, window),
    prefix: `jc:rl:${name}`,
    analytics: false,
  });
}

function getLimiter(name: LimiterName): Limiter {
  if (!globalRef.__jcLimiters) globalRef.__jcLimiters = new Map();
  let limiter = globalRef.__jcLimiters.get(name);
  if (!limiter) {
    limiter = buildLimiter(name);
    globalRef.__jcLimiters.set(name, limiter);
  }
  return limiter;
}

/**
 * Applies a limiter, throwing `429 RATE_LIMITED` when exceeded.
 *
 * A limiter outage must not take the site down, so a Redis failure is logged
 * and the request is allowed. That is a deliberate availability-over-strictness
 * trade: the endpoints behind these limits are also protected by validation,
 * Turnstile and authentication, so a brief unlimited window is survivable in a
 * way that a totally unreachable registration form is not.
 */
export async function enforceRateLimit(name: LimiterName, key: string): Promise<void> {
  try {
    const decision = await getLimiter(name).limit(key);
    if (!decision.success) {
      logger.warn("Rate limit exceeded", { limiter: name });
      throw new AppError(ERROR_CODES.RATE_LIMITED);
    }
  } catch (error) {
    if (error instanceof AppError) throw error;
    logger.error("Rate limiter unavailable - allowing request", {
      limiter: name,
      error,
    });
  }
}

/**
 * Extracts the client IP from the platform's forwarded header.
 *
 * Treat this as untrusted input - it is trivially spoofed by the caller
 * and must never be interpolated into SQL or written to a log unescaped. Here
 * it is only ever used as a rate-limit key, and it is truncated so an attacker
 * cannot blow up key cardinality with a very long header value.
 */
export function clientIpFrom(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for");
  // The left-most entry is the original client; the rest are proxies.
  const candidate = forwarded?.split(",")[0]?.trim() || headers.get("x-real-ip") || "unknown";
  return candidate.slice(0, 45);
}

/** Start-up check for production: refuses to run with the dev-only limiter. */
export function assertRateLimitReady(): void {
  if (!rateLimitConfig().enabled) {
    throw new Error(
      "Rate limiting requires UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN in production",
    );
  }
}

/** Lets tests install a deterministic limiter instead of a real one. */
export function __setTestLimiter(name: LimiterName, limiter: Limiter | undefined) {
  if (!globalRef.__jcLimiters) globalRef.__jcLimiters = new Map();
  if (limiter) globalRef.__jcLimiters.set(name, limiter);
  else globalRef.__jcLimiters.delete(name);
}

export type { Limiter, LimiterName };
