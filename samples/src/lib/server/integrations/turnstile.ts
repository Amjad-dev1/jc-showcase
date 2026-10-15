import "server-only";
import { turnstileConfig } from "../config";
import { logger } from "../logger";

/**
 * Cloudflare Turnstile bot protection.
 *
 * Turnstile replaces reCAPTCHA entirely, replacing the legacy
 * system loaded reCAPTCHA **Enterprise** in the browser while verifying against
 * the **classic** `siteverify` endpoint - different products, different APIs,
 * different keys, so verification could never have worked as intended.
 *
 * > **The difference that matters: there is no `score`.** Turnstile returns a
 * > boolean. Any code carrying the legacy `score >= 0.5` threshold is wrong -
 * > It is deleted rather than ported. Accordingly nothing in this
 * > module reads a score, and `success === true` is the only accepting
 * > condition.
 */

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export interface TurnstileVerifier {
  verify(token: string, remoteIp?: string): Promise<boolean>;
}

interface SiteverifyResponse {
  success: boolean;
  hostname?: string;
  "error-codes"?: string[];
}

class HttpTurnstileVerifier implements TurnstileVerifier {
  async verify(token: string, remoteIp?: string): Promise<boolean> {
    const config = turnstileConfig();

    // Not configured: verification is skipped so local development and tests
    // can exercise the contact form. Keyed off configuration rather than
    // NODE_ENV so a production deploy missing the key is a visible
    // misconfiguration, not a silently open form.
    if (!config.enabled || !config.secretKey) {
      logger.warn("Turnstile not configured - skipping verification");
      return true;
    }

    if (!token) return false;

    // Form-encoded, as the endpoint requires; JSON is rejected.
    const body = new URLSearchParams({
      secret: config.secretKey,
      response: token,
    });
    // Include remoteip where available.
    if (remoteIp && remoteIp !== "unknown") body.set("remoteip", remoteIp);

    let response: Response;
    try {
      response = await fetch(SITEVERIFY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
        signal: AbortSignal.timeout(10_000),
      });
    } catch (error) {
      // Fail closed. Unlike rate limiting - where an outage degrades to
      // "unlimited" so the site keeps working - a Turnstile outage degrading to
      // "accept everything" would leave the contact form open to exactly the
      // abuse it exists to stop.
      logger.error("Turnstile verification request failed", { error });
      return false;
    }

    const payload = (await response.json().catch(() => null)) as SiteverifyResponse | null;

    if (!payload?.success) {
      logger.warn("Turnstile rejected a token", {
        errorCodes: payload?.["error-codes"],
      });
      return false;
    }

    // Validate the returned hostname matches our domain, so a token
    // solved on an attacker's site cannot be replayed against ours.
    if (config.expectedHostname && payload.hostname !== config.expectedHostname) {
      logger.warn("Turnstile hostname mismatch", { hostname: payload.hostname });
      return false;
    }

    return true;
  }
}

interface TurnstileGlobal {
  __jcTurnstile?: TurnstileVerifier;
}

const globalRef = globalThis as unknown as TurnstileGlobal;

export function getTurnstileVerifier(): TurnstileVerifier {
  if (!globalRef.__jcTurnstile) globalRef.__jcTurnstile = new HttpTurnstileVerifier();
  return globalRef.__jcTurnstile;
}

export function __setTurnstileVerifier(verifier: TurnstileVerifier | undefined) {
  globalRef.__jcTurnstile = verifier;
}
