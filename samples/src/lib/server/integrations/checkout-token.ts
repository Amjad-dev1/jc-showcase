import "server-only";
import { createHmac, timingSafeEqual } from "node:crypto";
import { authConfig } from "../config";

/**
 * The signed checkout token.
 *
 * This binds `{ orderId, eventId, sessionId }` to a short-lived HMAC so the
 * payment callback can be trusted without the client telling us anything about
 * the payment.
 *
 * > **What legacy did.** It serialized the registration form into
 * > `localStorage`, redirected to the gateway, and compared query-string values
 * > against `localStorage` **in JavaScript** to decide whether the callback was
 * > legitimate. Every part of that was forgeable.
 *
 * The token proves only one thing: *this browser started this specific checkout
 * session*. It is deliberately not evidence of payment - verification requires
 * the outcome to come from MPGS's own API, and this token merely says which
 * order to ask about.
 */

const TOKEN_VERSION = "v1";
/** One hour, matching the `pending_registrations.expires_at` window. */
const TOKEN_TTL_MS = 60 * 60 * 1000;

export interface CheckoutTokenPayload {
  orderId: string;
  eventId: number;
  sessionId: string;
}

interface SignedPayload extends CheckoutTokenPayload {
  /** Expiry, so a leaked token stops working rather than lasting forever. */
  exp: number;
}

function base64Url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(input: string): Buffer {
  return Buffer.from(input.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function sign(body: string): string {
  // Reuses AUTH_SECRET: it is already a required, rotated, high-entropy secret,
  // and introducing a second one is a second thing to forget to set.
  return base64Url(createHmac("sha256", authConfig().secret).update(body).digest());
}

export function createCheckoutToken(payload: CheckoutTokenPayload): string {
  const signed: SignedPayload = { ...payload, exp: Date.now() + TOKEN_TTL_MS };
  const body = base64Url(JSON.stringify(signed));
  return `${TOKEN_VERSION}.${body}.${sign(body)}`;
}

/**
 * Verifies a token, returning its payload or `null`.
 *
 * Returns `null` for every failure mode - bad format, wrong signature, expired -
 * so a caller cannot accidentally treat "expired" differently from "forged".
 * The caller maps `null` to `403 INVALID_CALLBACK`.
 */
export function verifyCheckoutToken(token: string): CheckoutTokenPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [version, body, signature] = parts;
  if (version !== TOKEN_VERSION) return null;

  const expected = sign(body);
  const expectedBuffer = fromBase64Url(expected);
  const providedBuffer = fromBase64Url(signature);

  // Length must match before `timingSafeEqual`, which throws on mismatched
  // buffers rather than returning false.
  if (expectedBuffer.length !== providedBuffer.length) return null;
  // Constant-time: a byte-by-byte `===` would let an attacker discover a valid
  // signature one character at a time by measuring response latency.
  if (!timingSafeEqual(expectedBuffer, providedBuffer)) return null;

  let parsed: SignedPayload;
  try {
    parsed = JSON.parse(fromBase64Url(body).toString("utf8")) as SignedPayload;
  } catch {
    return null;
  }

  if (typeof parsed.exp !== "number" || parsed.exp < Date.now()) return null;
  if (!parsed.orderId || !parsed.eventId) return null;

  return {
    orderId: parsed.orderId,
    eventId: parsed.eventId,
    sessionId: parsed.sessionId,
  };
}
