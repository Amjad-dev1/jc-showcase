import { describe, expect, it, vi } from "vitest";
import {
  createCheckoutToken,
  verifyCheckoutToken,
} from "@/lib/server/integrations/checkout-token";
import { mapOrderResponse, generateOrderId } from "@/lib/server/integrations/mpgs";
import { escapeHtml, escapeHtmlWithBreaks } from "@/lib/server/integrations/mail";
import { contactNotificationEmail } from "@/lib/server/integrations/mail-templates";
import { __testing } from "@/lib/server/logger";
import { AppError, ERROR_CODES } from "@/lib/shared/errors";
import { translatePgError } from "@/lib/server/repositories/errors";

/**
 * Security controls.
 *
 * Each block corresponds to a specific legacy defect the rewrite was required to
 * correct, so a regression here is a regression to a known-vulnerable
 * behaviour rather than an abstract quality problem.
 */

describe("checkout token", () => {
  const payload = { orderId: "42-abc123def456", eventId: 42, sessionId: "SESSION0001" };

  it("round-trips a valid token", () => {
    const token = createCheckoutToken(payload);
    expect(verifyCheckoutToken(token)).toEqual(payload);
  });

  it("rejects a tampered payload", () => {
    const token = createCheckoutToken(payload);
    const [version, body, signature] = token.split(".");

    // Re-encode the payload with a different order ID but keep the signature.
    // This is precisely the legacy attack: the old flow compared query-string
    // values against localStorage in client JavaScript, so swapping an order ID
    // was trivial. Here the HMAC covers the payload.
    const forged = Buffer.from(
      JSON.stringify({ ...payload, orderId: "99-attacker", exp: Date.now() + 60_000 }),
    )
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    expect(verifyCheckoutToken(`${version}.${forged}.${signature}`)).toBeNull();
    expect(body).not.toBe(forged);
  });

  it("rejects a tampered signature", () => {
    const token = createCheckoutToken(payload);
    const [version, body] = token.split(".");
    expect(verifyCheckoutToken(`${version}.${body}.AAAABBBBCCCC`)).toBeNull();
  });

  it("rejects malformed tokens without throwing", () => {
    // Every failure mode returns null so a caller cannot distinguish "expired"
    // from "forged" and treat one leniently.
    for (const bad of ["", "a", "a.b", "a.b.c.d", "v2.abc.def"]) {
      expect(verifyCheckoutToken(bad)).toBeNull();
    }
  });

  it("rejects an expired token", () => {
    const token = createCheckoutToken(payload);
    // One hour and a minute later - past the TTL.
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 61 * 60 * 1000);
    expect(verifyCheckoutToken(token)).toBeNull();
    vi.restoreAllMocks();
  });
});

describe("MPGS order mapping", () => {
  it("treats SUCCESS + CAPTURED as paid", () => {
    expect(
      mapOrderResponse("order-1", {
        result: "SUCCESS",
        status: "CAPTURED",
        amount: 750,
        currency: "USD",
      }),
    ).toEqual({
      state: "PAID",
      amount: "750.00",
      currency: "USD",
      orderId: "order-1",
    });
  });

  it("does NOT treat SUCCESS alone as paid", () => {
    // The single most important branch in the payment flow: an authorised but
    // uncaptured order has taken no money.
    for (const status of ["AUTHORIZED", "PENDING", "INITIATED", ""]) {
      const outcome = mapOrderResponse("order-1", { result: "SUCCESS", status });
      expect(outcome.state).toBe("PENDING_REVIEW");
    }
  });

  it("treats failures and cancellations as failed", () => {
    for (const result of ["FAILURE", "CANCELLED", "ERROR", ""]) {
      const outcome = mapOrderResponse("order-1", { result, status: "CAPTURED" });
      expect(outcome.state).toBe("FAILED");
    }
  });
});

describe("order ID generation", () => {
  it("is prefixed with the event ID and within the column limit", () => {
    const orderId = generateOrderId(42);
    expect(orderId).toMatch(/^42-[0-9a-f]{20}$/);
    // The column is varchar(50).
    expect(orderId.length).toBeLessThanOrEqual(50);
  });

  it("does not collide across many generations", () => {
    // Uniqueness comes from crypto randomness plus the unique constraint, not
    // from legacy's mt_rand + SELECT COUNT(*) pre-check loop.
    const ids = new Set(Array.from({ length: 5_000 }, () => generateOrderId(1)));
    expect(ids.size).toBe(5_000);
  });
});

describe("email HTML escaping", () => {
  it("escapes markup in interpolated values", () => {
    expect(escapeHtml('<script>alert("x")</script>')).toBe(
      "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;",
    );
  });

  it("escapes before converting newlines to breaks", () => {
    // The order matters: converting first would leave the injected markup
    // unescaped around a legitimate <br>.
    expect(escapeHtmlWithBreaks("line1\n<b>line2</b>")).toBe(
      "line1<br>&lt;b&gt;line2&lt;/b&gt;",
    );
  });

  it("neutralises an injection attempt in a contact message", () => {
    // Legacy interpolated client-supplied HTML straight into outgoing mail.
    const message = contactNotificationEmail(
      {
        name: '<img src=x onerror="alert(1)">',
        email: "attacker@example.com",
        message: "</div><script>steal()</script>",
      },
      "support@example.com",
    );

    // The property that matters is that no attacker-supplied *tag* survives:
    // the payload is still present as inert escaped text, which is correct.
    expect(message.html).not.toContain("<script>");
    expect(message.html).not.toContain("<img");
    expect(message.html).toContain("&lt;script&gt;");
    expect(message.html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");

    // Only the markup this template itself emits may appear as real tags.
    const tags = [...message.html.matchAll(/<\/?([a-zA-Z][\w-]*)/g)].map((m) => m[1]);
    expect(new Set(tags)).toEqual(new Set(["div", "strong", "br"]));
  });
});

describe("PII redaction in logs", () => {
  it("redacts sensitive keys entirely", () => {
    const redacted = __testing.redact({
      email: "jane@example.com",
      mobile: "+96170123456",
      password: "hunter2",
      checkoutToken: "v1.abc.def",
      fullName: "Jane Doe",
    }) as Record<string, unknown>;

    expect(redacted.email).toBe("[redacted]");
    expect(redacted.mobile).toBe("[redacted]");
    expect(redacted.password).toBe("[redacted]");
    expect(redacted.checkoutToken).toBe("[redacted]");
    // A name is not in the sensitive-key list; it is not contact information.
    expect(redacted.fullName).toBe("Jane Doe");
  });

  it("masks an email that appears inside a free-text value", () => {
    // Redaction cannot rely on the key alone - addresses turn up inside
    // messages and error strings too.
    expect(__testing.redactString("Failed for jane@example.com")).toBe(
      "Failed for j***@example.com",
    );
  });

  it("masks phone-shaped digit runs in free text", () => {
    expect(__testing.redactString("called +961 70 123 456 twice")).toContain("[phone]");
  });

  it("redacts nested structures and error stacks", () => {
    const redacted = __testing.redact({
      payload: { registrant: { email: "deep@example.com" } },
    }) as { payload: { registrant: { email: string } } };

    expect(redacted.payload.registrant.email).toBe("[redacted]");

    const error = __testing.redact(new Error("failed for jane@example.com")) as {
      message: string;
    };
    expect(error.message).toBe("failed for j***@example.com");
  });

  it("survives deeply nested input without throwing", () => {
    // A logger must never be the thing that brings a request down.
    let deep: Record<string, unknown> = { value: 1 };
    for (let i = 0; i < 50; i += 1) deep = { nested: deep };
    expect(() => __testing.redact(deep)).not.toThrow();
  });
});

describe("database error translation", () => {
  it("maps the duplicate-registration constraint to a 409", () => {
    const translated = translatePgError({
      cause: { code: "23505", constraint: "uq_registrations_event_email" },
    });

    expect(translated).toBeInstanceOf(AppError);
    expect(translated?.code).toBe(ERROR_CODES.DUPLICATE_EMAIL_FOR_EVENT);
    expect(translated?.status).toBe(409);
  });

  it("maps a RESTRICT violation to RESOURCE_IN_USE", () => {
    // 23001, not 23503 - RESTRICT is checked immediately.
    const translated = translatePgError({ cause: { code: "23001" } });
    expect(translated?.code).toBe(ERROR_CODES.RESOURCE_IN_USE);
  });

  it("returns null for an unrecognised error so it becomes a generic 500", () => {
    // The detail is logged server-side; the client learns nothing. This is the
    // control that stops raw driver text reaching a response.
    expect(translatePgError(new Error("connection reset"))).toBeNull();
    expect(translatePgError({ cause: { code: "08006" } })).toBeNull();
  });

  it("never leaks database text into the envelope", () => {
    const translated = translatePgError({
      cause: {
        code: "23505",
        constraint: "uq_registrations_event_email",
        detail: "Key (event_id, email)=(42, jane@example.com) already exists.",
      },
    });

    const envelope = translated!.toEnvelope();
    expect(JSON.stringify(envelope)).not.toContain("jane@example.com");
    expect(JSON.stringify(envelope)).not.toContain("Key (event_id");
  });
});
