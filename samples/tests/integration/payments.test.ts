import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { setupTestDb, resetTestDb, teardownTestDb, testDb } from "../helpers/db";
import { createFullEvent } from "../helpers/fixtures";
import { FakeMpgsGateway } from "../helpers/fake-mpgs";
import { __setMpgsGateway } from "@/lib/server/integrations/mpgs";
import {
  createPaymentSession,
  verifyPayment,
} from "@/lib/server/services/payment-service";
import { createRegistration } from "@/lib/server/services/registration-service";
import { paymentSessionSchema, registrationSchema } from "@/lib/shared/schemas/public";
import { pendingRegistrations, registrations } from "@/lib/server/db/schema";
import { createCheckoutToken } from "@/lib/server/integrations/checkout-token";

/**
 * The secure payment flow.
 *
 * The acceptance criteria require that payment finalization is provably
 * idempotent under retry and duplicate callbacks. These tests are that proof:
 * they drive the real service against a real database with a programmable
 * gateway, and assert on row counts as well as return values - because the
 * failure mode that matters is a *second* registration, not a wrong response.
 */

let gateway: FakeMpgsGateway;

beforeAll(async () => {
  await setupTestDb();
});

afterAll(async () => {
  await teardownTestDb();
});

beforeEach(async () => {
  await resetTestDb();
  gateway = new FakeMpgsGateway();
  __setMpgsGateway(gateway);
});

afterEach(() => {
  __setMpgsGateway(undefined);
});

function paymentInput(eventId: number, overrides?: Record<string, unknown>) {
  return paymentSessionSchema.parse({
    eventId,
    title: "Dr.",
    firstName: "Jane",
    lastName: "Doe",
    mobile: "+961 70 123 456",
    mobileIntl: "+96170123456",
    email: "jane@example.com",
    ...overrides,
  });
}

describe("payment session creation", () => {
  it("stores the payload server-side and never returns it", async () => {
    const { event } = await createFullEvent({ paymentMode: "Mandatory" });

    const result = await createPaymentSession(paymentInput(event.id));

    expect(result.orderId).toMatch(new RegExp(`^${event.id}-[0-9a-f]{20}$`));
    expect(result.sessionId).toBe("SESSION0001");
    expect(result.checkoutToken).toBeTruthy();

    // The registration data lives in the database, not in the browser. This is
    // the core of the redesign: legacy kept it in localStorage across a
    // third-party redirect and re-posted it afterwards.
    const [pending] = await testDb().select().from(pendingRegistrations);
    expect(pending.orderId).toBe(result.orderId);
    expect(pending.sessionId).toBe("SESSION0001");
    expect(pending.payload).toMatchObject({
      email: "jane@example.com",
      fullName: "Jane Doe",
    });
    expect(pending.consumedAt).toBeNull();

    // No registration exists yet - nobody is booked until payment is verified.
    const rows = await testDb().select().from(registrations);
    expect(rows).toHaveLength(0);
  });

  it("charges the event type's gateway fee, not the display fee", async () => {
    const { event } = await createFullEvent({ paymentMode: "Mandatory" });
    await createPaymentSession(paymentInput(event.id));

    expect(gateway.sessions[0]).toMatchObject({
      amount: "750.00",
      currency: "USD",
      customerEmail: "jane@example.com",
    });
  });

  it("refuses when the event does not accept online payment", async () => {
    const { event } = await createFullEvent({ paymentMode: "No" });

    await expect(createPaymentSession(paymentInput(event.id))).rejects.toMatchObject({
      code: "PAYMENT_NOT_AVAILABLE",
    });
  });

  it("refuses when the event is closed", async () => {
    const { event } = await createFullEvent({
      paymentMode: "Mandatory",
      status: "Cancelled",
    });

    await expect(createPaymentSession(paymentInput(event.id))).rejects.toMatchObject({
      code: "REGISTRATION_CLOSED",
    });
  });

  it("refuses before charging when the email is already registered", async () => {
    const { event } = await createFullEvent({ paymentMode: "Mandatory" });
    await createRegistration(registrationSchema.parse(paymentInput(event.id)));

    // Taking money for a seat that cannot be booked is the worst outcome here,
    // so the duplicate check runs before the gateway is touched.
    await expect(createPaymentSession(paymentInput(event.id))).rejects.toMatchObject({
      code: "DUPLICATE_EMAIL_FOR_EVENT",
    });
    expect(gateway.sessions).toHaveLength(0);
  });

  it("issues unique order IDs", async () => {
    const first = await createFullEvent({ paymentMode: "Mandatory" });
    const a = await createPaymentSession(paymentInput(first.event.id));
    const b = await createPaymentSession(
      paymentInput(first.event.id, { email: "other@example.com" }),
    );

    // Uniqueness comes from crypto randomness plus the DB constraint, not from
    // legacy's mt_rand + SELECT COUNT(*) pre-check loop.
    expect(a.orderId).not.toBe(b.orderId);
  });
});

describe("payment verification", () => {
  it("creates a Paid registration on SUCCESS + CAPTURED", async () => {
    const { event } = await createFullEvent({ paymentMode: "Mandatory" });
    const session = await createPaymentSession(paymentInput(event.id));

    gateway.setOutcome(session.orderId, {
      state: "PAID",
      amount: "750.00",
      currency: "USD",
      orderId: session.orderId,
    });

    const result = await verifyPayment(session.checkoutToken);

    expect(result).toMatchObject({
      status: "PAID",
      orderId: session.orderId,
      amount: "750.00",
      currency: "USD",
    });

    const [row] = await testDb().select().from(registrations);
    expect(row.paymentState).toBe("Paid");
    expect(row.orderId).toBe(session.orderId);
    expect(row.email).toBe("jane@example.com");

    // The outcome came from the gateway, not from the caller.
    expect(gateway.retrievals).toContain(session.orderId);
  });

  it("does NOT confirm a successful but uncaptured order", async () => {
    const { event } = await createFullEvent({ paymentMode: "Mandatory" });
    const session = await createPaymentSession(paymentInput(event.id));

    // Success requires BOTH result === 'SUCCESS' AND status ===
    // 'CAPTURED'. An authorised-but-uncaptured order is PENDING_REVIEW.
    gateway.setOutcome(session.orderId, {
      state: "PENDING_REVIEW",
      result: "SUCCESS",
      status: "AUTHORIZED",
    });

    const result = await verifyPayment(session.checkoutToken);
    expect(result.status).toBe("PENDING_REVIEW");

    const rows = await testDb().select().from(registrations);
    expect(rows).toHaveLength(0);

    // Left unconsumed so a human - or the recovery job - can revisit it.
    const [pending] = await testDb().select().from(pendingRegistrations);
    expect(pending.consumedAt).toBeNull();
  });

  it("creates no registration on a failed or cancelled payment", async () => {
    const { event } = await createFullEvent({ paymentMode: "Mandatory" });
    const session = await createPaymentSession(paymentInput(event.id));

    gateway.setOutcome(session.orderId, {
      state: "FAILED",
      result: "FAILURE",
      status: "DECLINED",
    });

    const result = await verifyPayment(session.checkoutToken);
    expect(result.status).toBe("FAILED");

    const rows = await testDb().select().from(registrations);
    expect(rows).toHaveLength(0);
  });

  it("rejects a forged or malformed token", async () => {
    // The whole legacy callback check lived in client JavaScript and was
    // forgeable; here the signature is the gate.
    await expect(verifyPayment("not-a-token")).rejects.toMatchObject({
      code: "INVALID_CALLBACK",
      status: 403,
    });

    await expect(verifyPayment("v1.abc.def")).rejects.toMatchObject({
      code: "INVALID_CALLBACK",
    });
  });

  it("rejects a well-formed token for an order that does not exist", async () => {
    const token = createCheckoutToken({
      orderId: "99-deadbeefdeadbeefdead",
      eventId: 99,
      sessionId: "SESSION9999",
    });

    await expect(verifyPayment(token)).rejects.toMatchObject({ status: 404 });
  });
});

describe("finalization idempotency", () => {
  it("returns the same registration on a duplicate callback", async () => {
    const { event } = await createFullEvent({ paymentMode: "Mandatory" });
    const session = await createPaymentSession(paymentInput(event.id));
    gateway.succeedAll();

    const first = await verifyPayment(session.checkoutToken);
    const second = await verifyPayment(session.checkoutToken);
    const third = await verifyPayment(session.checkoutToken);

    expect(first.status).toBe("PAID");
    expect(second).toEqual(first);
    expect(third).toEqual(first);

    // The assertion that matters: one payment, one registration, however many
    // times the callback fires.
    const rows = await testDb().select().from(registrations);
    expect(rows).toHaveLength(1);
  });

  it("attaches the order to an existing unpaid registration rather than failing", async () => {
    const { event } = await createFullEvent({ paymentMode: "Optional" });

    // Registered unpaid first - this occupies the unique (event, email) slot.
    await createRegistration(registrationSchema.parse(paymentInput(event.id)));
    const [before] = await testDb().select().from(registrations);
    expect(before.paymentState).toBe("Pending");

    // Then pays. A plain insert would violate the unique constraint and leave a
    // paying customer with no paid booking, so finalization updates in place.
    const session = await createPaymentSession(
      paymentInput(event.id, { email: "second@example.com" }),
    );
    await testDb()
      .update(pendingRegistrations)
      .set({
        payload: {
          eventId: event.id,
          title: "Dr.",
          firstName: "Jane",
          lastName: "Doe",
          fullName: "Jane Doe",
          mobile: "+96170123456",
          mobileIntl: "+96170123456",
          email: "jane@example.com",
          notes: null,
        },
      });
    gateway.succeedAll();

    const result = await verifyPayment(session.checkoutToken);
    expect(result.status).toBe("PAID");

    const rows = await testDb().select().from(registrations);
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(before.id);
    expect(rows[0].paymentState).toBe("Paid");
    expect(rows[0].orderId).toBe(session.orderId);
  });

  it("survives concurrent verifications of the same order", async () => {
    const { event } = await createFullEvent({ paymentMode: "Mandatory" });
    const session = await createPaymentSession(paymentInput(event.id));
    gateway.succeedAll();

    // Two callbacks racing - a browser retry landing beside the recovery job.
    const results = await Promise.allSettled([
      verifyPayment(session.checkoutToken),
      verifyPayment(session.checkoutToken),
    ]);

    const fulfilled = results.filter((r) => r.status === "fulfilled");
    expect(fulfilled.length).toBeGreaterThan(0);

    const rows = await testDb().select().from(registrations);
    expect(rows).toHaveLength(1);
  });
});
