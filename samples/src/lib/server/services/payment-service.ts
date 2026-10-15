import "server-only";
import { getDb } from "../db";
import { findEventWithDetails } from "../repositories/events";
import {
  findRegistrationByEventAndEmail,
  findRegistrationByOrderId,
  insertRegistration,
  isEmailRegisteredForEvent,
  markRegistrationPaid,
} from "../repositories/registrations";
import {
  attachSessionId,
  createPendingRegistration,
  findPendingRegistration,
  markPendingConsumed,
  type PendingRegistrationPayload,
} from "../repositories/pending-registrations";
import {
  createCheckoutToken,
  verifyCheckoutToken,
} from "../integrations/checkout-token";
import { generateOrderId, getMpgsGateway } from "../integrations/mpgs";
import { AppError, ERROR_CODES, errors } from "@/lib/shared/errors";
import { logger } from "../logger";
import { queueConfirmationEmail } from "./registration-service";
import type { PaymentSessionInput } from "@/lib/shared/schemas/public";

/**
 * The secure payment flow.
 *
 * > **What legacy did, and why it must not be reproduced.** The old flow
 * > serialized the entire registration form into browser `localStorage`,
 * > redirected to the gateway, and on return compared query-string values
 * > against `localStorage` **in JavaScript** to decide whether the callback was
 * > legitimate. It then had the browser POST the stored form data to the
 * > registration endpoint, appending the order ID client-side. Every part of
 * > that check was forgeable, and if the final AJAX call timed out the customer
 * > was **charged with no registration record created**.
 *
 * The replacement holds three properties:
 *
 *  - **The payload never leaves the server.** It lives in
 *    `pending_registrations`, keyed by order ID.
 *  - **The client is never believed about payment.** Verification asks MPGS
 *    directly; the callback carries only a signed token naming which order to
 *    ask about.
 *  - **Finalization is idempotent.** A duplicate callback, a refresh, or the
 *    recovery job all converge on the same registration.
 */

const PENDING_TTL_MS = 60 * 60 * 1000; // One hour.

export interface PaymentSessionResult {
  orderId: string;
  sessionId: string;
  checkoutToken: string;
}

/**
 * `POST /api/public/payments/session`.
 *
 * The gate order is deliberate: everything that can reject the request without
 * side effects runs before the order ID is minted, so a closed event or a
 * duplicate email never leaves an orphaned pending row behind.
 */
export async function createPaymentSession(
  input: PaymentSessionInput,
): Promise<PaymentSessionResult> {
  const event = await findEventWithDetails(input.eventId);
  if (!event) throw errors.eventNotFound();
  if (event.status !== "New") throw errors.registrationClosed();

  // Only Optional and Mandatory events can be paid online.
  if (event.paymentMode !== "Optional" && event.paymentMode !== "Mandatory") {
    throw new AppError(ERROR_CODES.PAYMENT_NOT_AVAILABLE);
  }

  // Checked before charging anyone: taking a payment for a seat that cannot be
  // booked is the worst possible failure here.
  if (await isEmailRegisteredForEvent(input.eventId, input.email)) {
    throw errors.duplicateEmail();
  }

  const orderId = generateOrderId(input.eventId);

  const payload: PendingRegistrationPayload = {
    eventId: input.eventId,
    title: input.title,
    firstName: input.firstName,
    lastName: input.lastName,
    fullName: input.fullName,
    mobile: input.mobile,
    mobileIntl: input.mobileIntl ?? input.mobile,
    email: input.email,
    notes: input.notes,
  };

  // Persisted BEFORE the gateway call, so a session that succeeds at MPGS but
  // whose response never reaches us still has a recoverable server-side record
  //.
  await createPendingRegistration({
    orderId,
    eventId: input.eventId,
    payload,
    amount: event.gatewayFee,
    currency: event.gatewayCurrency,
    expiresAt: new Date(Date.now() + PENDING_TTL_MS),
  });

  const { sessionId } = await getMpgsGateway().createSession({
    orderId,
    amount: event.gatewayFee,
    currency: event.gatewayCurrency,
    description: `Payment for ${event.eventName} ${event.eventType}`,
    customerEmail: input.email,
  });

  await attachSessionId(orderId, sessionId);

  logger.info("Payment session created", { orderId, eventId: input.eventId });

  return {
    orderId,
    sessionId,
    checkoutToken: createCheckoutToken({ orderId, eventId: input.eventId, sessionId }),
  };
}

export type PaymentVerifyResult =
  | {
      status: "PAID";
      registrationId: number;
      orderId: string;
      amount: string;
      currency: string;
    }
  | { status: "PENDING_REVIEW"; orderId: string }
  | { status: "FAILED"; orderId: string };

/**
 * `POST /api/public/payments/verify`.
 *
 * Takes the signed token and nothing else that matters. The outcome comes from
 * MPGS's own `Retrieve Order` API. The payment outcome, amount and order ID
 * are never accepted from the client as authoritative.
 */
export async function verifyPayment(checkoutToken: string): Promise<PaymentVerifyResult> {
  const token = verifyCheckoutToken(checkoutToken);
  if (!token) throw new AppError(ERROR_CODES.INVALID_CALLBACK);

  const pending = await findPendingRegistration(token.orderId);
  if (!pending) throw errors.notFound("This payment session no longer exists.");

  /**
   * Already consumed: return the existing outcome.
   *
   * This is the idempotency guarantee. A refresh of the result page, a
   * duplicated callback, or the recovery job racing a live callback all land
   * here and get the same answer rather than a second registration or an error.
   */
  if (pending.consumedAt) {
    const existing = await findRegistrationByOrderId(token.orderId);
    if (existing) {
      return {
        status: "PAID",
        registrationId: existing.id,
        orderId: token.orderId,
        amount: pending.amount,
        currency: pending.currency,
      };
    }
    // Consumed without a registration means the order resolved to a
    // non-successful state on a previous pass.
    return { status: "FAILED", orderId: token.orderId };
  }

  const outcome = await getMpgsGateway().retrieveOrder(token.orderId);

  // Success requires BOTH result === 'SUCCESS' and status === 'CAPTURED'.
  // Everything else - including a successful-but-uncaptured authorisation - must
  // not auto-confirm.
  if (outcome.state !== "PAID") {
    logger.warn("Payment not completed", {
      orderId: token.orderId,
      state: outcome.state,
    });

    if (outcome.state === "PENDING_REVIEW") {
      // Left unconsumed deliberately: a human decides, and the recovery job can
      // re-check it in the meantime.
      return { status: "PENDING_REVIEW", orderId: token.orderId };
    }

    await markPendingConsumed(token.orderId);
    return { status: "FAILED", orderId: token.orderId };
  }

  const registration = await finalizePaidRegistration(
    token.orderId,
    pending.payload as PendingRegistrationPayload,
  );

  return {
    status: "PAID",
    registrationId: registration.id,
    orderId: token.orderId,
    amount: outcome.amount || pending.amount,
    currency: outcome.currency || pending.currency,
  };
}

/**
 * Idempotent finalization.
 *
 * The three-step lookup, all inside one transaction:
 *
 *  1. By `order_id` - exists, return it unchanged.
 *  2. By `(event_id, email)` - exists, attach the order ID and mark Paid.
 *  3. Otherwise insert.
 *
 * Step 2 is what handles the person who registered unpaid and later paid: they
 * already occupy the unique `(event_id, email)` slot, so a plain insert would
 * fail and leave a paying customer with no paid booking.
 */
export async function finalizePaidRegistration(
  orderId: string,
  payload: PendingRegistrationPayload,
) {
  const result = await getDb().transaction(async (tx) => {
    // Every statement below runs on `tx`. Reads on the outer handle would not
    // observe this transaction's own writes, so the "already exists" checks
    // could miss a row inserted moments earlier in the same transaction.
    const byOrder = await findRegistrationByOrderId(orderId, tx);
    if (byOrder) return { row: byOrder, created: false };

    const byEmail = await findRegistrationByEventAndEmail(
      payload.eventId,
      payload.email,
      tx,
    );
    if (byEmail) {
      const updated = await markRegistrationPaid(byEmail.id, orderId, tx);
      return { row: updated ?? byEmail, created: false };
    }

    const inserted = await insertRegistration(
      {
        eventId: payload.eventId,
        title: payload.title,
        fullName: payload.fullName,
        mobile: payload.mobile,
        mobileIntl: payload.mobileIntl,
        email: payload.email,
        notes: payload.notes,
        paymentState: "Paid",
        orderId,
      },
      tx,
    );

    if (!inserted) {
      // Lost a race between the lookup above and this insert. Re-reading is
      // correct rather than failing: the winner created exactly the row we
      // wanted, so the customer still ends up registered and paid.
      const raced = await findRegistrationByEventAndEmail(
        payload.eventId,
        payload.email,
        tx,
      );
      if (raced) {
        const updated = await markRegistrationPaid(raced.id, orderId, tx);
        return { row: updated ?? raced, created: false };
      }
      throw errors.internal();
    }

    return { row: inserted, created: true };
  });

  /**
   * Consumed after the registration is committed, and deliberately not inside
   * the transaction.
   *
   * The two orderings fail differently. Marking consumed *inside* and then
   * failing to commit would roll both back - safe, but so would leaving it
   * outside. What actually matters is which side is safe to repeat: if this
   * update is lost, the order is simply re-verified later and finalization
   * finds the existing registration by order ID and returns it unchanged. The
   * reverse - a consumed row with no registration - would strand a paying
   * customer, and cannot happen with this ordering.
   */
  await markPendingConsumed(orderId);

  logger.info("Paid registration finalized", {
    orderId,
    registrationId: result.row.id,
    created: result.created,
  });

  // Only on first creation, so a repeated callback does not re-send mail.
  if (result.created) {
    queueConfirmationEmail(result.row.id, payload.eventId, {
      to: payload.email,
      title: payload.title,
      fullName: payload.fullName,
      orderId,
    });
  }

  return result.row;
}
