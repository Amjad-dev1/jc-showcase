import "server-only";
import { mpgsConfig, appConfig } from "../config";
import { logger } from "../logger";
import { AppError, ERROR_CODES } from "@/lib/shared/errors";

/**
 * Mastercard Payment Gateway Services - hosted checkout.
 *
 * The gateway is reached through an interface so tests can inject a fake and
 * the recovery job can be exercised without touching a real merchant account.
 * Nothing here ever sees card data: the customer enters it on MPGS's own hosted
 * page, and this module only creates sessions and reads back order outcomes.
 */

export interface CreateSessionInput {
  orderId: string;
  amount: string;
  currency: string;
  description: string;
  customerEmail: string;
}

export interface CreateSessionResult {
  sessionId: string;
}

/** The normalised outcome of an order lookup, per the state mapping. */
export type OrderOutcome =
  | { state: "PAID"; amount: string; currency: string; orderId: string }
  | { state: "PENDING_REVIEW"; result: string; status: string }
  | { state: "FAILED"; result: string; status: string }
  | { state: "NOT_FOUND" };

export interface MpgsGateway {
  createSession(input: CreateSessionInput): Promise<CreateSessionResult>;
  retrieveOrder(orderId: string): Promise<OrderOutcome>;
}

/**
 * Order ID generation.
 *
 * Cryptographically random and prefixed with the event ID for traceability.
 * Legacy built this as `eventId + mt_rand(0,999) + uniqid()` and re-rolled in a
 * loop against a `SELECT COUNT(*)` - `mt_rand` is not cryptographically secure
 * and the pre-check races. Here uniqueness is guaranteed by the database's
 * unique constraint on `order_id`, not by looking first.
 *
 * Maximum length is 50 characters, matching the column.
 */
export function generateOrderId(eventId: number): string {
  const random = crypto.randomUUID().replace(/-/g, "").slice(0, 20);
  return `${eventId}-${random}`;
}

/** HTTP Basic credentials: `merchant.<MERCHANT_ID>` / API password. */
function authHeader(merchantId: string, apiPassword: string): string {
  const encoded = Buffer.from(`merchant.${merchantId}:${apiPassword}`).toString("base64");
  return `Basic ${encoded}`;
}

class HttpMpgsGateway implements MpgsGateway {
  private base(): { url: string; auth: string } {
    const config = mpgsConfig();
    return {
      url: `${config.baseUrl}/version/${config.apiVersion}/merchant/${config.merchantId}`,
      auth: authHeader(config.merchantId, config.apiPassword),
    };
  }

  /**
   * `INITIATE_CHECKOUT`.
   *
   * The amount and currency come from `event_types.gateway_fee` /
   * `gateway_currency` and are passed as strings - money is never a float, and
   * the gateway expects a decimal string anyway.
   */
  async createSession(input: CreateSessionInput): Promise<CreateSessionResult> {
    const { url, auth } = this.base();
    const app = appConfig();

    const body = {
      apiOperation: "INITIATE_CHECKOUT",
      interaction: {
        operation: "PURCHASE",
        merchant: {
          name: app.projectName,
          logo: `${app.baseUrl}/img/jc-c.png`,
          url: app.baseUrl,
        },
        displayControl: {
          billingAddress: "MANDATORY",
          customerEmail: "MANDATORY",
          shipping: "HIDE",
        },
      },
      order: {
        amount: input.amount,
        currency: input.currency,
        id: input.orderId,
        description: input.description,
      },
      customer: { email: input.customerEmail },
    };

    let response: Response;
    try {
      response = await fetch(`${url}/session`, {
        method: "POST",
        headers: { Authorization: auth, "Content-Type": "application/json" },
        body: JSON.stringify(body),
        // Without a timeout a hung gateway holds the serverless function until
        // the platform kills it, and the customer sees nothing at all.
        signal: AbortSignal.timeout(15_000),
      });
    } catch (error) {
      // Metadata only - never card data.
      logger.error("MPGS session request failed", { orderId: input.orderId, error });
      throw new AppError(ERROR_CODES.GATEWAY_ERROR);
    }

    const payload = (await response.json().catch(() => null)) as
      | { session?: { id?: string }; error?: unknown; result?: string }
      | null;

    if (!response.ok || !payload?.session?.id) {
      logger.error("MPGS session rejected", {
        orderId: input.orderId,
        status: response.status,
        result: payload?.result,
      });
      throw new AppError(ERROR_CODES.GATEWAY_ERROR);
    }

    logger.info("MPGS session created", { orderId: input.orderId });
    return { sessionId: payload.session.id };
  }

  /**
   * `Retrieve Order`, mapped to a normalised state.
   *
   * **Success requires both `result === 'SUCCESS'` and `status === 'CAPTURED'`.**
   * Anything else is not a completed payment - a successful-but-uncaptured order
   * is `PENDING_REVIEW` and must never auto-confirm a registration.
   */
  async retrieveOrder(orderId: string): Promise<OrderOutcome> {
    const { url, auth } = this.base();

    let response: Response;
    try {
      response = await fetch(`${url}/order/${encodeURIComponent(orderId)}`, {
        method: "GET",
        headers: { Authorization: auth },
        signal: AbortSignal.timeout(15_000),
      });
    } catch (error) {
      logger.error("MPGS order lookup failed", { orderId, error });
      throw new AppError(ERROR_CODES.GATEWAY_ERROR);
    }

    if (response.status === 404) return { state: "NOT_FOUND" };

    const payload = (await response.json().catch(() => null)) as {
      result?: string;
      status?: string;
      amount?: number | string;
      currency?: string;
    } | null;

    if (!response.ok || !payload) {
      logger.error("MPGS order lookup rejected", { orderId, status: response.status });
      throw new AppError(ERROR_CODES.GATEWAY_ERROR);
    }

    return mapOrderResponse(orderId, payload);
  }
}

/**
 * The state mapping, extracted so it can be unit-tested directly against
 * every combination the gateway can return.
 */
export function mapOrderResponse(
  orderId: string,
  payload: { result?: string; status?: string; amount?: number | string; currency?: string },
): OrderOutcome {
  const result = payload.result ?? "";
  const status = payload.status ?? "";

  if (result === "SUCCESS" && status === "CAPTURED") {
    const amount =
      typeof payload.amount === "number"
        ? payload.amount.toFixed(2)
        : (payload.amount ?? "0.00");
    return { state: "PAID", amount, currency: payload.currency ?? "", orderId };
  }

  // Successful but not captured: funds are authorised, not taken. The mapping says
  // do not auto-confirm - flag for manual review instead.
  if (result === "SUCCESS") return { state: "PENDING_REVIEW", result, status };

  return { state: "FAILED", result, status };
}

interface GatewayGlobal {
  __jcMpgs?: MpgsGateway;
}

const globalRef = globalThis as unknown as GatewayGlobal;

export function getMpgsGateway(): MpgsGateway {
  if (!globalRef.__jcMpgs) globalRef.__jcMpgs = new HttpMpgsGateway();
  return globalRef.__jcMpgs;
}

/** Lets tests and the local development environment inject a fake gateway. */
export function __setMpgsGateway(gateway: MpgsGateway | undefined) {
  globalRef.__jcMpgs = gateway;
}
