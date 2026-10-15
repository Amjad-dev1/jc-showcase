import "server-only";
import { NextResponse } from "next/server";
import { AppError, ERROR_CODES, type ErrorEnvelope } from "@/lib/shared/errors";
import { logger, newRequestId } from "./logger";

/**
 * Route-handler plumbing.
 *
 * Every handler is wrapped by `handleRoute`, which exists to make one guarantee
 * structural rather than conventional: **no error escapes as anything other
 * than the error envelope**. An unexpected throw - a driver error, a TypeError,
 * a failed `JSON.parse` - becomes a generic `INTERNAL_ERROR` with the detail
 * logged server-side and nothing revealing sent to the client.
 *
 * That corrects the legacy behaviour: it "surfaced raw database exception
 * text directly in the HTML response, leaking schema details".
 */

export function jsonResponse<T>(data: T, status = 200): NextResponse {
  return NextResponse.json(data, { status });
}

export function errorResponse(error: AppError): NextResponse<ErrorEnvelope> {
  return NextResponse.json(error.toEnvelope(), { status: error.status });
}

/**
 * Wraps a handler with error translation and request tracing.
 *
 * The `requestId` is generated per request, attached to every log line the
 * handler produces, and returned in an `X-Request-Id` header so a user-reported
 * failure can be traced to its logs without the response carrying any detail
 * about what went wrong.
 */
export function handleRoute<Args extends unknown[], R extends Response = NextResponse>(
  route: string,
  handler: (...args: Args) => Promise<R>,
) {
  return async (...args: Args): Promise<Response> => {
    const requestId = newRequestId();

    try {
      const response = await handler(...args);
      response.headers.set("X-Request-Id", requestId);
      return response;
    } catch (error) {
      if (error instanceof AppError) {
        // An expected, modelled failure. Logged at warn because it is part of
        // normal operation - a duplicate email is not an incident.
        logger.warn("Request failed", {
          requestId,
          route,
          code: error.code,
          status: error.status,
        });
        const response = errorResponse(error);
        response.headers.set("X-Request-Id", requestId);
        return response;
      }

      // Anything else is a bug. The detail goes to the log; the client gets the
      // generic message and a request ID to quote.
      logger.error("Unhandled route error", { requestId, route, error });
      const response = errorResponse(new AppError(ERROR_CODES.INTERNAL_ERROR));
      response.headers.set("X-Request-Id", requestId);
      return response;
    }
  };
}

/**
 * Parses a JSON body, tolerating the shapes `navigator.sendBeacon()` produces.
 *
 * The lead-capture endpoint accepts a beacon payload: beacons
 * send no custom headers and may arrive as `text/plain` or as form-encoded data
 * rather than `application/json`. Rejecting on content type would silently drop
 * exactly the leads the endpoint exists to catch.
 */
export async function readJsonBody(request: Request): Promise<unknown> {
  const contentType = request.headers.get("content-type") ?? "";

  try {
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await request.formData();
      return Object.fromEntries(form.entries());
    }

    const text = await request.text();
    if (!text.trim()) return {};
    return JSON.parse(text);
  } catch {
    // An unparseable body is a client error, not a server one.
    throw new AppError(ERROR_CODES.INVALID_INPUT, "Malformed request body.");
  }
}

/** Reads and coerces query parameters for the pagination schemas. */
export function searchParamsToObject(url: string): Record<string, string> {
  return Object.fromEntries(new URL(url).searchParams.entries());
}
