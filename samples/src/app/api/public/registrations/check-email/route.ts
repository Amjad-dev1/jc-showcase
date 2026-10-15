import { handleRoute, jsonResponse, readJsonBody } from "@/lib/server/http";
import { checkEmailAvailability } from "@/lib/server/services/registration-service";
import { checkEmailSchema } from "@/lib/shared/schemas/public";
import { parseOrThrow } from "@/lib/shared/schemas/common";
import { clientIpFrom, enforceRateLimit } from "@/lib/server/ratelimit";

/**
 * `POST /api/public/registrations/check-email`.
 *
 * **Rate limiting is not optional here.** This is an unauthenticated oracle that
 * reveals whether a given address is registered for a given event, so throttling
 * is the only thing standing between it and enumeration of an event's attendee
 * list. The key combines IP and event ID.
 */

export const dynamic = "force-dynamic";

export const POST = handleRoute(
  "POST /api/public/registrations/check-email",
  async (request: Request) => {
    const body = await readJsonBody(request);
    const input = parseOrThrow(checkEmailSchema, body);

    // Keyed per IP *and* event so probing many addresses against one event is
    // throttled, while a busy office NAT checking different events is not.
    await enforceRateLimit(
      "checkEmail",
      `${clientIpFrom(request.headers)}:${input.eventId}`,
    );

    return jsonResponse(await checkEmailAvailability(input.eventId, input.email));
  },
);
