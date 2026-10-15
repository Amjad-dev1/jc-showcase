import { handleRoute, jsonResponse, readJsonBody } from "@/lib/server/http";
import { requireAdmin } from "@/lib/server/auth/guards";
import { changeAdminPassword } from "@/lib/server/services/admin-service";
import { changePasswordSchema } from "@/lib/shared/schemas/admin";
import { parseOrThrow } from "@/lib/shared/schemas/common";

/**
 * `POST /api/admin/auth/change-password`.
 *
 * All four rules are enforced server-side: the old password must verify, the
 * new one must match its confirmation, be 8-25 characters, and differ from the
 * old. Legacy enforced the length rule only in the browser and permitted
 * setting the password to its current value.
 *
 * Responds with `forceReauth: true` so the client signs out - a password change
 * should not leave the old session usable.
 */

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = handleRoute(
  "POST /api/admin/auth/change-password",
  async (request: Request) => {
    const session = await requireAdmin();
    const input = parseOrThrow(changePasswordSchema, await readJsonBody(request));

    return jsonResponse(await changeAdminPassword(session.adminId, input));
  },
);
