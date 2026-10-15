import "server-only";
import { auth } from "./config";
import { AppError, ERROR_CODES } from "@/lib/shared/errors";

/**
 * Authorization guards.
 *
 * **Every Server Action is a publicly reachable HTTP endpoint.** Next.js
 * compiles each one into a callable POST endpoint with a generated ID. Being
 * defined inside an admin-only component, or imported only by an admin page,
 * grants **no** protection whatsoever.
 *
 * That is why this guard exists as a single function that every admin action and
 * route handler calls explicitly. The guard is centralised so
 * it cannot be forgotten, but it is still called explicitly in each action, and the
 * distinction matters: centralising it makes the call one line, but nothing
 * *implicitly* protects an action. The proxy guard in `src/proxy.ts` covers the
 * `/admin/**` page subtree; it does not cover Server Action POSTs, which are
 * dispatched by action ID rather than by path.
 */

export interface AdminSession {
  adminId: number;
  email: string;
  displayName: string;
}

/**
 * Throws `401 UNAUTHORIZED` unless the caller holds a valid admin session.
 *
 * The role is re-derived from the session cookie every time. Never pass
 * authorization state as an action argument. A `role` or `userId` parameter is
 * client-controlled and forgeable.
 */
export async function requireAdmin(): Promise<AdminSession> {
  const session = await auth();

  if (!session?.user || session.user.role !== "admin") {
    throw new AppError(ERROR_CODES.UNAUTHORIZED);
  }

  return {
    adminId: session.user.adminId,
    email: session.user.email ?? "",
    displayName: session.user.name ?? "",
  };
}

/** Non-throwing variant, for UI that renders differently when signed in. */
export async function getAdminSession(): Promise<AdminSession | null> {
  const session = await auth();
  if (!session?.user || session.user.role !== "admin") return null;

  return {
    adminId: session.user.adminId,
    email: session.user.email ?? "",
    displayName: session.user.name ?? "",
  };
}
