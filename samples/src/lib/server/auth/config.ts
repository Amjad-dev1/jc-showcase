import "server-only";
import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";
import { findActiveAdminByEmail } from "../repositories/admin-users";
import { verifyAgainstDummy, verifyPassword } from "./password";
import { logger } from "../logger";
import { authConfig } from "../config";

/**
 * Auth.js configuration.
 *
 * The Credentials provider is used because admins are rows in `admin_users`
 * migrated from the legacy admin table, with Argon2id hashes that must
 * keep verifying. Auth.js does not hash anything itself - `authorize`
 * owns that entirely, which is why it is unsafe to let a
 * bcrypt default in.
 *
 * **JWT sessions rather than database sessions.** There is no sessions table in
 * the schema, and adding one would mean a database round trip on every admin
 * request. The signed cookie is httpOnly, secure and SameSite.
 */

const credentialsSchema = z.object({
  email: z.string().min(1),
  password: z.string().min(1),
});

export const nextAuthConfig: NextAuthConfig = {
  secret: authConfig().secret,
  session: {
    strategy: "jwt",
    // Eight hours: a working day. Long enough that staff are not re-logging in
    // between tasks, short enough that a forgotten session on a shared machine
    // expires the same day.
    maxAge: 8 * 60 * 60,
  },
  pages: {
    signIn: "/admin/login",
    error: "/admin/login",
  },
  providers: [
    Credentials({
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        const parsed = credentialsSchema.safeParse(credentials);
        if (!parsed.success) return null;

        const { email, password } = parsed.data;

        // Returns null for both "no such user" and "deactivated account", so
        // the two are indistinguishable from here on.
        const user = await findActiveAdminByEmail(email);

        if (!user) {
          // Still pay the Argon2 cost, so an unknown email is not measurably
          // faster than a wrong password - otherwise the endpoint is a
          // user-enumeration oracle despite the identical error message.
          await verifyAgainstDummy(password);
          logger.warn("Failed admin login", { reason: "unknown-or-inactive" });
          return null;
        }

        const ok = await verifyPassword(user.passwordHash, password);
        if (!ok) {
          logger.warn("Failed admin login", { reason: "bad-password" });
          return null;
        }

        logger.info("Admin login succeeded", { adminId: user.id });

        return {
          id: String(user.id),
          email: user.email,
          name: user.displayName,
          role: "admin" as const,
        };
      },
    }),
  ],
  callbacks: {
    /**
     * Persists `role` into the token. The guards read it, and it must be
     * derived from the database at sign-in - never accepted as an input - or it
     * becomes trivially forged privilege escalation.
     */
    async jwt({ token, user }) {
      if (user) {
        token.role = "admin";
        token.adminId = Number(user.id);
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.role = token.role as string;
        session.user.adminId = token.adminId as number;
      }
      return session;
    },
  },
  // Auth.js sets `__Secure-` prefixed, httpOnly, SameSite=Lax cookies over
  // HTTPS by default, as required; they are left alone here so
  // a partial override cannot weaken them.
  trustHost: true,
};

export const { handlers, auth, signIn, signOut } = NextAuth(nextAuthConfig);
