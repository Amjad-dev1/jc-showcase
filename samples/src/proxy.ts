import { NextResponse, type NextRequest } from "next/server";
import { defaultLocale, locales } from "@/lib/i18n/config";

/**
 * Request proxy - locale routing, the admin guard, and CSRF origin checks.
 *
 * Note the file name: the `middleware` convention is deprecated in this version
 * of Next and has been renamed to `proxy`.
 *
 * Only one proxy file is supported per project, so the three concerns share it:
 *
 *  1. **Locale redirect** - every public visitor lands on a locale-prefixed URL.
 *  2. **Admin subtree guard** - protects `/admin/**` at this layer so
 *     "a newly added screen cannot ship unprotected by omission". Legacy
 *     repeated a guard inside each page, so protection depended on the author
 *     remembering it.
 *  3. **CSRF origin check** - same-site enforcement for state-changing
 *     public API calls, replacing legacy's `$_SESSION["allowed"]` flag.
 *
 * **What this file deliberately does not do:** authenticate. This
 * guard is a structural backstop, and the Next.js docs are explicit that a
 * proxy "should not be used as a full session management or authorization
 * solution". The cookie presence check below is an optimistic redirect; the
 * real authorization is `requireAdmin()` inside every admin route and Server
 * Action.
 */

const COOKIE = "NEXT_LOCALE";

/**
 * Parse `Accept-Language` and return the best supported match.
 *
 * Hand-rolled rather than pulling in Negotiator + intl-localematcher: with
 * three locales and no region variants to disambiguate, quality-value sorting
 * and a prefix match is the whole algorithm, and it keeps the edge bundle free
 * of two extra dependencies.
 */
function matchLocale(header: string | null) {
  if (!header) return defaultLocale;

  const ranked = header
    .split(",")
    .map((part) => {
      const [tag, ...params] = part.trim().split(";");
      const q = params.find((p) => p.trim().startsWith("q="));
      // A tag with no explicit q-value is the most preferred (q=1).
      const quality = q ? Number.parseFloat(q.split("=")[1]) : 1;
      return {
        // "en-GB" and "EN" both need to match the "en" locale.
        base: tag.trim().toLowerCase().split("-")[0],
        quality: Number.isFinite(quality) ? quality : 0,
      };
    })
    // `q=0` explicitly means "not acceptable", so drop those.
    .filter((entry) => entry.quality > 0)
    .sort((a, b) => b.quality - a.quality);

  return ranked.find((entry) => locales.includes(entry.base as never))?.base ?? defaultLocale;
}

/**
 * Auth.js session cookie names.
 *
 * Both are checked because the `__Secure-` prefix is only used over HTTPS, so
 * production and local development carry different names for the same cookie.
 */
const SESSION_COOKIES = [
  "authjs.session-token",
  "__Secure-authjs.session-token",
] as const;

function hasSessionCookie(request: NextRequest): boolean {
  return SESSION_COOKIES.some((name) => Boolean(request.cookies.get(name)?.value));
}

/**
 * Same-origin check for state-changing requests.
 *
 * Browsers always attach `Origin` to cross-origin requests, so a mismatch is a
 * genuine cross-site call. A *missing* `Origin` is allowed: `navigator.sendBeacon`
 * and some same-origin form posts omit it, and the lead-capture endpoint
 * depends on beacons working.
 *
 * This complements - never replaces - the authorization checks in the handlers
 * themselves.
 */
function isCrossSiteWrite(request: NextRequest): boolean {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return false;

  const origin = request.headers.get("origin");
  if (!origin) return false;

  try {
    return new URL(origin).host !== request.nextUrl.host;
  } catch {
    // An unparseable Origin header is not something a browser sends.
    return true;
  }
}

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // API routes: CSRF origin check only. No locale prefix, no redirect.
  if (pathname.startsWith("/api/")) {
    if (isCrossSiteWrite(request)) {
      return NextResponse.json(
        {
          error: {
            code: "FORBIDDEN",
            message: "Cross-site requests are not permitted.",
          },
        },
        { status: 403 },
      );
    }
    return NextResponse.next();
  }

  // Admin subtree: guarded, and never locale-prefixed.
  if (pathname === "/admin" || pathname.startsWith("/admin/")) {
    if (isCrossSiteWrite(request)) {
      return new NextResponse("Forbidden", { status: 403 });
    }

    const isLoginPage = pathname === "/admin/login";
    const signedIn = hasSessionCookie(request);

    // `/admin` redirects to the login when unauthenticated and to the
    // dashboard when authenticated. No decoy page - legacy's served no purpose.
    if (pathname === "/admin") {
      const target = signedIn ? "/admin/events" : "/admin/login";
      return NextResponse.redirect(new URL(target, request.url));
    }

    if (!signedIn && !isLoginPage) {
      const loginUrl = new URL("/admin/login", request.url);
      // Preserve the intended destination so session expiry returns the user
      // where they were going.
      loginUrl.searchParams.set("callbackUrl", pathname);
      return NextResponse.redirect(loginUrl);
    }

    // Already signed in and visiting the login page - go to the landing screen,
    // which is `/admin/events`, matching legacy.
    if (signedIn && isLoginPage) {
      return NextResponse.redirect(new URL("/admin/events", request.url));
    }

    return NextResponse.next();
  }

  // Public pages: locale routing.

  // Already locale-prefixed - nothing to do.
  const hasLocale = locales.some(
    (locale) => pathname === `/${locale}` || pathname.startsWith(`/${locale}/`),
  );
  if (hasLocale) return NextResponse.next();

  // A returning visitor's explicit choice beats their browser header: someone
  // who switched to Arabic on an English-configured laptop meant it.
  const saved = request.cookies.get(COOKIE)?.value;
  const locale =
    saved && locales.includes(saved as never)
      ? saved
      : matchLocale(request.headers.get("accept-language"));

  const url = request.nextUrl.clone();
  // Preserves the trailing path and any query string: /docs/x?a=1 -> /fr/docs/x?a=1
  url.pathname = `/${locale}${pathname === "/" ? "" : pathname}`;
  return NextResponse.redirect(url);
}

export const config = {
  /**
   * Skip Next internals and anything that looks like a real file - the PDFs in
   * /docs, the logos in /img, the hero clips in /video and the favicon must be
   * served as-is, not redirected under a locale.
   *
   * `/api` is **no longer excluded**: the CSRF origin check above has to see
   * those requests. The handler returns early for them, so they never reach the
   * locale logic.
   */
  matcher: ["/((?!_next|.*\\.[\\w]+$).*)"],
};
