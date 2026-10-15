import type { NextConfig } from "next";

/**
 * Security headers.
 *
 * The hosting platform does not set these, so they are configured explicitly
 * here. Their absence is one of the attack surfaces a modern stack introduces,
 * alongside unguarded Server Actions and in-memory rate limiting.
 */

const isProduction = process.env.NODE_ENV === "production";

/**
 * The Content-Security-Policy.
 *
 * The allowances are exactly the third parties this application genuinely loads;
 * nothing is listed speculatively, because every extra origin is one
 * more place an injected script could be fetched from.
 *
 * - `challenges.cloudflare.com` - Turnstile widget and its frame
 * - the MPGS gateway host - hosted-checkout script and frame
 * - `connect.facebook.net` / `www.facebook.com` - Meta Pixel, only when enabled
 *
 * `'unsafe-inline'` in `script-src` is permitted **only outside production**,
 * where the dev overlay and Fast Refresh require it.
 * Keeping it out of production builds is the practical line here, since a
 * nonce-based policy cannot be expressed through static `headers()` - those are
 * applied per response, and a nonce must be unique per request.
 */
function contentSecurityPolicy(): string {
  const mpgsHost = process.env.MPGS_API_BASE_URL
    ? new URL(process.env.MPGS_API_BASE_URL).origin
    : "https://*.gateway.mastercard.com";

  const metaPixelEnabled = process.env.META_PIXEL_ENABLED === "true";
  const metaScript = metaPixelEnabled ? " https://connect.facebook.net" : "";
  const metaFrame = metaPixelEnabled ? " https://www.facebook.com" : "";
  const metaImage = metaPixelEnabled ? " https://www.facebook.com" : "";

  return [
    "default-src 'self'",
    `script-src 'self'${isProduction ? "" : " 'unsafe-inline' 'unsafe-eval'"} https://challenges.cloudflare.com ${mpgsHost}${metaScript}`,
    // Tailwind and next/font inject styles at runtime, so inline styles are
    // unavoidable. Inline *styles* are a far smaller risk than inline scripts.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:" + metaImage,
    "font-src 'self' data:",
    `connect-src 'self' https://challenges.cloudflare.com ${mpgsHost}`,
    `frame-src 'self' https://challenges.cloudflare.com ${mpgsHost}${metaFrame}`,
    // Nothing here is a plugin host or a legitimate framing target.
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'self'",
    ...(isProduction ? ["upgrade-insecure-requests"] : []),
  ].join("; ");
}

/** The baseline header set, applied to every route. */
const securityHeaders = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Content-Security-Policy", value: contentSecurityPolicy() },
];

const nextConfig: NextConfig = {
  // Hides the on-screen dev overlay badge so screen-shares and local
  // walkthroughs of the client preview stay clean. Compile and runtime
  // errors are still surfaced.
  devIndicators: false,

  /**
   * Native modules that must not be bundled.
   *
   * `@node-rs/argon2` is a native addon and `pg` opens raw sockets; bundling
   * either breaks it at runtime on the server.
   */
  serverExternalPackages: ["@node-rs/argon2", "pg", "exceljs"],

  async headers() {
    return [
      {
        // Every route gets the baseline set.
        source: "/:path*",
        headers: securityHeaders,
      },
      {
        /**
         * Admin responses additionally carry `noindex, nofollow`.
         *
         * `robots.txt` asks a crawler not to fetch; this tells one that fetched
         * anyway not to list the page. Public routes deliberately do **not**
         * get this - the marketing site, events list and registration pages
         * should all be indexable.
         */
        source: "/admin/:path*",
        headers: [{ key: "X-Robots-Tag", value: "noindex, nofollow" }],
      },
      {
        source: "/api/:path*",
        headers: [
          { key: "X-Robots-Tag", value: "noindex, nofollow" },
          // API responses are per-request and must never be held by a shared
          // cache - several carry registration and payment state.
          { key: "Cache-Control", value: "no-store, max-age=0" },
        ],
      },
    ];
  },
};

export default nextConfig;
