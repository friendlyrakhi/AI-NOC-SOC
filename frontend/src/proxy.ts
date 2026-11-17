import { NextResponse, type NextRequest } from "next/server";

/**
 * Optimistic check only (no session validation here): requests without a session cookie
 * go to sign-in. Real authorization happens in the API on every call.
 */
const PUBLIC_PREFIXES = ["/login", "/invite", "/api/health"];

/**
 * Content Security Policy (threat model T2, P7: found missing by the DAST baseline). Scripts run only
 * with this request's nonce ('strict-dynamic' lets Next's own loader add chunks). Next.js reads the
 * policy from the request headers and puts the nonce on its scripts. Inline style attributes are
 * still allowed (React style props, charts); they cannot execute code.
 */
function contentSecurityPolicy(nonce: string): string {
  const devEval = process.env.NODE_ENV === "production" ? "" : " 'unsafe-eval'"; // React dev tooling only
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${devEval}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join("; ");
}

function withPolicy(request: NextRequest): NextResponse {
  const nonce = btoa(crypto.randomUUID());
  const policy = contentSecurityPolicy(nonce);
  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", policy);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (PUBLIC_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return withPolicy(request);
  }
  if (!request.cookies.has("nocsoc_session")) {
    const url = new URL("/login", request.url);
    if (pathname !== "/") url.searchParams.set("next", `${pathname}${search}`);
    return NextResponse.redirect(url);
  }
  return withPolicy(request);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
