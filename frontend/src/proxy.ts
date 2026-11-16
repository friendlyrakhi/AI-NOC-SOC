import { NextResponse, type NextRequest } from "next/server";

/**
 * Optimistic check only (no session validation here): requests without a session cookie
 * go to sign-in. Real authorization happens in the API on every call.
 */
const PUBLIC_PREFIXES = ["/login", "/invite", "/api/health"];

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (PUBLIC_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return NextResponse.next();
  }
  if (!request.cookies.has("nocsoc_session")) {
    const url = new URL("/login", request.url);
    if (pathname !== "/") url.searchParams.set("next", `${pathname}${search}`);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
