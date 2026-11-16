import "server-only";

import { cookies } from "next/headers";

/**
 * BFF session (ADR-0017). The API's opaque session token lives only in an HttpOnly,
 * SameSite=Strict cookie. Browser JavaScript never sees it.
 */
const SESSION_COOKIE = "nocsoc_session";
const CHALLENGE_COOKIE = "nocsoc_challenge";

// Production builds use Secure cookies unless explicitly disabled (the local container runs
// over plain http on 127.0.0.1 until TLS arrives in P7). `next dev` is always plain http.
const secure = process.env.NODE_ENV === "production" && process.env.NOCSOC_COOKIE_SECURE !== "false";

export async function getSessionToken(): Promise<string | undefined> {
  return (await cookies()).get(SESSION_COOKIE)?.value;
}

export async function setSessionToken(token: string): Promise<void> {
  (await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: "/",
    maxAge: 12 * 60 * 60,
  });
}

export async function clearSession(): Promise<void> {
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
  jar.delete(CHALLENGE_COOKIE);
}

export async function getChallenge(): Promise<string | undefined> {
  return (await cookies()).get(CHALLENGE_COOKIE)?.value;
}

export async function setChallenge(challenge: string): Promise<void> {
  (await cookies()).set(CHALLENGE_COOKIE, challenge, {
    httpOnly: true,
    secure,
    sameSite: "strict",
    path: "/",
    maxAge: 5 * 60,
  });
}

export async function clearChallenge(): Promise<void> {
  (await cookies()).delete(CHALLENGE_COOKIE);
}

export const SESSION_COOKIE_NAME = SESSION_COOKIE;
