import { timingSafeEqual } from "node:crypto";

export const CSRF_COOKIE_NAME = "cybershield_csrf";

export function readCsrfCookie(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  for (const pair of cookieHeader.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0 || pair.slice(0, separator).trim() !== CSRF_COOKIE_NAME) continue;
    try { return decodeURIComponent(pair.slice(separator + 1).trim()); }
    catch { return null; }
  }
  return null;
}

export function hasValidCsrfPair(cookieHeader: string | undefined, submittedToken: string | undefined): boolean {
  const cookieToken = readCsrfCookie(cookieHeader);
  if (!cookieToken || !submittedToken) return false;
  const cookieBytes = Buffer.from(cookieToken, "utf8");
  const submittedBytes = Buffer.from(submittedToken, "utf8");
  return cookieBytes.length > 0 && cookieBytes.length === submittedBytes.length && timingSafeEqual(cookieBytes, submittedBytes);
}
