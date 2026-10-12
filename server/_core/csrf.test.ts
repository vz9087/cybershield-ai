import { describe, expect, it } from "vitest";
import { CSRF_COOKIE_NAME, hasValidCsrfPair, readCsrfCookie } from "./csrf";

describe("double-submit CSRF protection", () => {
  it("reads the application token from a cookie header and accepts only an equal header token", () => {
    expect(readCsrfCookie(`session=x; ${CSRF_COOKIE_NAME}=safe-token_123`)).toBe("safe-token_123");
    expect(hasValidCsrfPair(`${CSRF_COOKIE_NAME}=safe-token_123`, "safe-token_123")).toBe(true);
  });

  it("rejects missing, mismatched, empty and malformed tokens", () => {
    expect(hasValidCsrfPair(undefined, "token")).toBe(false);
    expect(hasValidCsrfPair(`${CSRF_COOKIE_NAME}=token`, undefined)).toBe(false);
    expect(hasValidCsrfPair(`${CSRF_COOKIE_NAME}=token`, "other")).toBe(false);
    expect(readCsrfCookie(`${CSRF_COOKIE_NAME}=%E0%A4%A`)).toBeNull();
  });
});
