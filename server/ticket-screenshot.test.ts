import { describe, expect, it } from "vitest";
import { sanitizeScreenshotDataUri } from "./tickets/screenshot";

describe("private ticket screenshot validation", () => {
  it("accepts a PNG data URL with a matching signature", () => {
    const bytes = Buffer.from([137,80,78,71,13,10,26,10,1]);
    const value = `data:image/png;base64,${bytes.toString("base64")}`;
    expect(sanitizeScreenshotDataUri(value)).toBe(value);
  });

  it("rejects non-image payloads, mismatched headers, and oversized values", () => {
    expect(() => sanitizeScreenshotDataUri("data:image/svg+xml;base64,PHN2Zz4=" )).toThrow("PNG, JPEG or WebP");
    expect(() => sanitizeScreenshotDataUri("data:image/png;base64,SGVsbG8=" )).toThrow("does not match");
    expect(() => sanitizeScreenshotDataUri(`data:image/png;base64,${"A".repeat(560_001)}`)).toThrow("400 KB");
  });
});
