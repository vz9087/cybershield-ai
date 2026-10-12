const MAX_SCREENSHOT_BYTES = 400 * 1024;

export function sanitizeScreenshotDataUri(value?: string): string | null {
  if (value === undefined || value === "") return null;
  if (value.length > 560_000) throw new Error("Screenshot must be 400 KB or smaller.");
  const match = /^data:(image\/(?:png|jpeg|webp));base64,([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!match) throw new Error("Screenshot must be a PNG, JPEG or WebP image.");
  const [, mime, base64] = match;
  const bytes = Buffer.from(base64, "base64");
  if (!bytes.length || bytes.length > MAX_SCREENSHOT_BYTES || bytes.toString("base64") !== base64) throw new Error("Screenshot is invalid or exceeds 400 KB.");
  const isPng = mime === "image/png" && bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  const isJpeg = mime === "image/jpeg" && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff && bytes[bytes.length - 2] === 0xff && bytes[bytes.length - 1] === 0xd9;
  const isWebp = mime === "image/webp" && bytes.toString("ascii", 0, 4) === "RIFF" && bytes.toString("ascii", 8, 12) === "WEBP";
  if (!isPng && !isJpeg && !isWebp) throw new Error("Screenshot content does not match its declared image type.");
  return `data:${mime};base64,${base64}`;
}
