import { createHash, randomBytes } from "node:crypto";
import { domainToASCII } from "node:url";
import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import ApkParser from "app-info-parser";

export type ScanType = "url" | "email" | "sms" | "link" | "apk" | "api";
export type ScanAction = "allow" | "warn" | "strong_warning" | "prevent_opening";
export type Finding = { label: string; detail: string; points: number };
export type Analysis = {
  riskScore: number;
  riskLevel: string;
  threatType: string;
  reasons: string[];
  indicators: Finding[];
  recommendation: string;
  action: ScanAction;
  safeAlternative?: string;
  normalizedInput: string;
  fileHash?: string;
};

const OFFICIAL_BRANDS: Record<string, string> = {
  google: "google.com", amazon: "amazon.com", microsoft: "microsoft.com",
  apple: "apple.com", instagram: "instagram.com", paypal: "paypal.com",
  facebook: "facebook.com", netflix: "netflix.com", linkedin: "linkedin.com",
};
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "shorturl.at", "is.gd", "rb.gy"]);
const SUSPICIOUS = /(?:login|verify|secure|account|update|banking|wallet|gift|reward|claim|urgent|password|credential|otp|kyc|suspend|payment|invoice|bonus|prize|free)/i;
const URL_RE = /\bhttps?:\/\/[^\s<>"')\]]+/gi;

function clampScore(points: number) { return Math.max(0, Math.min(100, Math.round(points))); }
function riskLevel(score: number) {
  if (score <= 10) return "Very Low";
  if (score <= 30) return "Low";
  if (score <= 50) return "Medium";
  if (score <= 70) return "High";
  if (score <= 90) return "Very High";
  return "Critical";
}
export function actionForRisk(score: number): ScanAction {
  if (score >= 91) return "prevent_opening";
  if (score >= 51) return "strong_warning";
  if (score >= 31) return "warn";
  return "allow";
}
function levenshtein(a: string, b: string) {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0]; row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const old = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = old;
    }
  }
  return row[b.length];
}
function cleanSnippet(value: string) {
  return redactForHistory(value).replace(/\b\d{6}\b/g, "[six-digit code]").slice(0, 1800);
}
function add(findings: Finding[], label: string, detail: string, points: number) {
  findings.push({ label, detail, points });
}

export function analyzeUrl(raw: string): { findings: Finding[]; domain: string; safeAlternative?: string; normalized: string; threatType: string } {
  const findings: Finding[] = [];
  const normalized = /^https?:\/\//i.test(raw.trim()) ? raw.trim() : `https://${raw.trim()}`;
  let parsed: URL;
  try { parsed = new URL(normalized); }
  catch { add(findings, "Invalid URL", "Input could not be parsed as a URL.", 12); return { findings, domain: "", normalized: raw, threatType: "Suspicious URL" }; }
  const host = domainToASCII(parsed.hostname.toLowerCase()).replace(/\.$/, "");
  const labels = host.split(".").filter(Boolean);
  const registrable = labels.slice(-2).join(".");
  const knownBrand = Object.entries(OFFICIAL_BRANDS).find(([, domain]) => registrable === domain);
  if (parsed.protocol !== "https:") add(findings, "Insecure transport", "The URL uses HTTP rather than HTTPS. Encryption and server identity are not protected by TLS.", 18);
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":")) add(findings, "IP-based host", "The destination uses a raw IP address instead of a recognizable domain.", 28);
  if (host.startsWith("xn--") || host.split(".").some(label => label.startsWith("xn--"))) add(findings, "Internationalized hostname", "The hostname contains punycode; visually similar Unicode characters may be used.", 22);
  if (labels.length >= 5) add(findings, "Many subdomains", "The hostname has several subdomain labels that can obscure its registered domain.", 10);
  if (parsed.username || parsed.password || raw.includes("@")) add(findings, "Embedded credentials or @", "The URL contains an @ marker or user-info section that can disguise the real host.", 20);
  if (host.length > 50 || parsed.href.length > 150) add(findings, "Unusually long URL", "Long host or URL structure makes the destination harder to inspect.", 7);
  if (SUSPICIOUS.test(`${host}${parsed.pathname}${parsed.search}`)) add(findings, "High-pressure URL terms", "The address includes account, verification, reward or urgency-related terms.", 8);
  if (SHORTENERS.has(registrable)) add(findings, "URL shortener", "The shortened link hides its final destination; this analyzer did not follow it.", 14);
  if (/[\u0000-\u0020\\]/.test(raw) || /%[0-9a-f]{2}/i.test(parsed.pathname + parsed.search)) add(findings, "Encoded or unusual characters", "The address contains escaped or non-printable characters worth reviewing.", 8);
  const normalizedLabel = labels.length > 1 ? labels[labels.length - 2] : labels[0] ?? "";
  const homoglyphLabel = normalizedLabel.replace(/0/g, "o").replace(/[1!]/g, "i").replace(/3/g, "e").replace(/5/g, "s").replace(/\$/g, "s");
  for (const [brand, official] of Object.entries(OFFICIAL_BRANDS)) {
    const officialLabel = official.split(".")[0];
    const exactOfficial = registrable === official;
    if (exactOfficial) continue;
    const distance = levenshtein(homoglyphLabel, officialLabel);
    const containsBrandAsLookalike = homoglyphLabel === officialLabel || (homoglyphLabel.includes(officialLabel) && registrable !== official);
    if (containsBrandAsLookalike || (normalizedLabel.length >= 5 && distance <= 1)) {
      add(findings, "Possible brand impersonation", `The registered domain resembles ${brand} but is not its listed official domain (${official}).`, 72);
      return { findings, domain: registrable, safeAlternative: official, normalized: redactForHistory(parsed.href), threatType: "Typosquatting / Brand impersonation" };
    }
  }
  if (knownBrand && registrable !== knownBrand[1]) add(findings, "Brand mismatch", "The hostname does not match the listed official brand domain.", 20);
  return { findings, domain: registrable, normalized: redactForHistory(parsed.href), threatType: findings.length ? "Suspicious URL" : "No known threat indicators" };
}

function textFindings(text: string, mode: "email" | "sms" | "link") {
  const findings: Finding[] = [];
  const lower = text.toLowerCase();
  if (/\b(urgent|immediately|within \d+ (?:hours?|minutes?)|act now|final warning|today only|account.{0,24}(?:blocked|suspended|closed))\b/i.test(text)) add(findings, "Urgency or pressure", "The message pressures the recipient to act quickly, a common social-engineering technique.", mode === "email" ? 16 : 18);
  if (/\b(?:otp|one[- ]time password|verification code|share.{0,12}code|send.{0,12}otp)\b/i.test(text)) add(findings, "One-time code request", "The message refers to a one-time code or asks the recipient to share it.", 30);
  if (/\b(?:password|passcode|credentials|sign in|log ?in|verify your account|confirm your identity)\b/i.test(text)) add(findings, "Credential request", "The message asks for sign-in details or account verification.", 24);
  if (/\b(?:bank|kyc|account.{0,18}(?:expire|blocked|suspend)|card|refund|payment|upi)\b/i.test(text)) add(findings, "Financial or account context", "Banking, KYC, payment or account-access language is present.", mode === "sms" ? 22 : 18);
  if (/\b(?:prize|reward|gift card|lottery|claim.{0,16}free|won.{0,16}money)\b/i.test(text)) add(findings, "Prize or reward lure", "A reward or prize claim is used to prompt action.", 18);
  if (/\b(?:job|internship|scholarship|application fee|registration fee|work from home)\b/i.test(text) && /\b(?:fee|pay|deposit|guaranteed|apply now|limited)\b/i.test(text)) add(findings, "Employment or application scam cues", "Employment or scholarship language is paired with payment or pressure cues.", 22);
  if (mode === "email") {
    const fromLine = text.match(/^\s*(?:from|sender)\s*:\s*(.+)$/im)?.[1] ?? "";
    const address = fromLine.match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i)?.[1]?.toLowerCase();
    if (address) {
      const labels = address.split(".");
      const senderDomain = labels.slice(-2).join(".");
      const impersonated = Object.entries(OFFICIAL_BRANDS).find(([brand, official]) => fromLine.toLowerCase().includes(brand) && senderDomain !== official);
      if (impersonated) add(findings, "Sender-brand mismatch", `The sender line mentions ${impersonated[0]} but the supplied sender domain (${senderDomain}) is not its listed official domain.`, 36);
      const senderUrl = analyzeUrl(address);
      for (const f of senderUrl.findings) if (f.label === "Possible brand impersonation" || f.label === "Internationalized hostname" || f.label === "IP-based host") add(findings, `Sender domain: ${f.label}`, f.detail, Math.min(72, f.points));
    }
  }
  if (/\b(?:click|open|tap|visit)\b/i.test(text) && /https?:\/\//i.test(text)) add(findings, "Action link in message", "A message asks the recipient to follow an embedded link.", 12);
  if (/\b(?:attachment|attached|document|invoice|apk|install the app)\b/i.test(text)) add(findings, "Attachment or app reference", "The message references a file or application that should be verified independently.", 8);
  const urls = text.match(URL_RE) ?? [];
  for (const raw of urls.slice(0, 5)) {
    const urlResult = analyzeUrl(raw.replace(/[.,!?;:]+$/, ""));
    for (const f of urlResult.findings) add(findings, f.label, `Linked destination: ${f.detail}`, f.points);
  }
  if (mode === "link" && urls.length === 0 && SUSPICIOUS.test(lower)) add(findings, "Link context without destination", "The surrounding text uses a high-pressure call to action, but no destination URL was included for checking.", 12);
  return findings;
}

function apiFindings(raw: string, context: string) {
  const findings: Finding[] = [];
  const parsed = analyzeUrl(raw);
  findings.push(...parsed.findings);
  if (/^http:\/\//i.test(raw.trim())) add(findings, "API over HTTP", "API endpoint is not encrypted in transit.", 22);
  const headers = context.toLowerCase();
  const hasHeaderSnapshot = /(?:^|\n)\s*(?:content-security-policy|strict-transport-security|x-content-type-options|x-frame-options|referrer-policy|access-control-allow-origin)\s*:/i.test(context);
  if (hasHeaderSnapshot) {
    const expected: Array<[RegExp, string, number]> = [
      [/^strict-transport-security\s*:/im, "HSTS header not present in supplied snapshot", 8],
      [/^x-content-type-options\s*:/im, "X-Content-Type-Options header not present in supplied snapshot", 5],
      [/^content-security-policy\s*:/im, "Content-Security-Policy header not present in supplied snapshot", 6],
    ];
    expected.forEach(([re, label, score]) => { if (!re.test(context)) add(findings, label, "This header was absent from the response-header text you supplied.", score); });
    if (/access-control-allow-origin:\s*\*/i.test(context)) add(findings, "Wildcard CORS", "Supplied headers allow cross-origin requests from every origin; confirm this is intentional.", 15);
  } else {
    add(findings, "No response snapshot", "No response-header snapshot was supplied; live connectivity and headers were not tested.", 0);
  }
  if (/(?:stack trace|sql syntax|exception at|internal server error|database password)/i.test(context)) add(findings, "Error detail exposure", "The supplied sample includes stack-trace, exception or internal error language.", 20);
  if (/(?:api[_-]?key|access[_-]?token|secret)\s*[:=]\s*[^\s,;]+/i.test(context)) add(findings, "Possible secret in sample", "The submitted sample may contain a secret. It is redacted from stored history; rotate exposed credentials.", 25);
  return findings;
}

export async function analyzeScan(input: { scanType: ScanType; content: string; context?: string; fileName?: string; fileData?: string }): Promise<Analysis> {
  const { scanType } = input;
  const raw = input.content.trim();
  let findings: Finding[] = [];
  let normalizedInput = cleanSnippet(raw);
  let safeAlternative: string | undefined;
  let threatType = "No known threat indicators";
  let fileHash: string | undefined;
  if (scanType === "url" || scanType === "link") {
    if (!raw) throw new Error("Enter a URL or message to scan.");
    if (scanType === "url") {
      const r = analyzeUrl(raw); findings = r.findings; safeAlternative = r.safeAlternative; normalizedInput = r.normalized; threatType = r.threatType;
    } else {
      findings = textFindings(raw, "link");
      const urls = raw.match(URL_RE) ?? [];
      normalizedInput = cleanSnippet(raw);
      if (urls.length && urls[0]) {
        const r = analyzeUrl(urls[0].replace(/[.,!?;:]+$/, "")); safeAlternative = r.safeAlternative;
        threatType = r.threatType;
      }
    }
  } else if (scanType === "email" || scanType === "sms") {
    if (!raw) throw new Error("Paste message content to scan.");
    findings = textFindings(raw, scanType);
    threatType = scanType === "email" ? "Email phishing / social engineering review" : "Smishing / message scam review";
  } else if (scanType === "api") {
    if (!/^https?:\/\//i.test(raw)) throw new Error("Enter a complete API endpoint URL beginning with https:// or http://.");
    const safeRaw = redactForHistory(raw);
    if (input.context && /(?:api[_-]?key|access[_-]?token|client[_-]?secret|authorization|password|secret)\s*[:=]\s*(?:bearer\s+)?\S+/i.test(input.context)) normalizedInput = `${safeRaw} · header snapshot (sensitive values redacted)`;
    else normalizedInput = `${safeRaw} · passive review only`;
    findings = apiFindings(raw, input.context ?? "");
    threatType = "API configuration review";
  } else {
    // ============ APK BRANCH ============
    if (!input.fileData || !input.fileName) throw new Error("Select an APK file to scan.");

    const bytes = Buffer.from(input.fileData, "base64");
    if (bytes.length === 0) throw new Error("APK file is empty.");
    if (bytes.length > 50 * 1024 * 1024) throw new Error("APK is larger than 50 MB.");
    if (!input.fileName.toLowerCase().endsWith(".apk")) {
      throw new Error("Only .apk uploads are enabled for static review.");
    }

    fileHash = createHash("sha256").update(bytes).digest("hex");
    normalizedInput = `${input.fileName.replace(/[\\/\0-\x1f]/g, "_").slice(0, 150)} (${(bytes.length / 1024 / 1024).toFixed(2)} MB)`;

    // ZIP signature check
    if (bytes[0] !== 0x50 || bytes[1] !== 0x4b) {
      add(findings, "Unexpected container signature", "The file name ends in .apk but its bytes do not begin with a ZIP signature.", 30);
    }

    // === Parse the APK with app-info-parser ===
    let manifest: any = null;
    let parseError: string | null = null;
    let permissions: string[] = [];
    const tempPath = join(tmpdir(), `cybershield-${randomBytes(8).toString("hex")}.apk`);

    try {
      await writeFile(tempPath, bytes);

      const parsePromise = (async () => {
        const parser = new ApkParser(tempPath);
        return await parser.parse();
      })();

      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Parser timed out after 5s")), 5000)
      );

      manifest = await Promise.race([parsePromise, timeoutPromise]);

      // app-info-parser returns permissions as `usesPermissions` (plural),
      // an array of objects like { name: "android.permission.INTERNET" }.
      const rawPerms =
        manifest?.usesPermissions ??
        manifest?.["uses-permission"] ??
        manifest?.usesPermission ??
        [];

      permissions = Array.isArray(rawPerms)
        ? rawPerms
          .map((p: any) => (typeof p === "string" ? p : p?.name))
          .filter((p: any): p is string => typeof p === "string" && p.length > 0)
        : [];

      console.log("[apk] parsed OK:", {
        package: manifest?.package,
        permissionCount: permissions.length,
        first: permissions.slice(0, 3),
      });
    } catch (err) {
      parseError = err instanceof Error ? err.message : String(err);
      console.error("[apk] parse failed:", parseError);
    } finally {
      try { await unlink(tempPath); } catch { /* ignore */ }
    }

    const packageName: string = manifest?.package ?? "(unknown)";
    const versionName: string = manifest?.versionName ?? "?";

    // === Dangerous permission weights ===
    const DANGEROUS: Record<string, number> = {
      "android.permission.READ_SMS": 15,
      "android.permission.SEND_SMS": 15,
      "android.permission.RECEIVE_SMS": 15,
      "android.permission.READ_CONTACTS": 8,
      "android.permission.WRITE_CONTACTS": 6,
      "android.permission.RECORD_AUDIO": 12,
      "android.permission.CAMERA": 10,
      "android.permission.ACCESS_FINE_LOCATION": 8,
      "android.permission.ACCESS_COARSE_LOCATION": 5,
      "android.permission.ACCESS_BACKGROUND_LOCATION": 12,
      "android.permission.READ_PHONE_STATE": 6,
      "android.permission.READ_PHONE_NUMBERS": 8,
      "android.permission.CALL_PHONE": 12,
      "android.permission.PROCESS_OUTGOING_CALLS": 14,
      "android.permission.SYSTEM_ALERT_WINDOW": 18,
      "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,
      "android.permission.REQUEST_INSTALL_PACKAGES": 15,
      "android.permission.WRITE_SETTINGS": 10,
      "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": 12,
      "android.permission.READ_EXTERNAL_STORAGE": 4,
      "android.permission.WRITE_EXTERNAL_STORAGE": 4,
      "android.permission.MANAGE_EXTERNAL_STORAGE": 14,
      "android.permission.INTERNET": 2,
      "android.permission.RECEIVE_BOOT_COMPLETED": 9,
      "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": 10,
      "android.permission.PACKAGE_USAGE_STATS": 8,
      "android.permission.QUERY_ALL_PACKAGES": 12,
      "android.permission.BIND_DEVICE_ADMIN": 22,
      "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": 20,
      "android.permission.READ_CALL_LOG": 16,
      "android.permission.WRITE_CALL_LOG": 14,
    };

    if (permissions.length > 0) {
      add(
        findings,
        "APK parsed successfully",
        `Package: ${packageName} · Version: ${versionName} · ${permissions.length} permissions declared.`,
        0
      );

      for (const perm of permissions) {
        const weight = DANGEROUS[perm];
        if (weight) {
          add(findings, perm.split(".").pop() ?? perm, `Dangerous permission declared: ${perm}`, weight);
        }
      }

      // Combination detection
      const has = (s: string) => permissions.some(p => p.includes(s));
      if (has("SMS") && has("SYSTEM_ALERT_WINDOW")) {
        add(findings, "SMS + overlay combination", "SMS interception combined with overlay windows is the standard banking-trojan pattern.", 15);
      }
      if (has("ACCESSIBILITY") && has("SYSTEM_ALERT_WINDOW")) {
        add(findings, "Accessibility + overlay combination", "Accessibility service + overlay is a credential-stealing pattern.", 20);
      }
      if (has("RECORD_AUDIO") && has("INTERNET")) {
        add(findings, "Audio recording + network", "App can record audio and send data over the network.", 10);
      }
      if (has("READ_CONTACTS") && has("SEND_SMS")) {
        add(findings, "Contacts + SMS send combination", "App can read contacts and send SMS — a known propagation pattern.", 12);
      }
      if (has("BIND_ACCESSIBILITY_SERVICE")) {
        add(findings, "Accessibility service", "App declares an accessibility service — often abused for screen scraping and auto-clicking.", 15);
      }
    } else {
      // Fallback string scanning
      const strings = bytes.toString("latin1");
      const fallbackRules: Array<[RegExp, string, number]> = [
        [/android\.permission\.READ_SMS/i, "SMS read (raw string)", 16],
        [/android\.permission\.SEND_SMS/i, "SMS send (raw string)", 20],
        [/android\.permission\.SYSTEM_ALERT_WINDOW/i, "Overlay (raw string)", 12],
        [/android\.permission\.REQUEST_INSTALL_PACKAGES/i, "Package install (raw string)", 18],
        [/android\.permission\.READ_CONTACTS/i, "Contacts read (raw string)", 8],
      ];
      fallbackRules.forEach(([re, label, score]) => {
        if (re.test(strings)) add(findings, label, "Found in raw binary strings.", score);
      });
      if (findings.length === 0) {
        add(
          findings,
          "APK could not be deeply parsed",
          parseError
            ? `Parser error: ${parseError}`
            : "No permissions extracted and no known risky strings found.",
          0
        );
      }
    }

    // Dynamic loading / exec strings
    const rawStrings = bytes.toString("latin1");
    if (/\b(?:dexclassloader|su\s+-c|Runtime\.getRuntime\(\)\.exec|loadLibrary\()/i.test(rawStrings)) {
      add(findings, "Dynamic code execution strings", "Contains strings associated with runtime code loading or shell execution.", 18);
    }

    // Embedded URLs
    URL_RE.lastIndex = 0;
    if (URL_RE.test(rawStrings)) {
      URL_RE.lastIndex = 0;
      add(findings, "Embedded URL strings", "The APK contains HTTP(S) URLs. Their reputation was not queried.", 12);
    }

    threatType = "APK static indicator review";
  }

  const score = clampScore(findings.reduce((sum, finding) => sum + finding.points, 0));
  const hasThreat = score > 10 || findings.some(f => f.points >= 18);
  if (scanType === "email" && hasThreat) threatType = "Phishing / social engineering";
  if (scanType === "sms" && hasThreat) threatType = /kyc|bank|financial/i.test(findings.map(f => f.label).join(" ")) ? "Smishing / possible bank scam" : "Smishing / social engineering";
  if (scanType === "link" && hasThreat && threatType === "No known threat indicators") threatType = "Suspicious link / social engineering";
  if (scanType === "apk" && score > 10) threatType = "Suspicious APK indicators";
  const reasons = findings.filter(f => f.points > 0).map(f => `${f.label}: ${f.detail}`);
  const recommendation = score >= 71
    ? "Do not continue, install, or provide information. Verify through a separately obtained official channel and report this item if appropriate."
    : score >= 31
      ? "Pause and verify the sender or destination independently. Do not share passwords, one-time codes or payment details."
      : "No strong configured indicators were found. This is not proof of safety; verify the destination independently before sharing sensitive information.";
  return { riskScore: score, riskLevel: riskLevel(score), threatType, reasons: reasons.length ? reasons : ["No configured risk indicators matched the submitted content."], indicators: findings, recommendation, action: actionForRisk(score), safeAlternative, normalizedInput, fileHash };
}

export function redactForHistory(value: string) {
  const noUrlUserInfo = value.replace(URL_RE, candidate => {
    try {
      const parsed = new URL(candidate);
      if (parsed.username || parsed.password) {
        if (parsed.username) parsed.username = "[redacted]";
        if (parsed.password) parsed.password = "[redacted]";
        return parsed.toString();
      }
    } catch { /* keep malformed input for other redaction rules */ }
    return candidate;
  });
  return noUrlUserInfo
    .replace(/((?:password|passcode|otp|(?:access[_ -]?)?token|api[_ -]?key|client[_ -]?secret|secret|authorization|auth[_ -]?token|session(?:[_ -]?id)?|private[_ -]?key|signature|credential|cookie|csrf|key)\s*[:=]\s*)(?:bearer\s+)?[^&\s,;]+/gi, "$1[redacted]")
    .replace(/([?&][^=&#]*(?:token|key|secret|signature|credential|session|auth|password)[^=&#]*=)[^&#\s]*/gi, "$1[redacted]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]{8,}/gi, "Bearer [redacted]")
    .replace(/\b\d{6}\b/g, "[six-digit code]").slice(0, 2000);
}
