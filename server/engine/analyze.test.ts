import { describe, expect, it } from "vitest";
import { actionForRisk, analyzeScan, redactForHistory } from "./analyze";
import { buildScanPdf } from "./pdf";

describe("CyberShield deterministic analysis", () => {
  it("maps risk bands to one persisted action vocabulary", () => {
    expect([30, 31, 51, 91].map(actionForRisk)).toEqual(["allow", "warn", "strong_warning", "prevent_opening"]);
  });
  it("does not infer risk from an HTTPS official domain alone", () => {
    const result = analyzeScan({ scanType: "url", content: "https://google.com" });
    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe("Very Low");
    expect(result.safeAlternative).toBeUndefined();
  });

  it("flags a high-confidence Google lookalike and suggests the listed official domain", () => {
    const result = analyzeScan({ scanType: "url", content: "https://g00gle.com/login" });
    expect(result.riskScore).toBeGreaterThanOrEqual(71);
    expect(result.riskLevel).toBe("Very High");
    expect(result.safeAlternative).toBe("google.com");
    expect(result.reasons.join(" ")).toContain("Possible brand impersonation");
  });

  it("uses the same URL signals in link context", () => {
    const result = analyzeScan({ scanType: "link", content: "Click now: https://g00gle.com/verify" });
    expect(result.riskScore).toBeGreaterThanOrEqual(71);
    expect(result.safeAlternative).toBe("google.com");
  });

  it("scores urgent KYC and OTP smishing patterns with concrete reasons", () => {
    const result = analyzeScan({ scanType: "sms", content: "URGENT: Your bank KYC is blocked. Send your OTP and verify your account immediately." });
    expect(result.riskScore).toBeGreaterThanOrEqual(51);
    expect(result.riskLevel).toBe("Critical");
    expect(result.reasons.some(reason => reason.includes("One-time code request"))).toBe(true);
    expect(result.reasons.some(reason => reason.includes("Urgency or pressure"))).toBe(true);
  });

  it("scores phishing email with urgency, credential requests, and spoofed sender", () => {
    const emailContent = `From: Security Team <security@amaz0n-security.com>
Subject: Urgent: Verify your Amazon account immediately
Dear Customer,
Your account has been suspended due to suspicious activity.
Click the link below immediately to enter your password and verify your payment card details:
https://amaz0n-security.com/login`;
    const result = analyzeScan({ scanType: "email", content: emailContent });
    expect(result.riskScore).toBeGreaterThanOrEqual(70);
    expect(result.riskLevel).toMatch(/High|Very High|Critical/);
    expect(result.threatType).toContain("Phishing");
    expect(result.reasons.some(r => r.includes("Credential request"))).toBe(true);
    expect(result.reasons.some(r => r.includes("Urgency or pressure"))).toBe(true);
  });

  it("scores job / internship scam links with pressure cues", () => {
    const jobScam = "Exclusive Work From Home Internship! Guaranteed $5000/month. Pay registration fee now: https://internship-offer-secure.xyz";
    const result = analyzeScan({ scanType: "link", content: jobScam });
    expect(result.riskScore).toBeGreaterThanOrEqual(30);
    expect(result.indicators.some(i => i.label.includes("Employment or application scam"))).toBe(true);
  });

  it("reviews only user-supplied API information and flags unencrypted transport", () => {
    const result = analyzeScan({ scanType: "api", content: "http://api.example.invalid/v1", context: "Access-Control-Allow-Origin: *" });
    expect(result.riskScore).toBeGreaterThanOrEqual(31);
    expect(result.indicators.some(finding => finding.label === "API over HTTP")).toBe(true);
    expect(result.indicators.some(finding => finding.label === "Wildcard CORS")).toBe(true);
  });

  it("detects embedded APK URLs consistently across repeated scans", () => {
    const input = { scanType: "apk" as const, content: "", fileName: "sample.apk", fileData: Buffer.from("PK\x03\x04 AndroidManifest.xml https://g00gle.com/login").toString("base64") };
    const first = analyzeScan(input);
    const second = analyzeScan(input);
    expect(first.riskScore).toBe(second.riskScore);
    expect(first.indicators).toEqual(second.indicators);
    expect(first.indicators.some(finding => finding.label === "Embedded URL strings")).toBe(true);
  });

  it("redacts credential-like values before history and PDF report creation", () => {
    const source = "https://example.invalid/?access_token=ABC123&api_key=XYZ";
    const redacted = redactForHistory(source);
    expect(redacted).not.toContain("ABC123");
    expect(redacted).not.toContain("XYZ");
    const pdf = buildScanPdf({ id: "scan-id", userId: 7, userName: "Sample User", userEmail: "sample@example.invalid", createdAt: new Date("2026-01-01T00:00:00Z"), scanType: "url", inputReference: redacted, riskScore: 0, riskLevel: "Very Low", action: "allow", threatType: "No known indicators", reasons: "[]", recommendation: "Verify independently." });
    expect(pdf.subarray(0, 8).toString("ascii")).toContain("%PDF-1.4");
    const pdfText = pdf.toString("ascii");
    expect(pdfText).not.toContain("ABC123");
    expect(pdfText).toContain("Owner account ID: 7");
    expect(pdfText).toContain("Explanation:");
    expect(pdfText).toContain("Final action:");
  });

  it("redacts URL user-info, session/key parameters and bearer tokens", () => {
    const source = "https://alice:secret@example.invalid/login?session_id=SESSIONABC&key=KEYABC Authorization: Bearer BEARERABC123";
    const redacted = redactForHistory(source);
    for (const secret of ["alice", "secret@", "SESSIONABC", "KEYABC", "BEARERABC123"]) expect(redacted).not.toContain(secret);
  });
});
