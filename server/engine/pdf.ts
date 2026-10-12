type PdfScan = { id: string; userId?: number; userName?: string | null; userEmail?: string | null; fileHash?: string | null; createdAt: Date | string; scanType: string; inputReference: string; riskScore: number; riskLevel: string; action?: string | null; threatType: string; reasons: string; recommendation: string; safeAlternative?: string | null };
const esc = (s: string) => s.replace(/[\\()]/g, "\\$&").replace(/[^\x20-\x7e]/g, "?").slice(0, 160);
function linesFor(scan: PdfScan) {
  const reasons: string[] = (() => { try { return JSON.parse(scan.reasons) as string[]; } catch { return [scan.reasons]; } })();
  const owner = [scan.userName, scan.userEmail].filter(Boolean).join(" · ");
  const action = scan.action ?? (scan.riskScore >= 91 ? "prevent_opening" : scan.riskScore >= 51 ? "strong_warning" : scan.riskScore >= 31 ? "warn" : "allow");
  const finalAction = action === "prevent_opening" ? "CRITICAL — Prevent opening; do not continue or submit information. Verify through an independently obtained official channel."
    : action === "strong_warning" ? "STRONG WARNING — Do not continue, install or provide sensitive information."
      : action === "warn" ? "WARNING — Pause and verify the sender or destination independently."
        : "ALLOW WITH CAUTION — No strong configured match; this heuristic result is not proof of safety.";
  const selectedReasons = reasons.slice(0, 8).map(reason => reason.slice(0, 180));
  const result = [
    "CYBERSHIELD AI", "Cyber Threat Analysis Report", "", `Scan ID: ${scan.id}`,
    ...(scan.userId !== undefined ? [`Owner account ID: ${scan.userId}`] : []),
    ...(owner ? [`User: ${owner.slice(0, 180)}`] : []),
    `Date: ${new Date(scan.createdAt).toISOString()}`, `Scan type: ${scan.scanType.toUpperCase()}`,
    `Input/reference: ${scan.inputReference.replace(/\s+/g, " ").slice(0, 320)}`, `Risk score: ${scan.riskScore}%` ,
    `Risk level: ${scan.riskLevel}`, `Threat type: ${scan.threatType}`,
    ...(scan.fileHash ? [`APK SHA-256: ${scan.fileHash}`] : []), "", "Security indicators:",
    ...selectedReasons.map(reason => `- ${reason}`), "", "Explanation:",
    selectedReasons.length ? `${scan.threatType} was assessed from the indicators listed above using deterministic heuristic rules.` : "No configured indicators matched the submitted content.",
    "", "Recommendation:", scan.recommendation.slice(0, 320), "", "Final action:", finalAction,
    ...(scan.safeAlternative ? ["", `Possible official alternative: ${scan.safeAlternative}`] : []),
    "", "This heuristic report is informational and does not guarantee safety.",
  ];
  const wrapped: string[] = [];
  for (const line of result) {
    const words = line.split(/\s+/); let current = "";
    for (const word of words) {
      const next = current ? `${current} ${word}` : word;
      if (next.length > 92) { wrapped.push(current); current = word; } else current = next;
    }
    wrapped.push(current);
  }
  return wrapped.slice(0, 48);
}
export function buildScanPdf(scan: PdfScan) {
  const text = linesFor(scan).map((line, i) => `1 0 0 1 52 ${748 - i * 14} Tm (${esc(line)}) Tj`).join("\n");
  const stream = `BT\n/F1 10 Tf\n${text}\nET`;
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${Buffer.byteLength(stream, "ascii")} >>\nstream\n${stream}\nendstream`,
  ];
  let pdf = "%PDF-1.4\n%CyberShield\n";
  const offsets = [0];
  objects.forEach((object, i) => { offsets.push(Buffer.byteLength(pdf, "ascii")); pdf += `${i + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = Buffer.byteLength(pdf, "ascii");
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf, "ascii");
}
