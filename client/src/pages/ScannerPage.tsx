import { trpc } from "@/lib/trpc";
import { AtSign, ArrowLeft, ArrowRight, Check, FileSearch, Globe2, Image, Info, Link2, LoaderCircle, LockKeyhole, ShieldAlert, ShieldCheck, Smartphone, Upload, ScanLine, type LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "wouter";
import { toast } from "sonner";

const scannerInfo: Record<string, { title: string; icon: LucideIcon; description: string; placeholder: string; tips: string[] }> = {
  url: { title: "Website / URL scanner", icon: Globe2, description: "Review URL structure and known domain indicators without opening the destination.", placeholder: "https://example.com", tips: ["HTTPS is not proof that a site is trustworthy.", "Lookalike domains are checked against a small official-domain list.", "We do not fetch pages or follow redirects."] },
  email: { title: "Email scanner", icon: AtSign, description: "Paste suspicious email text to review sender and social-engineering signals.", placeholder: "From: support@example.com\nSubject: Verify your account\n\nPaste the email body here…", tips: ["Remove private content you do not want to analyze.", "Common urgency, OTP, credential and payment cues are checked.", "Links are analyzed as text; they are not opened."] },
  sms: { title: "SMS / message scanner", icon: Smartphone, description: "Review SMS, WhatsApp-style, Telegram or copied messages for scam patterns.", placeholder: "Your bank KYC has expired. Click here immediately to update your account: https://example.com", tips: ["Never share an OTP or password with a sender.", "Urgency, account, reward and job scam patterns are checked.", "Extracted links are not opened automatically."] },
  link: { title: "Link context scanner", icon: Link2, description: "Paste a link and the message around it for one combined context and URL review.", placeholder: "Click here to claim your reward: https://example.com/claim", tips: ["Short links are not expanded by this scanner.", "Brand alternatives are suggested only for high-confidence matches.", "Use a separately obtained official app or site to verify."] },
  apk: { title: "APK / file scanner", icon: FileSearch, description: "Perform a static review of an APK file. The file is never installed or executed.", placeholder: "Choose an APK file", tips: ["Only APK files up to 10 MB are accepted.", "The file is inspected in memory and not made public.", "This lightweight review does not verify runtime behavior or signing."] },
  api: { title: "Authorized API review", icon: LockKeyhole, description: "Passively review your own API URL and any response-header snapshot you paste.", placeholder: "https://api.your-company.example/v1", tips: ["Only inspect APIs you own or are expressly authorized to assess.", "No network request, fuzzing, exploit attempt or authentication is performed.", "Header and error checks only use text you supply."] },
};
const severity = (score: number) => score >= 91 ? "critical" : score >= 71 ? "very-high" : score >= 51 ? "high" : score >= 31 ? "medium" : "low";
const actionCopy: Record<string, string> = { allow: "ALLOW WITH CAUTION", warn: "PAUSE AND VERIFY", strong_warning: "STRONG WARNING — DO NOT PROCEED", prevent_opening: "PREVENT OPENING — CRITICAL" };
type ScanResult = { id: string; createdAt: Date; riskScore: number; riskLevel: string; action: "allow" | "warn" | "strong_warning" | "prevent_opening"; threatType: string; reasons: string[]; indicators: { label: string; detail: string; points: number }[]; recommendation: string; safeAlternative?: string; normalizedInput: string; fileHash?: string; scanType: string; inputReference: string };
function downloadPdf(base64: string, fileName: string) {
  const binary = atob(base64); const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
  const link = document.createElement("a"); link.href = url; link.download = fileName; link.click(); URL.revokeObjectURL(url);
}
export default function ScannerPage({ type }: { type: string }) {
  const info = scannerInfo[type] ?? scannerInfo.url;
  const Icon = info.icon;
  const [content, setContent] = useState(""); const [context, setContext] = useState(""); const [ack, setAck] = useState(false);
  const [fileName, setFileName] = useState(""); const [fileData, setFileData] = useState(""); const [localError, setLocalError] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [reportOpen, setReportOpen] = useState(false); const [description, setDescription] = useState(""); const [additionalDetails, setAdditionalDetails] = useState("");
  const [screenshotData, setScreenshotData] = useState(""); const [screenshotName, setScreenshotName] = useState(""); const [reportError, setReportError] = useState("");
  const utils = trpc.useUtils();
  const scan = trpc.scan.run.useMutation({ onSuccess: value => { setResult(value); setLocalError(""); setReportOpen(false); } });
  const report = trpc.tickets.create.useMutation({ onSuccess: value => { toast.success("Threat report created", { description: `Ticket #${value.id} · ${value.riskScore === null ? "Risk not scored" : `${value.riskScore}% risk`} · awaiting admin review.` }); setReportOpen(false); setDescription(""); setAdditionalDetails(""); setScreenshotData(""); setScreenshotName(""); void utils.tickets.mine.invalidate(); void utils.user.dashboard.invalidate(); } });
  const pdf = trpc.scan.reportPdf.useMutation({ onSuccess: value => downloadPdf(value.base64, value.fileName) });
  const busy = scan.isPending;
  async function onFile(file?: File) {
    setLocalError(""); setFileData(""); setFileName(""); if (!file) return;
    if (file.size > 50 * 1024 * 1024) { setLocalError("File exceeds the 50 MB upload limit."); return; }
    if (!file.name.toLowerCase().endsWith(".apk")) { setLocalError("Only .apk files are enabled for static analysis."); return; }
    const reader = new FileReader();
    reader.onload = () => { const data = String(reader.result).split(",")[1] ?? ""; setFileData(data); setFileName(file.name); };
    reader.onerror = () => setLocalError("The file could not be read.");
    reader.readAsDataURL(file);
  }
  function onEvidenceFile(file?: File) {
    setReportError(""); setScreenshotData(""); setScreenshotName(""); if (!file) return;
    if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) { setReportError("Use a PNG, JPEG or WebP screenshot."); return; }
    if (file.size > 400 * 1024) { setReportError("Screenshot must be 400 KB or smaller."); return; }
    const reader = new FileReader();
    reader.onload = () => { setScreenshotData(String(reader.result)); setScreenshotName(file.name); };
    reader.onerror = () => setReportError("The screenshot could not be read.");
    reader.readAsDataURL(file);
  }
  function submit() {
    setLocalError("");
    if (type === "api" && !ack) { setLocalError("Confirm authorization before starting an API review."); return; }
    if (type === "apk" && !fileData) { setLocalError("Choose an APK file first."); return; }
    scan.mutate({ scanType: (Object.keys(scannerInfo).includes(type) ? type : "url") as "url" | "email" | "sms" | "link" | "apk" | "api", content, context: context || undefined, fileName: fileName || undefined, fileData: fileData || undefined, authorizationAcknowledged: ack }, { onSettled: () => { void utils.user.dashboard.invalidate(); void utils.scan.history.invalidate(); } });
  }
  function submitReport(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setReportError("");
    if (!result || description.trim().length < 8) { setReportError("Please provide at least eight characters describing the concern."); return; }
    report.mutate({ scanId: result.id, category: result.threatType, description, additionalDetails: additionalDetails || undefined, screenshotData: screenshotData || undefined });
  }
  const expectedType = useMemo(() => type.toUpperCase(), [type]);
  return <>
    <div className="page-heading"><div><p className="eyebrow-small">SHARED CYBER ENGINE · {expectedType}</p><h1>{info.title}</h1><p>{info.description}</p></div><Link className="button button-quiet" href="/dashboard"><ArrowLeft size={14} /> Dashboard</Link></div>
    <div className="scanner-layout"><section className="panel scanner-form"><div className="panel-head"><div><h2>Submit content for analysis</h2><p>Your input is stored in scan history with common secrets redacted.</p></div><Icon size={19} color="#147b73" /></div><div className="panel-body"><div className="form-stack">
      {type === "apk" ? <div><label className="field-label">APK file</label><label className="button button-outline button-sm" htmlFor="apk-file"><Upload size={14} />{fileName || "Choose .apk file"}</label><input id="apk-file" type="file" accept=".apk,application/vnd.android.package-archive" hidden onChange={e => void onFile(e.target.files?.[0])} /><p className="helper">Max 10 MB. Static analysis only; no execution, installation or public file storage.</p></div> : <div><label className="field-label">{type === "api" ? "API endpoint URL" : type === "url" ? "Website URL" : type === "link" ? "Link or surrounding message" : "Message content"}</label>{type === "email" || type === "sms" || type === "link" ? <textarea className="textarea" value={content} onChange={e => setContent(e.target.value)} placeholder={info.placeholder} maxLength={20000} /> : <input className="input" value={content} onChange={e => setContent(e.target.value)} placeholder={info.placeholder} maxLength={20000} />}<p className="helper">Do not submit passwords, one-time codes, payment data or private secrets.</p></div>}
      {type === "api" && <><div><label className="field-label">Optional response-header or error snapshot</label><textarea className="textarea" style={{ minHeight: 100 }} value={context} onChange={e => setContext(e.target.value)} placeholder={'Strict-Transport-Security: max-age=…\nX-Content-Type-Options: nosniff'} maxLength={10000} /><p className="helper">Paste only safe header/error text from an API you are authorized to assess. Redact credentials first.</p></div><label className="check-row"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} /><span>I own or am expressly authorized to review this API. I understand this is a passive review and no endpoint will be contacted.</span></label></>}
      {localError && <div className="notice" role="alert">{localError}</div>}{scan.error && <div className="notice" role="alert">{scan.error.message}</div>}
      <button className="button button-primary" disabled={busy} onClick={submit}>{busy ? <><LoaderCircle size={15} className="spin" /> Analyzing signals…</> : <><ScanLine size={15} /> Analyze with CyberShield <ArrowRight size={14} /></>}</button>
    </div></div></section><aside className="scanner-tips"><h3><Info size={15} /> What this scanner checks</h3><ul>{info.tips.map(tip => <li key={tip}>{tip}</li>)}</ul><div className="banner-note" style={{ marginTop: 14 }}>Risk values are explainable heuristic indicators—not probabilities and not a guarantee of safety.</div></aside></div>
    {result && <section className="risk-result"><div className="result-banner"><div className="result-score">{result.riskScore}<small>%</small></div><div className="result-title"><span className={`risk-pill ${severity(result.riskScore)}`}>{result.riskLevel.toUpperCase()} RISK</span><div className={`action-chip ${severity(result.riskScore)}`}>{actionCopy[result.action]}</div><h2 style={{ marginTop: 8 }}>{result.threatType}</h2><p>Scan {result.id.slice(0, 8)} · {new Date(result.createdAt).toLocaleString()}</p></div></div><div className="result-grid"><div className="result-section"><h3>Why this result</h3>{result.indicators.length ? result.indicators.map((finding, i) => <div className="finding" key={`${finding.label}-${i}`}><span className="finding-dot" /><span><b>{finding.label}</b> — {finding.detail}</span></div>) : <div className="finding"><Check size={14} color="#288768" /><span>{result.reasons[0]}</span></div>}{result.safeAlternative && <div className="banner-note" style={{ marginTop: 12 }}>Possible official alternative: <b>{result.safeAlternative}</b>. Verify it independently before opening.</div>}</div><div className="result-section"><h3>Recommended next step</h3><div className="recommendation">{result.recommendation}</div><p className="supporting" style={{ marginTop: 11 }}>This result is based on configured indicators only. Absence of a match does not prove an item is safe.</p></div></div><div className="result-actions"><button className="button button-sm button-danger" disabled={report.isPending} onClick={() => { setReportOpen(value => !value); setReportError(""); }}><ShieldAlert size={13} /> Report threat</button><button className="button button-sm button-outline" disabled={pdf.isPending} onClick={() => pdf.mutate({ id: result.id })}><FileSearch size={13} /> Download PDF</button><Link className="button button-sm button-outline" href="/history">Scan history <ArrowRight size={13} /></Link><button className="button button-sm button-outline" onClick={() => { setResult(null); setContent(""); setContext(""); setFileData(""); setFileName(""); setLocalError(""); setReportOpen(false); }}>Scan another</button></div>
      {reportOpen && <form className="panel report-form" onSubmit={submitReport}><div className="panel-head"><div><h3>Report this scan for review</h3><p>Category and score are copied from the saved scan; private screenshots remain available only to you and authorized administrators.</p></div><ShieldAlert size={17} color="#a04c3d" /></div><div className="panel-body form-stack"><div className="report-summary"><b>{result.threatType}</b><span>Risk {result.riskScore}% · Scan {result.id.slice(0, 8)}</span></div><div><label className="field-label" htmlFor="report-description">Description</label><textarea className="textarea" id="report-description" value={description} onChange={event => setDescription(event.target.value)} minLength={8} maxLength={2000} required placeholder="Explain why this item should be reviewed…" /></div><div><label className="field-label" htmlFor="report-details">Additional details (optional)</label><textarea className="textarea" id="report-details" value={additionalDetails} onChange={event => setAdditionalDetails(event.target.value)} maxLength={4000} placeholder="Add context, without passwords, codes or secrets." /></div><div><label className="field-label" htmlFor="report-screenshot">Screenshot evidence (optional)</label><input className="input" id="report-screenshot" type="file" accept="image/png,image/jpeg,image/webp" onChange={event => onEvidenceFile(event.target.files?.[0])} /><p className="helper">PNG, JPEG or WebP · 400 KB max · stored privately with the ticket.</p>{screenshotName && <p className="helper"><Image size={13} /> {screenshotName}</p>}</div>{reportError && <div className="notice" role="alert">{reportError}</div>}{report.error && <div className="notice" role="alert">{report.error.message}</div>}<div className="result-actions"><button className="button button-primary" disabled={report.isPending || description.trim().length < 8} type="submit">{report.isPending ? "Submitting…" : "Submit threat report"}</button><button className="button button-quiet" type="button" onClick={() => setReportOpen(false)}>Cancel</button></div></div></form>}
    </section>}
  </>;
}
