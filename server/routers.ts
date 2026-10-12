import { TRPCError } from "@trpc/server";
import { createHash, randomUUID } from "node:crypto";
import type { Request } from "express";
import { z } from "zod";
import { adminProcedure, protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { sdk } from "./_core/sdk";
import { hashPassword, passwordMeetsPolicy, validEmail, verifyPassword } from "./_core/passwords";
import { systemRouter } from "./_core/systemRouter";
import * as db from "./db";
import { actionForRisk, analyzeScan, redactForHistory } from "./engine/analyze";
import { buildScanPdf } from "./engine/pdf";
import { awarenessQuestions, scoreAwarenessAnswers } from "./awareness";
import { sanitizeScreenshotDataUri } from "./tickets/screenshot";
import { canTransitionTicket, TICKET_STATUSES } from "@shared/ticket-workflow";

const scanType = z.enum(["url", "email", "sms", "link", "apk", "api"]);
const ticketStatus = z.enum(TICKET_STATUSES);
const scanWindows = new Map<number, number[]>();
const authWindows = new Map<string, number[]>();
function authBucketAllowed(key: string, limit: number, windowMs: number) {
  const now = Date.now();
  const active = (authWindows.get(key) ?? []).filter(stamp => now - stamp < windowMs);
  if (active.length >= limit) { authWindows.set(key, active); return false; }
  active.push(now); authWindows.set(key, active);
  if (authWindows.size > 5000) for (const [bucket, stamps] of authWindows) if (!stamps.some(stamp => now - stamp < 60 * 60 * 1000)) authWindows.delete(bucket);
  return true;
}
function allowAuthAttempt(req: Request, scope: string, email: string, accountLimit: number, windowMs: number) {
  const ip = (req.ip || req.socket.remoteAddress || "unknown").slice(0, 80);
  const digest = createHash("sha256").update(`${scope}:${email}`).digest("hex");
  return authBucketAllowed(`ip:${ip}`, scope === "login" ? 30 : 12, scope === "login" ? 15 * 60 * 1000 : 60 * 60 * 1000)
    && authBucketAllowed(`${scope}:${ip}:${digest}`, accountLimit, windowMs);
}
function enforceScanRateLimit(userId: number) {
  const now = Date.now();
  const active = (scanWindows.get(userId) ?? []).filter(stamp => now - stamp < 60 * 60 * 1000);
  if (active.length >= 40) throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Scan limit reached. Please try again later." });
  active.push(now); scanWindows.set(userId, active);
}
function parseJson<T>(value: string, fallback: T): T { try { return JSON.parse(value) as T; } catch { return fallback; } }
function normalizedIndicator(scanType: string, normalized: string, hash?: string) {
  if (scanType === "apk") return hash ? `sha256:${hash}` : "";
  const url = normalized.match(/https?:\/\/[^\s<>"')\]]+/i)?.[0];
  if (url) { try { const parsed = new URL(url); return parsed.username || parsed.password ? "" : parsed.hostname.toLowerCase().replace(/^www\./, ""); } catch { /* no valid domain */ } }
  if (scanType === "email") {
    const sender = normalized.match(/^from:\s*(?:[^<\n]*<)?[^@\s<>]+@([a-z0-9.-]+\.[a-z]{2,63})/im);
    if (sender?.[1]) return sender[1].toLowerCase();
  }
  return "";
}
function safeIndicator(value?: string) {
  if (!value) return null;
  const safe = redactForHistory(value.trim());
  if (/^sha256:[a-f0-9]{64}$/i.test(safe)) return safe.toLowerCase();
  let candidate = safe;
  try { if (!/^https?:\/\//i.test(candidate)) candidate = `https://${candidate}`; const parsed = new URL(candidate); if (parsed.username || parsed.password) return null; const host = parsed.hostname.toLowerCase().replace(/^www\./, ""); return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ? host : null; } catch { return null; }
}
async function recordAuthFailure(action: "auth.login.failed" | "auth.registration.failed", userId: number | null = null) {
  try { await db.addSecurityLog(userId, action, "failure"); } catch { /* preserve the generic auth response if logging is unavailable */ }
}
function formatScan(row: Awaited<ReturnType<typeof db.getScanForUser>>) {
  if (!row) return null;
  return { ...row, reasons: parseJson<string[]>(row.reasons, []), indicators: parseJson<unknown[]>(row.indicators, []) };
}
async function notifyAdmins(title: string, message: string, type: string) {
  const admins = (await db.listUsers()).filter(user => user.role === "admin" && user.status === "active");
  await Promise.all(admins.map(async admin => { await db.createNotification(admin.id, title, message, type); await db.recordEmailIntent(admin.email ?? null, title, message); }));
}

const scansRouter = router({
  run: protectedProcedure.input(z.object({
    scanType,
    content: z.string().max(20_000),
    context: z.string().max(10_000).optional(),
    fileName: z.string().max(180).optional(),
    fileData: z.string().max(70_000_000).optional(),
    authorizationAcknowledged: z.boolean().optional(),
  })).mutation(async ({ input, ctx }) => {
    enforceScanRateLimit(ctx.user.id);
    if (input.scanType === "api" && !input.authorizationAcknowledged) throw new TRPCError({ code: "FORBIDDEN", message: "Confirm that you own or are authorized to review this API." });
    if (input.scanType === "apk" && !input.fileName) throw new TRPCError({ code: "BAD_REQUEST", message: "Choose an APK file." });
    let result: Awaited<ReturnType<typeof analyzeScan>>;
    try { result = await analyzeScan(input); }
    catch (error) { throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "Unable to analyze this input." }); }
    const indicator = normalizedIndicator(input.scanType, result.normalizedInput, result.fileHash);
    const known = indicator ? await db.findThreat(indicator) : undefined;
    if (known && (known.status === "confirmed" || known.status === "blocked")) {
      result.riskScore = Math.max(result.riskScore, known.riskScore, known.status === "blocked" ? 98 : 92);
      result.riskLevel = result.riskScore >= 91 ? "Critical" : result.riskScore >= 71 ? "Very High" : "High";
      result.action = actionForRisk(result.riskScore);
      result.threatType = known.threatType;
      result.recommendation = "Do not continue, install or provide information. This indicator matches the internal threat intelligence database; verify through an independently obtained official channel.";
      result.reasons.unshift(`Known ${known.status} indicator: this item matches the internal threat intelligence database.`);
      result.indicators.unshift({ label: `Known ${known.status} threat`, detail: "Confirmed by the CyberShield threat database.", points: known.riskScore });
    }
    const id = crypto.randomUUID();
    const inputReference = input.scanType === "apk" ? result.normalizedInput : redactForHistory(result.normalizedInput);
    await db.createScanRecord({
      id, userId: ctx.user.id, scanType: input.scanType, inputReference,
      riskScore: result.riskScore, riskLevel: result.riskLevel, action: result.action, threatType: result.threatType,
      reasons: JSON.stringify(result.reasons), indicators: JSON.stringify(result.indicators),
      recommendation: result.recommendation, safeAlternative: result.safeAlternative ?? null, fileHash: result.fileHash ?? null,
    });
    await db.addSecurityLog(ctx.user.id, "scan.completed", "success", `${input.scanType}:${result.riskLevel}`);
    if (input.scanType === "apk") await db.addSecurityLog(ctx.user.id, "file.scan.uploaded", "success", result.fileHash ? `sha256:${result.fileHash}` : undefined);
    if (result.riskScore >= 51) {
      await db.createNotification(ctx.user.id, "High-risk indicators found", `Your ${input.scanType.toUpperCase()} scan detected ${result.riskLevel.toLowerCase()} risk indicators. Review the evidence before acting.`, "warning");
      await db.recordEmailIntent(ctx.user.email ?? null, "High-Risk Cyber Threat Detected");
      if (result.riskScore >= 91) await notifyAdmins("Critical Cyber Threat Detected", `A critical ${input.scanType.toUpperCase()} scan was recorded with risk score ${result.riskScore}%.`, "danger");
    } else {
      await db.createNotification(ctx.user.id, "Scan completed", `Your ${input.scanType.toUpperCase()} scan is ready to review.`, "info");
    }
    return { ...result, id, scanType: input.scanType, createdAt: new Date(), inputReference };
  }),
  history: protectedProcedure.input(z.object({ scanType: scanType.optional() }).optional()).query(({ ctx, input }) => db.listUserScans(ctx.user.id, input?.scanType)),
  get: protectedProcedure.input(z.object({ id: z.string().uuid() })).query(async ({ ctx, input }) => {
    const row = await db.getScanForUser(input.id, ctx.user.id);
    if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found." });
    return formatScan(row);
  }),
  reportPdf: protectedProcedure.input(z.object({ id: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    const row = ctx.user.role === "admin" ? await db.getScanById(input.id) : await db.getScanForUser(input.id, ctx.user.id);
    if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found." });
    const owner = await db.getUserById(row.userId);
    const pdf = buildScanPdf({ ...row, userName: owner?.name ?? null, userEmail: owner?.email ?? null });
    await db.createNotification(ctx.user.id, "Security report generated", `A PDF report was generated for scan ${row.id.slice(0, 8)}.`, "info");
    await db.addSecurityLog(ctx.user.id, "report.generated", "success", `scan:${row.id}`);
    return { fileName: `cybershield-report-${row.id.slice(0, 8)}.pdf`, base64: pdf.toString("base64") };
  }),
});

const ticketsRouter = router({
  mine: protectedProcedure.query(({ ctx }) => db.listUserTickets(ctx.user.id)),
  evidence: protectedProcedure.input(z.object({ id: z.number().int().positive() })).query(async ({ ctx, input }) => {
    const ticket = await db.getTicketEvidence(input.id);
    if (!ticket || (ctx.user.role !== "admin" && ticket.userId !== ctx.user.id) || !ticket.screenshotData) throw new TRPCError({ code: "NOT_FOUND", message: "Evidence is not available to this account." });
    return { data: ticket.screenshotData };
  }),
  create: protectedProcedure.input(z.object({ scanId: z.string().uuid().optional(), category: z.string().min(2).max(100), description: z.string().min(8).max(2000), additionalDetails: z.string().max(4000).optional(), screenshotData: z.string().max(560_000).optional(), indicator: z.string().max(500).optional() })).mutation(async ({ ctx, input }) => {
    let scan;
    if (input.scanId) {
      scan = await db.getScanForUser(input.scanId, ctx.user.id);
      if (!scan) throw new TRPCError({ code: "NOT_FOUND", message: "Scan not found." });
    }
    let screenshotData: string | null;
    try { screenshotData = sanitizeScreenshotDataUri(input.screenshotData); }
    catch (error) { throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "Screenshot could not be validated." }); }
    const category = (scan?.threatType ?? redactForHistory(input.category)).slice(0, 100);
    const indicator = scan ? normalizedIndicator(scan.scanType, scan.inputReference, scan.fileHash ?? undefined) : safeIndicator(input.indicator);
    if (input.indicator && !scan && !indicator) throw new TRPCError({ code: "BAD_REQUEST", message: "Use a valid domain or SHA-256 indicator, or attach the report to a scan." });
    const priority = scan?.riskScore && scan.riskScore >= 91 ? "critical" : scan?.riskScore && scan.riskScore >= 51 ? "high" : "medium";
    const id = await db.createTicket({ userId: ctx.user.id, scanId: input.scanId ?? null, category, threatType: scan?.threatType ?? category, riskScore: scan?.riskScore ?? null, description: redactForHistory(input.description), additionalDetails: input.additionalDetails ? redactForHistory(input.additionalDetails) : null, screenshotData, indicator, priority, status: "new" });
    const risk = scan?.riskScore === undefined ? "not scored" : `${scan.riskScore}%`;
    const submittedAt = new Date().toISOString();
    await db.createNotification(ctx.user.id, "Threat report received", `Ticket #${id} · ${category} · risk ${risk}. It is awaiting review.`, "success");
    await db.recordEmailIntent(ctx.user.email ?? null, `Threat Report Received — Ticket #${id}`, `Ticket #${id} · ${category} · risk ${risk} · priority ${priority} · ${submittedAt}`);
    await notifyAdmins("New Cyber Threat Ticket Raised", `Ticket #${id} · ${category} · risk ${risk} · priority ${priority} · ${submittedAt}.`, "warning");
    await db.addSecurityLog(ctx.user.id, "ticket.created", "success", `ticket:${id}`);
    return { id, status: "new" as const, riskScore: scan?.riskScore ?? null };
  }),
});

const awarenessRouter = router({
  questions: protectedProcedure.query(() => awarenessQuestions.map(({ id, question, options }) => ({ id, question, options }))),
  history: protectedProcedure.query(({ ctx }) => db.listAwarenessAttempts(ctx.user.id)),
  submit: protectedProcedure.input(z.object({ answers: z.array(z.object({ questionId: z.string(), selected: z.number().int().min(0).max(10) })).length(10) })).mutation(async ({ input, ctx }) => {
    let scored;
    try { scored = scoreAwarenessAnswers(input.answers); }
    catch (error) { throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "Quiz answers are invalid." }); }
    const { feedback, score } = scored;
    await db.saveAwarenessAttempt(ctx.user.id, score, awarenessQuestions.length);
    await db.createNotification(ctx.user.id, "Awareness test completed", `You scored ${score}/10. Review the explanations to strengthen your safety habits.`, "info");
    await db.addSecurityLog(ctx.user.id, "awareness.completed", "success", `score:${score}/10`);
    return { score, total: awarenessQuestions.length, feedback };
  }),
});

const notificationsRouter = router({
  list: protectedProcedure.query(({ ctx }) => db.listNotifications(ctx.user.id)),
  markRead: protectedProcedure.input(z.object({ id: z.number().int().positive() })).mutation(({ ctx, input }) => db.readNotification(input.id, ctx.user.id)),
});

const adminRouter = router({
  dashboard: adminProcedure.query(async () => {
    const [users, allScans, tickets, threats] = await Promise.all([db.listUsers(), db.listAllScans(), db.listAllTickets(), db.listThreats()]);
    return { users: users.length, scans: allScans.length, safe: allScans.filter(s => s.riskScore <= 30).length, detected: allScans.filter(s => s.riskScore > 30).length, critical: allScans.filter(s => s.riskScore >= 51).length, openTickets: tickets.filter(t => !["resolved", "false_report"].includes(t.status)).length, confirmedThreats: threats.filter(t => t.status === "confirmed").length, blocked: threats.filter(t => t.status === "blocked").length, recentScans: allScans.slice(0, 8), recentTickets: tickets.slice(0, 8) };
  }),
  users: adminProcedure.query(() => db.listUsers()),
  scans: adminProcedure.query(() => db.listAllScans()),
  updateUser: adminProcedure.input(z.object({ id: z.number().int().positive(), role: z.enum(["user", "admin"]).optional(), status: z.enum(["active", "suspended"]).optional() })).mutation(async ({ ctx, input }) => {
    if (ctx.user.id === input.id && (input.role === "user" || input.status === "suspended")) throw new TRPCError({ code: "BAD_REQUEST", message: "You cannot remove your own admin access or suspend your current account." });
    await db.updateUser(input.id, { role: input.role, status: input.status });
    await db.addSecurityLog(ctx.user.id, "admin.user.updated", "success", `user:${input.id}`);
    return { success: true };
  }),
  tickets: adminProcedure.query(() => db.listAllTickets()),
  updateTicket: adminProcedure.input(z.object({ id: z.number().int().positive(), status: ticketStatus.optional(), assignedAdminId: z.number().int().positive().nullable().optional(), notes: z.string().max(4000).optional() })).mutation(async ({ ctx, input }) => {
    const ticket = await db.getTicket(input.id);
    if (!ticket) throw new TRPCError({ code: "NOT_FOUND", message: "Ticket not found." });
    if (input.status && !canTransitionTicket(ticket.status, input.status)) throw new TRPCError({ code: "BAD_REQUEST", message: `Ticket cannot move from ${ticket.status} to ${input.status}.` });
    if (input.assignedAdminId) {
      const admin = (await db.listUsers()).find(user => user.id === input.assignedAdminId && user.role === "admin" && user.status === "active");
      if (!admin) throw new TRPCError({ code: "BAD_REQUEST", message: "Assignee must be an active administrator." });
    }
    await db.updateTicket(input.id, { status: input.status, assignedAdminId: input.assignedAdminId, adminNotes: input.notes ? redactForHistory(input.notes).slice(0, 4000) : undefined });
    if (input.assignedAdminId && input.assignedAdminId !== ticket.assignedAdminId) {
      const assignee = (await db.listUsers()).find(user => user.id === input.assignedAdminId);
      if (assignee) { await db.createNotification(assignee.id, "Cyber Threat Ticket Assigned to You", `Ticket #${ticket.id} is ready for review.`, "warning"); await db.recordEmailIntent(assignee.email ?? null, `Cyber Threat Ticket Assigned to You — #${ticket.id}`); }
    }
    if (input.status === "under_review" && ticket.status !== "under_review") await notifyAdmins("Pending Cyber Threat Ticket Requires Review", `Ticket #${ticket.id} is under review.`, "warning");
    if (input.status === "confirmed" && ticket.indicator) {
      await db.saveThreat({ indicator: ticket.indicator, threatType: ticket.threatType ?? ticket.category, riskScore: ticket.riskScore ?? 96, status: "confirmed", source: "user-report", confirmedBy: ctx.user.email ?? ctx.user.name ?? "admin", notes: input.notes ? redactForHistory(input.notes) : ticket.adminNotes });
      await db.addSecurityLog(ctx.user.id, "admin.threat.confirmed", "success", `ticket:${ticket.id}`);
    }
    const label = input.status ? input.status.replaceAll("_", " ") : "updated";
    if (input.status && input.status !== ticket.status) {
      const user = await db.getUserById(ticket.userId);
      const title = input.status === "confirmed" ? "Your threat report has been confirmed." : input.status === "resolved" ? "Your threat report has been resolved." : "Your Threat Report Has Been Updated";
      await db.createNotification(ticket.userId, title, `Your ticket #${ticket.id} is now ${label}.`, input.status === "confirmed" ? "warning" : "info");
      await db.recordEmailIntent(user?.email ?? null, input.status === "resolved" ? `Your Threat Report Has Been Resolved — Ticket #${ticket.id}` : `Your Threat Report Has Been Updated — Ticket #${ticket.id}`);
    }
    await db.addSecurityLog(ctx.user.id, "admin.ticket.updated", "success", `ticket:${ticket.id}:${label}`);
    return { success: true };
  }),
  threats: adminProcedure.query(() => db.listThreats()),
  addThreat: adminProcedure.input(z.object({ indicator: z.string().min(3).max(500), threatType: z.string().min(2).max(100), riskScore: z.number().int().min(0).max(100), status: z.enum(["confirmed", "blocked", "safe"]), notes: z.string().max(2000).optional() })).mutation(async ({ ctx, input }) => {
    const indicator = safeIndicator(input.indicator);
    if (!indicator) throw new TRPCError({ code: "BAD_REQUEST", message: "Use a valid domain, IP address or SHA-256 indicator." });
    await db.saveThreat({ ...input, indicator, threatType: redactForHistory(input.threatType).slice(0, 100), source: "admin", confirmedBy: ctx.user.email ?? ctx.user.name ?? "admin", notes: input.notes ? redactForHistory(input.notes) : null });
    await db.addSecurityLog(ctx.user.id, "admin.threat.upserted", "success", `indicator:${createHash("sha256").update(indicator).digest("hex").slice(0, 16)}`);
    return { success: true };
  }),
  updateThreat: adminProcedure.input(z.object({ id: z.number().int().positive(), status: z.enum(["confirmed", "blocked", "safe"]), notes: z.string().max(2000).optional() })).mutation(async ({ ctx, input }) => {
    const threat = (await db.listThreats()).find(item => item.id === input.id);
    if (!threat) throw new TRPCError({ code: "NOT_FOUND", message: "Threat indicator not found." });
    await db.setThreatStatus(input.id, input.status, input.notes);
    const affected = await db.listAllScans();
    const owners = new Set(affected.filter(scan => normalizedIndicator(scan.scanType, scan.inputReference, scan.fileHash ?? undefined) === threat.indicator).map(scan => scan.userId));
    const noticeTitle = input.status === "blocked" ? "Threat indicator blocked" : input.status === "safe" ? "Threat indicator marked safe" : "Threat indicator confirmed";
    await Promise.all(Array.from(owners, userId => db.createNotification(userId, noticeTitle, `An administrator updated a threat indicator relevant to a previous scan. Status: ${input.status}.`, input.status === "blocked" ? "danger" : "info")));
    if (input.status === "confirmed") await notifyAdmins("Critical Cyber Threat Detected", `A threat indicator was confirmed: ${threat.indicator.slice(0, 100)}.`, "danger");
    await db.addSecurityLog(ctx.user.id, "admin.threat.updated", "success", `threat:${input.id}:${input.status}`);
    return { success: true };
  }),
  analytics: adminProcedure.query(async () => {
    const [allScans, allTickets, allThreats] = await Promise.all([db.listAllScans(), db.listAllTickets(), db.listThreats()]);
    const count = (values: string[], key: string) => values.filter(value => value === key).length;
    const daily = Array.from({ length: 7 }, (_, i) => { const start = new Date(); start.setHours(0, 0, 0, 0); start.setDate(start.getDate() - (6 - i)); const end = new Date(start); end.setDate(end.getDate() + 1); const matches = allScans.filter(s => { const date = new Date(s.createdAt); return date >= start && date < end; }); return { period: start.toLocaleDateString("en", { weekday: "short" }), count: matches.filter(s => s.riskScore >= 51).length, total: matches.length }; });
    const weekly = Array.from({ length: 8 }, (_, i) => { const stop = new Date(); stop.setHours(0, 0, 0, 0); stop.setDate(stop.getDate() + 1 - (7 - i) * 7); const start = new Date(stop); start.setDate(start.getDate() - 7); const matches = allScans.filter(s => { const date = new Date(s.createdAt); return date >= start && date < stop; }); return { period: `W${i + 1}`, count: matches.filter(s => s.riskScore >= 51).length, total: matches.length }; });
    const monthly = Array.from({ length: 6 }, (_, i) => { const now = new Date(); const start = new Date(now.getFullYear(), now.getMonth() - (5 - i), 1); const end = new Date(now.getFullYear(), now.getMonth() - (4 - i), 1); const matches = allScans.filter(s => { const date = new Date(s.createdAt); return date >= start && date < end; }); return { period: start.toLocaleDateString("en", { month: "short" }), count: matches.filter(s => s.riskScore >= 51).length, total: matches.length }; });
    return { scanTypes: ["url", "email", "sms", "link", "apk", "api"].map(type => ({ type, count: count(allScans.map(s => s.scanType), type) })), threats: [...new Set(allScans.map(s => s.threatType))].map(type => ({ type, count: count(allScans.map(s => s.threatType), type) })).sort((a, b) => b.count - a.count).slice(0, 8), ticketStates: TICKET_STATUSES.map(status => ({ status, count: count(allTickets.map(t => t.status), status) })), riskBuckets: [{ label: "Very low", count: allScans.filter(s => s.riskScore <= 10).length }, { label: "Low", count: allScans.filter(s => s.riskScore > 10 && s.riskScore <= 30).length }, { label: "Medium", count: allScans.filter(s => s.riskScore > 30 && s.riskScore <= 50).length }, { label: "High", count: allScans.filter(s => s.riskScore > 50 && s.riskScore <= 70).length }, { label: "Very high / critical", count: allScans.filter(s => s.riskScore > 70).length }], trends: { daily, weekly, monthly }, confirmedThreats: allThreats.filter(threat => threat.status === "confirmed").length };
  }),
  logs: adminProcedure.query(() => db.listSecurityLogs()),
  emails: adminProcedure.query(() => db.listEmailIntents()),
});

const userRouter = router({
  dashboard: protectedProcedure.query(async ({ ctx }) => {
    const [scans, tickets, awareness] = await Promise.all([db.listUserScans(ctx.user.id), db.listUserTickets(ctx.user.id), db.listAwarenessAttempts(ctx.user.id)]);
    const latest = awareness[0];
    return { totalScans: scans.length, safeScans: scans.filter(s => s.riskScore <= 30).length, riskyScans: scans.filter(s => s.riskScore > 30).length, reports: tickets.length, awarenessScore: latest ? Math.round((latest.score / latest.totalQuestions) * 100) : 0, recentScan: scans[0] ?? null, recentScans: scans.slice(0, 6) };
  }),
  exportData: protectedProcedure
    .input(
      z.object({
        days: z.number().int().min(1).max(90).default(10),
        format: z.enum(["json", "pdf", "excel"]).default("json"),
      }).optional()
    )
    .mutation(async ({ ctx, input }) => {
      const days = input?.days ?? 10;
      const data = await db.exportUserData(ctx.user.id, days);
      await db.addSecurityLog(ctx.user.id, "user.data.exported", "success", `days:${days}`);
      return data;
    }),

  deleteAccount: protectedProcedure
    .input(z.object({ confirm: z.literal("DELETE") }))
    .mutation(async ({ ctx }) => {
      const user = await db.getUserById(ctx.user.id);
      if (!user) throw new TRPCError({ code: "NOT_FOUND", message: "Account not found." });
      if (user.role === "admin") {
        const admins = (await db.listUsers()).filter(u => u.role === "admin" && u.status === "active");
        if (admins.length <= 1) {
          throw new TRPCError({
            code: "BAD_REQUEST",
            message: "Cannot delete the last remaining administrator account.",
          });
        }
      }
      await db.addSecurityLog(ctx.user.id, "user.account.deleted", "success", `publicId:${user.publicId}`);
      await db.deleteUserAccount(ctx.user.id);
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true };
    }),
});

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    register: publicProcedure.input(z.object({ name: z.string().max(120).optional(), email: z.string().max(320).optional(), password: z.string().max(128).optional(), confirmPassword: z.string().max(128).optional() })).mutation(async ({ ctx, input }) => {
      const name = input.name?.trim() ?? "";
      const email = input.email?.trim().toLowerCase() ?? "";
      const password = input.password ?? "";
      const confirmPassword = input.confirmPassword ?? "";
      if (name.length < 2 || !validEmail(email)) { await recordAuthFailure("auth.registration.failed"); throw new TRPCError({ code: "BAD_REQUEST", message: "Enter a valid name and email address." }); }
      if (password !== confirmPassword) { await recordAuthFailure("auth.registration.failed"); throw new TRPCError({ code: "BAD_REQUEST", message: "Passwords do not match." }); }
      if (!passwordMeetsPolicy(password)) { await recordAuthFailure("auth.registration.failed"); throw new TRPCError({ code: "BAD_REQUEST", message: "Password must contain at least one uppercase letter, one number, and one special character." }); }
      if (!allowAuthAttempt(ctx.req, "register", email, 4, 60 * 60 * 1000)) { await recordAuthFailure("auth.registration.failed"); throw new TRPCError({ code: "TOO_MANY_REQUESTS", message: "Registration attempts are temporarily limited. Try again later." }); }
      const existing = await db.getUserByEmail(email);
      if (existing) { await recordAuthFailure("auth.registration.failed", existing.id); throw new TRPCError({ code: "CONFLICT", message: "An account with this email already exists. Sign in using your saved method." }); }
      const passwordHash = await hashPassword(password);
      let user;
      try {
        user = await db.createLocalAccount({
          openId: `local_${randomUUID()}`,
          publicId: `usr_${randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase()}`,
          name, email, passwordHash
        });
      }
      catch (error) { if ((error as { code?: string })?.code === "ER_DUP_ENTRY") { await recordAuthFailure("auth.registration.failed"); throw new TRPCError({ code: "CONFLICT", message: "An account with this email already exists. Sign in using your saved method." }); } throw error; }
      if (!user) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Account setup could not be completed." });
      await db.createNotification(user.id, "Welcome to CyberShield AI", "Your account has been created. You can now review suspicious websites, messages, files and APIs.", "success");
      await db.recordEmailIntent(user.email ?? null, "Welcome to CyberShield AI");
      await db.addSecurityLog(user.id, "registration.completed", "success");
      const token = await sdk.createSessionToken(user.openId, { name: user.name ?? "", expiresInMs: ONE_YEAR_MS });
      ctx.res.cookie(COOKIE_NAME, token, { ...getSessionCookieOptions(ctx.req), maxAge: ONE_YEAR_MS });
      return { success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } };
    }),
    login: publicProcedure.input(z.object({ email: z.string().max(320).optional(), password: z.string().max(128).optional(), mode: z.enum(["user", "admin"]).default("user") })).mutation(async ({ ctx, input }) => {
      const email = input.email?.trim().toLowerCase() ?? "";
      const password = input.password ?? "";
      const genericFailure = () => new TRPCError({ code: "UNAUTHORIZED", message: "Invalid email or password." });
      const withinLimit = allowAuthAttempt(ctx.req, "login", email, 10, 15 * 60 * 1000);
      if (!validEmail(email) || !withinLimit) { await verifyPassword(password, undefined); await recordAuthFailure("auth.login.failed"); throw genericFailure(); }
      const credential = await db.getLocalCredentialByEmail(email);
      const passwordValid = await verifyPassword(password, credential?.passwordHash);
      const user = credential ? await db.getUserById(credential.userId) : undefined;
      if (!passwordValid || !user || user.status !== "active" || (input.mode === "admin" && user.role !== "admin")) {
        await recordAuthFailure("auth.login.failed", user?.id ?? null);
        throw genericFailure();
      }
      await db.upsertUser({
        openId: user.openId,
        publicId: user.publicId ?? `usr_${randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase()}`,
        lastSignedIn: new Date()
      });
      await db.addSecurityLog(user.id, "auth.login.succeeded", "success");
      await db.recordEmailIntent(user.email ?? null, "New Login Detected");
      const token = await sdk.createSessionToken(user.openId, { name: user.name ?? "", expiresInMs: ONE_YEAR_MS });
      ctx.res.cookie(COOKIE_NAME, token, { ...getSessionCookieOptions(ctx.req), maxAge: ONE_YEAR_MS });
      return { success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } };
    }),
    logout: publicProcedure.mutation(({ ctx }) => { if (ctx.user) void db.addSecurityLog(ctx.user.id, "auth.logout", "success"); const cookieOptions = getSessionCookieOptions(ctx.req); ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 }); return { success: true } as const; }),
  }),
  scan: scansRouter,
  tickets: ticketsRouter,
  awareness: awarenessRouter,
  notifications: notificationsRouter,
  user: userRouter,
  admin: adminRouter,
});

export type AppRouter = typeof appRouter;
