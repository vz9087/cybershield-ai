import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { randomUUID } from "node:crypto";

import {
  awarenessAttempts,
  emailOutbox,
  localCredentials,
  notifications,
  passwordResetOtps,
  passwordResetThrottle,
  scans,
  securityLogs,
  threats,
  tickets,
  ticketResponses,
  users,
} from "../drizzle/schema";

import type {
  InsertUser,
  User,
  Scan,
  Ticket,
  Threat,
  TicketResponse,
  PasswordResetOtp,
} from "../drizzle/schema";

import { hashPassword } from "./_core/passwords";
import { ENV } from "./_core/env";

export const INITIAL_ADMINS = [
  {
    name: "Keerthi Manjunath Geddappanavar",
    email: "karbasamamg@gmail.com",
    defaultPassword: process.env.ADMIN_KEERTHI_PASSWORD || "Keerthi@1234",
  },
  {
    name: "Vishal VP",
    email: "vishalvpurshan360@gmail.com",
    defaultPassword: process.env.ADMIN_VISHAL_PASSWORD || "Vishal@1234",
  },
  {
    name: "Pooja N Annigere",
    email: "annigerep@gmail.com",
    defaultPassword: process.env.ADMIN_POOJA_PASSWORD || "Pooja@1234",
  },
];

const ticketListColumns = {
  id: tickets.id,
  userId: tickets.userId,
  scanId: tickets.scanId,
  category: tickets.category,
  description: tickets.description,
  additionalDetails: tickets.additionalDetails,
  indicator: tickets.indicator,
  riskScore: tickets.riskScore,
  threatType: tickets.threatType,
  priority: tickets.priority,
  status: tickets.status,
  hasScreenshot: sql<number>`${tickets.screenshotData} IS NOT NULL`,
  assignedAdminId: tickets.assignedAdminId,
  adminNotes: tickets.adminNotes,
  createdAt: tickets.createdAt,
  updatedAt: tickets.updatedAt,
};

// -------------------------------------------------------------
// In-Memory Fallback Storage (Active when MySQL is unreachable)
// -------------------------------------------------------------
type LocalCred = { id: number; userId: number; email: string; passwordHash: string; createdAt: Date };
type AwarenessAttempt = { id: number; userId: number; score: number; totalQuestions: number; createdAt: Date };
type Notification = { id: number; userId: number; title: string; message: string; type: string; readStatus: number; createdAt: Date };
type SecurityLog = { id: number; userId: number | null; action: string; status: string; details: string | null; createdAt: Date };
type EmailRecord = { id: number; recipient: string | null; subject: string; body: string | null; status: string; createdAt: Date };

const mem = {
  userSeq: 1,
  users: new Map<number, User>(),
  localCredentials: new Map<number, LocalCred>(),
  scans: new Map<string, Scan>(),
  ticketSeq: 1040,
  tickets: new Map<number, Ticket>(),
  threatSeq: 1,
  threats: new Map<string, Threat>(),
  notifSeq: 1,
  notifications: new Map<number, Notification>(),
  awarenessSeq: 1,
  awarenessAttempts: new Map<number, AwarenessAttempt>(),
  logSeq: 1,
  securityLogs: [] as SecurityLog[],
  emailSeq: 1,
  emailOutbox: [] as EmailRecord[],
};

// Seed initial threat indicators into fallback store
const INITIAL_THREAT_INDICATORS = [
  { indicator: "fake-bank-example.com", threatType: "Phishing / Financial Impersonation", riskScore: 96, status: "confirmed" as const, source: "threat-intel", notes: "Confirmed phishing portal imitating retail bank" },
  { indicator: "g00gle.com", threatType: "Typosquatting / Brand Impersonation", riskScore: 85, status: "confirmed" as const, source: "threat-intel", notes: "Known homoglyph domain mimicking google.com" },
  { indicator: "phishing-update-account.com", threatType: "Credential Harvesting", riskScore: 94, status: "confirmed" as const, source: "threat-intel", notes: "Reported credential theft URL" },
  { indicator: "suspicious-kyc-alert.com", threatType: "Smishing / Bank Scam", riskScore: 98, status: "blocked" as const, source: "threat-intel", notes: "High volume fraudulent KYC SMS link" },
];

for (const item of INITIAL_THREAT_INDICATORS) {
  const now = new Date();
  mem.threats.set(item.indicator.toLowerCase(), {
    id: mem.threatSeq++,
    indicator: item.indicator.toLowerCase(),
    threatType: item.threatType,
    riskScore: item.riskScore,
    status: item.status,
    source: item.source,
    firstDetected: now,
    lastChecked: now,
    confirmedBy: "Threat Intelligence Engine",
    notes: item.notes,
  });
}

let _db: ReturnType<typeof drizzle> | null = null;
let _dbFailed = false;

export async function getDb() {
  if (_dbFailed) return null;
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] MySQL initialization failed, running in resilient local mode:", error);
      _db = null;
      _dbFailed = true;
    }
  }
  return _db;
}

export async function upsertUser(user: Omit<InsertUser, "publicId"> & { publicId?: string }): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");

  // Generate a public ID if one wasn't provided
  const publicId = user.publicId ?? `usr_${randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase()}`;

  const db = await getDb();
  if (db) {
    try {
      const values: InsertUser = { openId: user.openId, publicId };
      const updateSet: Record<string, unknown> = {};
      for (const field of ["name", "email", "loginMethod"] as const) {
        if (user[field] !== undefined) { values[field] = user[field] ?? null; updateSet[field] = user[field] ?? null; }
      }
      if (user.lastSignedIn !== undefined) { values.lastSignedIn = user.lastSignedIn; updateSet.lastSignedIn = user.lastSignedIn; }
      if (user.role !== undefined) { values.role = user.role; updateSet.role = user.role; }
      if (!values.lastSignedIn) values.lastSignedIn = new Date();
      if (Object.keys(updateSet).length === 0) updateSet.lastSignedIn = new Date();
      await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
      return;
    } catch {
      // Fallback to in-memory store if DB query fails
    }
  }

  // Memory fallback
  const existing = Array.from(mem.users.values()).find(u => u.openId === user.openId);
  const now = new Date();
  if (existing) {
    if (user.name !== undefined) existing.name = user.name ?? null;
    if (user.email !== undefined) existing.email = user.email ?? null;
    if (user.role !== undefined) existing.role = user.role;
    if (user.publicId !== undefined) existing.publicId = user.publicId;
    existing.lastSignedIn = user.lastSignedIn ?? now;
    existing.updatedAt = now;
  } else {
    const id = mem.userSeq++;
    const newUser: User = {
      id,
      openId: user.openId,
      publicId,
      name: user.name ?? null,
      email: user.email ?? null,
      loginMethod: user.loginMethod ?? "password",
      role: user.role ?? "user",
      status: user.status ?? "active",
      createdAt: now,
      updatedAt: now,
      lastSignedIn: now,
      sessionsInvalidatedAt: null,
    };
    mem.users.set(id, newUser);
  }
}

export async function getUserByOpenId(openId: string): Promise<User | undefined> {
  const db = await getDb();
  if (db) {
    try {
      const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
      if (result[0]) return result[0];
    } catch { }
  }
  return Array.from(mem.users.values()).find(u => u.openId === openId);
}

export async function getUserById(id: number): Promise<User | undefined> {
  const db = await getDb();
  if (db) {
    try {
      const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
      if (result[0]) return result[0];
    } catch { }
  }
  return mem.users.get(id);
}

export async function getUserByEmail(email: string): Promise<User | undefined> {
  const lower = email.toLowerCase();
  const db = await getDb();
  if (db) {
    try {
      const result = await db.select().from(users).where(sql`lower(${users.email}) = ${lower}`).limit(1);
      if (result[0]) return result[0];
    } catch { }
  }
  return Array.from(mem.users.values()).find(u => u.email?.toLowerCase() === lower);
}

export async function getLocalCredentialByEmail(email: string): Promise<LocalCred | undefined> {
  const lower = email.toLowerCase();
  const db = await getDb();
  if (db) {
    try {
      const result = await db.select().from(localCredentials).where(eq(localCredentials.email, lower)).limit(1);
      if (result[0]) return result[0];
    } catch { }
  }
  return Array.from(mem.localCredentials.values()).find(c => c.email.toLowerCase() === lower);
}

export async function createLocalAccount(input: {
  openId: string;
  publicId: string;
  name: string;
  email: string;
  passwordHash: string;
  role?: "user" | "admin";
}): Promise<User> {
  const db = await getDb();
  if (db) {
    try {
      return await db.transaction(async tx => {
        const inserted = await tx.insert(users).values({
          openId: input.openId,
          publicId: input.publicId,
          name: input.name,
          email: input.email.toLowerCase(),
          role: input.role || "user",
          loginMethod: "password",
          status: "active",
          lastSignedIn: new Date(),
        });
        const userId = Number(inserted[0].insertId);
        await tx.insert(localCredentials).values({
          userId,
          email: input.email.toLowerCase(),
          passwordHash: input.passwordHash,
        });
        return (await tx.select().from(users).where(eq(users.id, userId)).limit(1))[0]!;
      });
    } catch (err) {
      if ((err as { code?: string })?.code === "ER_DUP_ENTRY") throw err;
      // If DB failed, continue to fallback
    }
  }

  // Check unique email in memory
  const existingCred = Array.from(mem.localCredentials.values()).find(c => c.email.toLowerCase() === input.email.toLowerCase());
  if (existingCred) {
    const error = new Error("Duplicate account email");
    (error as any).code = "ER_DUP_ENTRY";
    throw error;
  }

  const now = new Date();
  const id = mem.userSeq++;
  const newUser: User = {
    id,
    openId: input.openId,
    publicId: input.publicId,
    name: input.name,
    email: input.email.toLowerCase(),
    loginMethod: "password",
    role: input.role || "user",
    status: "active",
    createdAt: now,
    updatedAt: now,
    lastSignedIn: now,
    sessionsInvalidatedAt: null,
  };

  mem.users.set(id, newUser);

  const credId = mem.localCredentials.size + 1;
  mem.localCredentials.set(credId, {
    id: credId,
    userId: id,
    email: input.email.toLowerCase(),
    passwordHash: input.passwordHash,
    createdAt: now,
  });

  return newUser;
}

export async function createScanRecord(row: typeof scans.$inferInsert): Promise<typeof scans.$inferInsert> {
  const db = await getDb();
  if (db) {
    try {
      await db.insert(scans).values(row);
      return row;
    } catch { }
  }

  const fullScan: Scan = {
    ...row,
    createdAt: new Date(),
    action: row.action ?? "allow",
    safeAlternative: row.safeAlternative ?? null,
    fileHash: row.fileHash ?? null,
  };
  mem.scans.set(row.id, fullScan);
  return row;
}

export async function getScanForUser(scanId: string, userId: number): Promise<Scan | undefined> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(scans).where(and(eq(scans.id, scanId), eq(scans.userId, userId))).limit(1);
      if (rows[0]) return rows[0];
    } catch { }
  }
  const scan = mem.scans.get(scanId);
  return scan && scan.userId === userId ? scan : undefined;
}

export async function getScanById(scanId: string): Promise<Scan | undefined> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(scans).where(eq(scans.id, scanId)).limit(1);
      if (rows[0]) return rows[0];
    } catch { }
  }
  return mem.scans.get(scanId);
}

export async function listUserScans(userId: number, type?: string): Promise<Scan[]> {
  const db = await getDb();
  if (db) {
    try {
      const where = type
        ? and(eq(scans.userId, userId), eq(scans.scanType, type as typeof scans.$inferSelect.scanType))
        : eq(scans.userId, userId);
      return await db.select().from(scans).where(where).orderBy(desc(scans.createdAt)).limit(300);
    } catch { }
  }

  return Array.from(mem.scans.values())
    .filter(s => s.userId === userId && (!type || s.scanType === type))
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .slice(0, 300);
}

export async function listAllScans(): Promise<Scan[]> {
  const db = await getDb();
  if (db) {
    try {
      return await db.select().from(scans).orderBy(desc(scans.createdAt)).limit(1000);
    } catch { }
  }

  return Array.from(mem.scans.values())
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .slice(0, 1000);
}

export async function createTicket(row: typeof tickets.$inferInsert): Promise<number> {
  const db = await getDb();
  if (db) {
    try {
      const result = await db.insert(tickets).values(row);
      return Number(result[0].insertId);
    } catch { }
  }

  const id = mem.ticketSeq++;
  const now = new Date();
  const ticket: Ticket = {
    ...row,
    id,
    scanId: row.scanId ?? null,
    additionalDetails: row.additionalDetails ?? null,
    indicator: row.indicator ?? null,
    riskScore: row.riskScore ?? null,
    threatType: row.threatType ?? null,
    screenshotData: row.screenshotData ?? null,
    priority: row.priority ?? "medium",
    status: row.status ?? "new",
    assignedAdminId: row.assignedAdminId ?? null,
    adminNotes: row.adminNotes ?? null,
    createdAt: now,
    updatedAt: now,
  };
  mem.tickets.set(id, ticket);
  return id;
}

export async function listUserTickets(userId: number) {
  const db = await getDb();
  if (db) {
    try {
      return await db.select(ticketListColumns).from(tickets).where(eq(tickets.userId, userId)).orderBy(desc(tickets.createdAt)).limit(200);
    } catch { }
  }

  return Array.from(mem.tickets.values())
    .filter(t => t.userId === userId)
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .map(t => ({
      id: t.id,
      userId: t.userId,
      scanId: t.scanId,
      category: t.category,
      description: t.description,
      additionalDetails: t.additionalDetails,
      indicator: t.indicator,
      riskScore: t.riskScore,
      threatType: t.threatType,
      priority: t.priority,
      status: t.status,
      hasScreenshot: t.screenshotData ? 1 : 0,
      assignedAdminId: t.assignedAdminId,
      adminNotes: t.adminNotes,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    }));
}

export async function listAllTickets() {
  const db = await getDb();
  if (db) {
    try {
      return await db.select(ticketListColumns).from(tickets).orderBy(desc(tickets.updatedAt)).limit(500);
    } catch { }
  }

  return Array.from(mem.tickets.values())
    .sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime())
    .map(t => ({
      id: t.id,
      userId: t.userId,
      scanId: t.scanId,
      category: t.category,
      description: t.description,
      additionalDetails: t.additionalDetails,
      indicator: t.indicator,
      riskScore: t.riskScore,
      threatType: t.threatType,
      priority: t.priority,
      status: t.status,
      hasScreenshot: t.screenshotData ? 1 : 0,
      assignedAdminId: t.assignedAdminId,
      adminNotes: t.adminNotes,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    }));
}

export async function getTicket(id: number) {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select(ticketListColumns).from(tickets).where(eq(tickets.id, id)).limit(1);
      if (rows[0]) return rows[0];
    } catch { }
  }

  const t = mem.tickets.get(id);
  if (!t) return undefined;
  return {
    id: t.id,
    userId: t.userId,
    scanId: t.scanId,
    category: t.category,
    description: t.description,
    additionalDetails: t.additionalDetails,
    indicator: t.indicator,
    riskScore: t.riskScore,
    threatType: t.threatType,
    priority: t.priority,
    status: t.status,
    hasScreenshot: t.screenshotData ? 1 : 0,
    assignedAdminId: t.assignedAdminId,
    adminNotes: t.adminNotes,
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
  };
}

export async function getTicketEvidence(id: number) {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select({ userId: tickets.userId, screenshotData: tickets.screenshotData }).from(tickets).where(eq(tickets.id, id)).limit(1);
      if (rows[0]) return rows[0];
    } catch { }
  }
  const t = mem.tickets.get(id);
  return t ? { userId: t.userId, screenshotData: t.screenshotData } : undefined;
}

export async function updateTicket(id: number, patch: Partial<typeof tickets.$inferInsert>): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db.update(tickets).set({ ...patch, updatedAt: new Date() }).where(eq(tickets.id, id));
      return;
    } catch { }
  }

  const t = mem.tickets.get(id);
  if (t) {
    Object.assign(t, patch);
    t.updatedAt = new Date();
  }
}

export async function listUsers(): Promise<Array<Pick<User, "id" | "name" | "email" | "role" | "status" | "createdAt" | "lastSignedIn">>> {
  const db = await getDb();
  if (db) {
    try {
      return await db
        .select({
          id: users.id,
          name: users.name,
          email: users.email,
          role: users.role,
          status: users.status,
          createdAt: users.createdAt,
          lastSignedIn: users.lastSignedIn,
        })
        .from(users)
        .orderBy(desc(users.createdAt))
        .limit(500);
    } catch { }
  }

  return Array.from(mem.users.values())
    .map(u => ({
      id: u.id,
      name: u.name,
      email: u.email,
      role: u.role,
      status: u.status,
      createdAt: u.createdAt,
      lastSignedIn: u.lastSignedIn,
    }))
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
}

export async function updateUser(id: number, patch: { role?: "user" | "admin"; status?: "active" | "suspended" }): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db.update(users).set({ ...patch, updatedAt: new Date() }).where(eq(users.id, id));
      return;
    } catch { }
  }

  const u = mem.users.get(id);
  if (u) {
    if (patch.role) u.role = patch.role;
    if (patch.status) u.status = patch.status;
    u.updatedAt = new Date();
  }
}

export async function listThreats(): Promise<Threat[]> {
  const db = await getDb();
  if (db) {
    try {
      return await db.select().from(threats).orderBy(desc(threats.lastChecked)).limit(500);
    } catch { }
  }

  return Array.from(mem.threats.values()).sort((a, b) => b.lastChecked.getTime() - a.lastChecked.getTime());
}

export async function findThreat(indicator: string): Promise<Threat | undefined> {
  const lower = indicator.toLowerCase();
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(threats).where(eq(threats.indicator, lower)).limit(1);
      if (rows[0]) return rows[0];
    } catch { }
  }

  return mem.threats.get(lower);
}

export async function saveThreat(row: typeof threats.$inferInsert): Promise<void> {
  const lower = row.indicator.toLowerCase();
  const db = await getDb();
  if (db) {
    try {
      await db.insert(threats).values({ ...row, indicator: lower }).onDuplicateKeyUpdate({
        set: {
          threatType: row.threatType,
          riskScore: row.riskScore,
          status: row.status,
          source: row.source,
          lastChecked: new Date(),
          confirmedBy: row.confirmedBy,
          notes: row.notes,
        },
      });
      return;
    } catch { }
  }

  const now = new Date();
  const existing = mem.threats.get(lower);
  if (existing) {
    existing.threatType = row.threatType;
    existing.riskScore = row.riskScore;
    existing.status = row.status ?? "confirmed";
    existing.source = row.source ?? existing.source;
    existing.lastChecked = now;
    existing.confirmedBy = row.confirmedBy ?? existing.confirmedBy;
    existing.notes = row.notes ?? existing.notes;
  } else {
    mem.threats.set(lower, {
      id: mem.threatSeq++,
      indicator: lower,
      threatType: row.threatType,
      riskScore: row.riskScore,
      status: row.status ?? "confirmed",
      source: row.source ?? "community-report",
      firstDetected: now,
      lastChecked: now,
      confirmedBy: row.confirmedBy ?? null,
      notes: row.notes ?? null,
    });
  }
}

export async function setThreatStatus(id: number, status: "confirmed" | "blocked" | "safe", notes?: string): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db.update(threats).set({ status, notes, lastChecked: new Date() }).where(eq(threats.id, id));
      return;
    } catch { }
  }

  const threat = Array.from(mem.threats.values()).find(t => t.id === id);
  if (threat) {
    threat.status = status;
    if (notes) threat.notes = notes;
    threat.lastChecked = new Date();
  }
}

export async function createNotification(userId: number, title: string, message: string, type = "info"): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db.insert(notifications).values({ userId, title, message, type, readStatus: 0 });
      return;
    } catch { }
  }

  const id = mem.notifSeq++;
  mem.notifications.set(id, { id, userId, title, message, type, readStatus: 0, createdAt: new Date() });
}

export async function listNotifications(userId: number): Promise<Notification[]> {
  const db = await getDb();
  if (db) {
    try {
      return await db.select().from(notifications).where(eq(notifications.userId, userId)).orderBy(desc(notifications.createdAt)).limit(150);
    } catch { }
  }

  return Array.from(mem.notifications.values())
    .filter(n => n.userId === userId)
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .slice(0, 150);
}

export async function readNotification(id: number, userId: number): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db.update(notifications).set({ readStatus: 1 }).where(and(eq(notifications.id, id), eq(notifications.userId, userId)));
      return;
    } catch { }
  }

  const notif = mem.notifications.get(id);
  if (notif && notif.userId === userId) {
    notif.readStatus = 1;
  }
}

export async function saveAwarenessAttempt(userId: number, score: number, total: number): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db.insert(awarenessAttempts).values({ userId, score, totalQuestions: total });
      return;
    } catch { }
  }

  const id = mem.awarenessSeq++;
  mem.awarenessAttempts.set(id, { id, userId, score, totalQuestions: total, createdAt: new Date() });
}

export async function listAwarenessAttempts(userId: number): Promise<AwarenessAttempt[]> {
  const db = await getDb();
  if (db) {
    try {
      return await db.select().from(awarenessAttempts).where(eq(awarenessAttempts.userId, userId)).orderBy(desc(awarenessAttempts.createdAt)).limit(50);
    } catch { }
  }

  return Array.from(mem.awarenessAttempts.values())
    .filter(a => a.userId === userId)
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .slice(0, 50);
}

export async function addSecurityLog(userId: number | null, action: string, status = "success", details?: string): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db.insert(securityLogs).values({ userId, action, status, details: details?.slice(0, 500) ?? null });
      return;
    } catch { }
  }

  const id = mem.logSeq++;
  mem.securityLogs.push({ id, userId, action, status, details: details?.slice(0, 500) ?? null, createdAt: new Date() });
}

export async function listSecurityLogs(): Promise<SecurityLog[]> {
  const db = await getDb();
  if (db) {
    try {
      return await db.select().from(securityLogs).orderBy(desc(securityLogs.createdAt)).limit(500);
    } catch { }
  }

  return [...mem.securityLogs].reverse().slice(0, 500);
}

export async function recordEmailIntent(
  recipient: string | null,
  subject: string,
  body?: string,
  html?: string
): Promise<void> {
  // 1. Attempt actual delivery via SMTP
  let sendStatus = "provider_not_configured";
  let sendError: string | null = null;
  try {
    const { sendMail } = await import("./_core/mailer");
    const result = await sendMail({ to: recipient, subject, text: body, html });
    if (result.ok) {
      sendStatus = "sent";
    } else {
      sendStatus = `failed:${result.reason}`;
      sendError = result.reason;
    }
  } catch (err) {
    sendStatus = `failed:${err instanceof Error ? err.message : "unknown"}`;
    sendError = err instanceof Error ? err.message : "unknown";
  }

  // 2. Log the attempt in email_outbox regardless of outcome
  const db = await getDb();
  if (db) {
    try {
      await db.insert(emailOutbox).values({
        recipient,
        subject: subject.slice(0, 240),
        body: body?.slice(0, 2000) ?? null,
        status: sendStatus.slice(0, 40),
      });
      return;
    } catch (err) {
      console.error("[db] email_outbox insert failed:", err);
    }
  }

  const id = mem.emailSeq++;
  mem.emailOutbox.push({
    id,
    recipient,
    subject: subject.slice(0, 240),
    body: body?.slice(0, 2000) ?? null,
    status: sendStatus.slice(0, 40),
    createdAt: new Date(),
  });

  if (sendError) console.error("[email] delivery failed:", sendError);
}

export async function listEmailIntents(): Promise<EmailRecord[]> {
  const db = await getDb();
  if (db) {
    try {
      return await db.select().from(emailOutbox).orderBy(desc(emailOutbox.createdAt)).limit(100);
    } catch { }
  }

  return [...mem.emailOutbox].reverse().slice(0, 100);
}

export async function countUsers(): Promise<number> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select({ id: users.id }).from(users).limit(10000);
      return rows.length;
    } catch { }
  }
  return mem.users.size;
}

export async function findThreatLike(indicator: string): Promise<Threat | undefined> {
  const candidate = indicator.toLowerCase().slice(0, 180);
  const all = await listThreats();
  const active = all.filter(t => t.status === "confirmed" || t.status === "blocked");
  return active.find(row => {
    const stored = row.indicator.toLowerCase();
    return candidate === stored || (!stored.startsWith("sha256:") && candidate.endsWith(`.${stored}`));
  });
}

// ================================================================
// TICKET RESPONSES (threading)
// ================================================================

export async function addTicketResponse(row: {
  ticketId: number;
  authorId: number;
  authorRole: "user" | "admin";
  message: string;
  attachmentName?: string | null;
  attachmentType?: string | null;
  attachmentData?: string | null;
}): Promise<number> {
  const db = await getDb();
  if (db) {
    try {
      const result = await db.insert(ticketResponses).values({
        ticketId: row.ticketId,
        authorId: row.authorId,
        authorRole: row.authorRole,
        message: row.message,
        attachmentName: row.attachmentName ?? null,
        attachmentType: row.attachmentType ?? null,
        attachmentData: row.attachmentData ?? null,
      });
      return Number(result[0].insertId);
    } catch (err) {
      console.error("[db] addTicketResponse failed:", err);
    }
  }

  // Memory fallback: append to a local map keyed by ticketId
  const id = (mem as any).respSeq ? (mem as any).respSeq++ : ((mem as any).respSeq = 2, 1);
  const store = (mem as any).ticketResponses ?? new Map<number, TicketResponse[]>();
  const list = store.get(row.ticketId) ?? [];
  list.push({
    id,
    ticketId: row.ticketId,
    authorId: row.authorId,
    authorRole: row.authorRole,
    message: row.message,
    attachmentName: row.attachmentName ?? null,
    attachmentType: row.attachmentType ?? null,
    attachmentData: row.attachmentData ?? null,
    createdAt: new Date(),
  } as TicketResponse);
  store.set(row.ticketId, list);
  (mem as any).ticketResponses = store;
  return id;
}

export async function listTicketResponses(ticketId: number) {
  const db = await getDb();
  if (db) {
    try {
      return await db
        .select({
          id: ticketResponses.id,
          ticketId: ticketResponses.ticketId,
          authorId: ticketResponses.authorId,
          authorRole: ticketResponses.authorRole,
          message: ticketResponses.message,
          attachmentName: ticketResponses.attachmentName,
          attachmentType: ticketResponses.attachmentType,
          hasAttachment: sql<number>`${ticketResponses.attachmentData} IS NOT NULL`,
          createdAt: ticketResponses.createdAt,
        })
        .from(ticketResponses)
        .where(eq(ticketResponses.ticketId, ticketId))
        .orderBy(ticketResponses.createdAt);
    } catch (err) {
      console.error("[db] listTicketResponses failed:", err);
    }
  }

  const store = (mem as any).ticketResponses as Map<number, TicketResponse[]> | undefined;
  const list = store?.get(ticketId) ?? [];
  return list.map(r => ({
    id: r.id,
    ticketId: r.ticketId,
    authorId: r.authorId,
    authorRole: r.authorRole,
    message: r.message,
    attachmentName: r.attachmentName,
    attachmentType: r.attachmentType,
    hasAttachment: r.attachmentData ? 1 : 0,
    createdAt: r.createdAt,
  }));
}

export async function getTicketResponseAttachment(responseId: number) {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db
        .select({
          ticketId: ticketResponses.ticketId,
          attachmentData: ticketResponses.attachmentData,
          attachmentType: ticketResponses.attachmentType,
          attachmentName: ticketResponses.attachmentName,
        })
        .from(ticketResponses)
        .where(eq(ticketResponses.id, responseId))
        .limit(1);
      if (rows[0]) return rows[0];
    } catch { /* fall through */ }
  }

  const store = (mem as any).ticketResponses as Map<number, TicketResponse[]> | undefined;
  if (store) {
    for (const list of store.values()) {
      const found = list.find(r => r.id === responseId);
      if (found) {
        return {
          ticketId: found.ticketId,
          attachmentData: found.attachmentData,
          attachmentType: found.attachmentType,
          attachmentName: found.attachmentName,
        };
      }
    }
  }
  return undefined;
}

/**
 * Idempotently seeds the three designated authorized administrator accounts:
 * 1. Keerthi Manjunath Geddappanavar — karbasamamg@gmail.com
 * 2. Vishal VP — vishalvpurshan360@gmail.com
 * 3. Pooja N Annigere — annigerep@gmail.com
 */

// ================================================================
// PASSWORD RESET (OTP-based)
// ================================================================

export async function createPasswordResetOtp(row: {
  userId: number;
  email: string;
  otpHash: string;
  expiresAt: Date;
}): Promise<number> {
  const db = await getDb();
  if (db) {
    try {
      const result = await db.insert(passwordResetOtps).values({
        userId: row.userId,
        email: row.email.toLowerCase(),
        otpHash: row.otpHash,
        expiresAt: row.expiresAt,
      });
      return Number(result[0].insertId);
    } catch (err) {
      console.error("[db] createPasswordResetOtp failed:", err);
    }
  }
  // Memory fallback: not persisted
  return 0;
}

export async function findActiveResetOtp(email: string, userId: number): Promise<PasswordResetOtp | undefined> {
  const db = await getDb();
  if (!db) return undefined;
  try {
    const rows = await db
      .select()
      .from(passwordResetOtps)
      .where(
        and(
          eq(passwordResetOtps.email, email.toLowerCase()),
          eq(passwordResetOtps.userId, userId),
        )
      )
      .orderBy(desc(passwordResetOtps.createdAt))
      .limit(5);
    // Find first unconsumed, unexpired
    const now = new Date();
    return rows.find(r => !r.consumedAt && new Date(r.expiresAt) > now);
  } catch (err) {
    console.error("[db] findActiveResetOtp failed:", err);
    return undefined;
  }
}

export async function consumeResetOtp(id: number): Promise<void> {
  const db = await getDb();
  if (!db) return;
  try {
    await db.update(passwordResetOtps).set({ consumedAt: new Date() }).where(eq(passwordResetOtps.id, id));
  } catch (err) {
    console.error("[db] consumeResetOtp failed:", err);
  }
}

export async function incrementOtpAttempt(id: number): Promise<void> {
  const db = await getDb();
  if (!db) return;
  try {
    await db.update(passwordResetOtps)
      .set({ attemptCount: sql`${passwordResetOtps.attemptCount} + 1` })
      .where(eq(passwordResetOtps.id, id));
  } catch (err) {
    console.error("[db] incrementOtpAttempt failed:", err);
  }
}

export async function countRecentResetRequests(email: string, windowMs: number): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  try {
    const since = new Date(Date.now() - windowMs);
    const rows = await db
      .select({ id: passwordResetThrottle.id })
      .from(passwordResetThrottle)
      .where(
        and(
          eq(passwordResetThrottle.email, email.toLowerCase()),
          sql`${passwordResetThrottle.requestedAt} >= ${since}`,
        )
      );
    return rows.length;
  } catch (err) {
    console.error("[db] countRecentResetRequests failed:", err);
    return 0;
  }
}

export async function logResetRequest(email: string, type: "request" | "resend"): Promise<void> {
  const db = await getDb();
  if (!db) return;
  try {
    await db.insert(passwordResetThrottle).values({ email: email.toLowerCase(), type });
  } catch (err) {
    console.error("[db] logResetRequest failed:", err);
  }
}

export async function invalidateUserSessions(userId: number): Promise<void> {
  const db = await getDb();
  if (!db) return;
  try {
    await db.update(users)
      .set({ sessionsInvalidatedAt: new Date(), updatedAt: new Date() })
      .where(eq(users.id, userId));
  } catch (err) {
    console.error("[db] invalidateUserSessions failed:", err);
  }
}

export async function getLocalCredentialByUserId(userId: number): Promise<LocalCred | undefined> {
  const db = await getDb();
  if (db) {
    try {
      const rows = await db.select().from(localCredentials).where(eq(localCredentials.userId, userId)).limit(1);
      if (rows[0]) return rows[0];
    } catch { /* fall through */ }
  }
  return Array.from(mem.localCredentials.values()).find(c => c.userId === userId);
}

export async function updatePassword(userId: number, newPasswordHash: string): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db.update(localCredentials)
        .set({ passwordHash: newPasswordHash })
        .where(eq(localCredentials.userId, userId));
      return;
    } catch (err) {
      console.error("[db] updatePassword failed:", err);
    }
  }
  const cred = Array.from(mem.localCredentials.values()).find(c => c.userId === userId);
  if (cred) cred.passwordHash = newPasswordHash;
}

export async function seedAdminAccounts(): Promise<{ created: number; existing: number; total: number }> {
  let created = 0;
  let existing = 0;

  for (const admin of INITIAL_ADMINS) {
    try {
      const existingUser = await getUserByEmail(admin.email);
      if (!existingUser) {
        const passwordHash = await hashPassword(admin.defaultPassword);
        const openId = `admin_${randomUUID()}`;
        await createLocalAccount({
          openId,
          publicId: `adm_${randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase()}`,
          name: admin.name,
          email: admin.email,
          passwordHash,
          role: "admin",
        });
        await addSecurityLog(null, "admin.seeded", "success", `Admin account initialized: ${admin.email}`);
        created++;
      } else {
        existing++;
        if (existingUser.role !== "admin") {
          await updateUser(existingUser.id, { role: "admin" });
        }
      }
    } catch (err) {
      console.error(`[Seed] Error initializing admin ${admin.email}:`, err);
    }
  }

  return { created, existing, total: INITIAL_ADMINS.length };
}

/**
 * Export all user data from the last N days (default 10).
 * Returns a structured object that can be serialized to JSON.
 */

export async function exportUserData(userId: number, daysBack = 10) {
  const cutoff = new Date(Date.now() - daysBack * 24 * 60 * 60 * 1000);

  let user: User | undefined;
  try { user = await getUserById(userId); } catch (e) { console.error("[export] user failed", e); }

  let userScans: Scan[] = [];
  try { userScans = await listUserScans(userId); } catch (e) { console.error("[export] scans failed", e); }

  let userTickets: Awaited<ReturnType<typeof listUserTickets>> = [];
  try { userTickets = await listUserTickets(userId); } catch (e) { console.error("[export] tickets failed", e); }

  let userNotifications: Notification[] = [];
  try { userNotifications = await listNotifications(userId); } catch (e) { console.error("[export] notifications failed", e); }

  let userLogs: SecurityLog[] = [];
  try {
    const allLogs = await listSecurityLogs();
    userLogs = allLogs.filter(l => l.userId === userId);
  } catch (e) { console.error("[export] logs failed", e); }

  let userAttempts: AwarenessAttempt[] = [];
  try { userAttempts = await listAwarenessAttempts(userId); } catch (e) { console.error("[export] attempts failed", e); }

  return {
    exportedAt: new Date().toISOString(),
    daysIncluded: daysBack,
    account: user
      ? {
        publicId: user.publicId,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
        createdAt: user.createdAt,
        lastSignedIn: user.lastSignedIn,
      }
      : null,
    scans: userScans.filter(s => new Date(s.createdAt) >= cutoff),
    tickets: userTickets.filter(t => new Date(t.createdAt) >= cutoff),
    notifications: userNotifications.filter(n => new Date(n.createdAt) >= cutoff),
    securityLogs: userLogs.filter(l => new Date(l.createdAt) >= cutoff),
    awarenessAttempts: userAttempts.filter(a => new Date(a.createdAt) >= cutoff),
  };
}

/**
 * Permanently delete a user account and all associated data.
 * MySQL CASCADE will remove localCredentials, scans, tickets, notifications.
 * Also clears in-memory fallback stores.
 */
export async function deleteUserAccount(userId: number): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      // Delete cascades from users → localCredentials, but scans/tickets/notifications
      // are not foreign-keyed. Delete them explicitly.
      await db.delete(scans).where(eq(scans.userId, userId));
      await db.delete(tickets).where(eq(tickets.userId, userId));
      await db.delete(notifications).where(eq(notifications.userId, userId));
      await db.delete(awarenessAttempts).where(eq(awarenessAttempts.userId, userId));
      await db.delete(securityLogs).where(eq(securityLogs.userId, userId));
      await db.delete(localCredentials).where(eq(localCredentials.userId, userId));
      await db.delete(users).where(eq(users.id, userId));
      return;
    } catch (err) {
      console.error("[DB] deleteUserAccount failed, falling back to memory:", err);
    }
  }

  // Memory fallback cleanup
  mem.users.delete(userId);
  mem.scans.forEach((scan, id) => { if (scan.userId === userId) mem.scans.delete(id); });
  mem.tickets.forEach((t, id) => { if (t.userId === userId) mem.tickets.delete(id); });
  mem.notifications.forEach((n, id) => { if (n.userId === userId) mem.notifications.delete(id); });
  mem.awarenessAttempts.forEach((a, id) => { if (a.userId === userId) mem.awarenessAttempts.delete(id); });
  mem.securityLogs = mem.securityLogs.filter(l => l.userId !== userId);
  mem.localCredentials.forEach((c, id) => { if (c.userId === userId) mem.localCredentials.delete(id); });
}