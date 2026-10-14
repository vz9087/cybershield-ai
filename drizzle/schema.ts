import { int, mediumtext, mysqlEnum, mysqlTable, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  publicId: varchar("publicId", { length: 16 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  status: mysqlEnum("status", ["active", "suspended"]).default("active").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
  sessionsInvalidatedAt: timestamp("sessionsInvalidatedAt"),
});

export const scans = mysqlTable("scans", {
  id: varchar("id", { length: 36 }).primaryKey(),
  userId: int("userId").notNull(),
  scanType: mysqlEnum("scanType", ["url", "email", "sms", "link", "apk", "api"]).notNull(),
  inputReference: text("inputReference").notNull(),
  riskScore: int("riskScore").notNull(),
  riskLevel: varchar("riskLevel", { length: 32 }).notNull(),
  action: varchar("action", { length: 32 }).notNull().default("allow"),
  threatType: varchar("threatType", { length: 100 }).notNull(),
  reasons: text("reasons").notNull(),
  indicators: text("indicators").notNull(),
  recommendation: text("recommendation").notNull(),
  safeAlternative: varchar("safeAlternative", { length: 500 }),
  fileHash: varchar("fileHash", { length: 64 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const localCredentials = mysqlTable("local_credentials", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  email: varchar("email", { length: 320 }).notNull(),
  passwordHash: varchar("passwordHash", { length: 255 }).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
}, table => ({
  localCredentialsUserUnique: uniqueIndex("local_credentials_user_unique").on(table.userId),
  localCredentialsEmailUnique: uniqueIndex("local_credentials_email_unique").on(table.email),
}));

export const threats = mysqlTable("threats", {
  id: int("id").autoincrement().primaryKey(),
  indicator: varchar("indicator", { length: 500 }).notNull().unique(),
  threatType: varchar("threatType", { length: 100 }).notNull(),
  riskScore: int("riskScore").notNull(),
  status: mysqlEnum("status", ["confirmed", "blocked", "safe"]).default("confirmed").notNull(),
  source: varchar("source", { length: 100 }).notNull().default("community-report"),
  firstDetected: timestamp("firstDetected").defaultNow().notNull(),
  lastChecked: timestamp("lastChecked").defaultNow().notNull(),
  confirmedBy: varchar("confirmedBy", { length: 320 }),
  notes: text("notes"),
});

export const tickets = mysqlTable("tickets", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  scanId: varchar("scanId", { length: 36 }),
  category: varchar("category", { length: 100 }).notNull(),
  description: text("description").notNull(),
  additionalDetails: text("additionalDetails"),
  indicator: varchar("indicator", { length: 500 }),
  riskScore: int("riskScore"),
  threatType: varchar("threatType", { length: 100 }),
  screenshotData: mediumtext("screenshotData"),
  priority: mysqlEnum("priority", ["low", "medium", "high", "critical"]).default("medium").notNull(),
  status: mysqlEnum("status", ["new", "under_review", "confirmed", "false_report", "need_more_info", "resolved"]).default("new").notNull(),
  assignedAdminId: int("assignedAdminId"),
  adminNotes: text("adminNotes"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export const ticketResponses = mysqlTable("ticket_responses", {
  id: int("id").autoincrement().primaryKey(),
  ticketId: int("ticketId").notNull(),
  authorId: int("authorId").notNull(),
  authorRole: mysqlEnum("authorRole", ["user", "admin"]).notNull(),
  message: text("message").notNull(),
  attachmentName: varchar("attachmentName", { length: 255 }),
  attachmentType: varchar("attachmentType", { length: 100 }),
  attachmentData: mediumtext("attachmentData"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const passwordResetOtps = mysqlTable("password_reset_otps", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  email: varchar("email", { length: 320 }).notNull(),
  otpHash: varchar("otpHash", { length: 255 }).notNull(),
  expiresAt: timestamp("expiresAt").notNull(),
  consumedAt: timestamp("consumedAt"),
  attemptCount: int("attemptCount").notNull().default(0),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const passwordResetThrottle = mysqlTable("password_reset_throttle", {
  id: int("id").autoincrement().primaryKey(),
  email: varchar("email", { length: 320 }).notNull(),
  requestedAt: timestamp("requestedAt").defaultNow().notNull(),
  type: varchar("type", { length: 40 }).notNull().default("request"),
});

export type PasswordResetOtp = typeof passwordResetOtps.$inferSelect;

export type TicketResponse = typeof ticketResponses.$inferSelect;

export const notifications = mysqlTable("notifications", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  title: varchar("title", { length: 200 }).notNull(),
  message: text("message").notNull(),
  type: varchar("type", { length: 40 }).notNull().default("info"),
  readStatus: int("readStatus").notNull().default(0),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const awarenessAttempts = mysqlTable("awareness_attempts", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  score: int("score").notNull(),
  totalQuestions: int("totalQuestions").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const securityLogs = mysqlTable("security_logs", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId"),
  action: varchar("action", { length: 120 }).notNull(),
  status: varchar("status", { length: 40 }).notNull().default("success"),
  details: text("details"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const emailOutbox = mysqlTable("email_outbox", {
  id: int("id").autoincrement().primaryKey(),
  recipient: varchar("recipient", { length: 320 }),
  subject: varchar("subject", { length: 240 }).notNull(),
  body: text("body"),
  status: varchar("status", { length: 40 }).notNull().default("provider_not_configured"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
export type Scan = typeof scans.$inferSelect;
export type Ticket = typeof tickets.$inferSelect;
export type Threat = typeof threats.$inferSelect;
