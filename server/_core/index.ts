import "dotenv/config";
import express from "express";
import cors from "cors";

import { createServer } from "http";
import { randomBytes } from "node:crypto";
import { createExpressMiddleware } from "@trpc/server/adapters/express";
import { registerOAuthRoutes } from "./oauth";
import { publicPlatformScript } from "./publicConfig";
import { appRouter } from "../routers";
import { createContext } from "./context";
import { serveStatic, setupVite } from "./vite";
import { CSRF_COOKIE_NAME, hasValidCsrfPair, readCsrfCookie } from "./csrf";
import { seedAdminAccounts } from "../db";

// Global handler for unhandled stream errors from third-party parsers.
// Without this, a single malformed APK can crash the whole server.
process.on("uncaughtException", (err) => {
  console.error("[server] uncaught exception:", err?.message ?? err);
  // Don't exit — keep serving.
});

process.on("unhandledRejection", (reason) => {
  console.error("[server] unhandled rejection:", reason);
});


async function startServer() {
  const app = express();
  app.use(cors({
    origin: [
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      /^chrome-extension:\/\//,
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-CSRF-Token", "Authorization"],
  }));
  const server = createServer(app);

  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    next();
  });
  // Base64-encoded 10 MB APKs fit within this bounded parser allowance.
  app.use(express.json({ limit: "22mb" }));
  app.use(express.urlencoded({ limit: "2mb", extended: true }));
  app.get("/api/health", (_req, res) => res.json({ status: "ok" }));
  app.get("/api/platform/config.js", (_req, res) => {
    res.set("Cache-Control", "no-store").type("application/javascript").send(publicPlatformScript());
  });
  registerOAuthRoutes(app);
  // tRPC API
    app.use(
    "/api/trpc",
    (req, res, next) => {
      const origin = req.get("Origin") || "";
      const isExtension = origin.startsWith("chrome-extension://");
      const safeMethod = ["GET", "HEAD", "OPTIONS"].includes(req.method);

      // 1. Chrome extension requests bypass CSRF.
      //    Extensions don't carry cookies or Sec-Fetch-Site headers.
      if (isExtension) {
        return next();
      }

      // 2. Browser requests use double-submit CSRF.
      if (safeMethod) {
        if (!readCsrfCookie(req.headers.cookie)) {
          res.cookie(CSRF_COOKIE_NAME, randomBytes(32).toString("base64url"), {
            httpOnly: false,
            secure: req.secure,
            sameSite: req.secure ? "none" : "lax",
            path: "/",
            maxAge: 24 * 60 * 60 * 1000,
          });
        }
      } else {
        const crossSite = req.get("Sec-Fetch-Site") === "cross-site";
        const validPair = hasValidCsrfPair(req.headers.cookie, req.get("X-CSRF-Token"));
        if (crossSite || !validPair) {
          res.status(403).json({ error: "Invalid or missing CSRF token." });
          return;
        }
      }

      next();
    },
    createExpressMiddleware({
      router: appRouter,
      createContext,
    })
  );
  // development mode uses Vite, production mode uses static files
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Seed authorized initial admin accounts
  await seedAdminAccounts().catch(err => console.warn("[Admin Seeding] Warning:", err));

  const port = Number(process.env.PORT || "3000");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid PORT");
  server.on("error", error => { console.error("Server failed:", error.message); process.exit(1); });
  server.listen(port, "0.0.0.0", () => console.log(`CyberShield AI server listening on port ${port}`));
}

startServer().catch(error => { console.error(error); process.exit(1); });
