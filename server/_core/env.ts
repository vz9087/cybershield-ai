// Platform values are read at use time. See the Webdev service/authentication skills.
export const ENV = {
  get appId() { return process.env.APP_ID || process.env.MANUS_PROJECT_ID || "cybershield-ai"; },
  get cookieSecret() { return process.env.JWT_SECRET || process.env.SESSION_SECRET || process.env.MANUS_JWT_SECRET || "cybershield-ai-secure-jwt-key-2026-cseresearch"; },
  get databaseUrl() { return process.env.DATABASE_URL ?? ""; },
  get oAuthServerUrl() { return process.env.MANUS_OAUTH_API_URL ?? ""; },
  get ownerOpenId() { return process.env.OWNER_OPEN_ID ?? ""; },
  get isProduction() { return process.env.NODE_ENV === "production"; },
  get forgeApiUrl() { return process.env.MANUS_API_URL ?? ""; },
  get forgeApiKey() { return process.env.MANUS_API_KEY ?? ""; },
};
