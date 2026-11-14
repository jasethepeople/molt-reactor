import { randomBytes } from "node:crypto";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const DEFAULT_TTLS = Object.freeze({
  spot: 4 * HOUR,
  full: 2 * HOUR,
  hazard: 6 * HOUR,
  activity: 90 * MINUTE,
  resource: 8 * HOUR
});

export function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV ?? "development";
  const storeKind = env.SPOTSIGNAL_STORE ?? (nodeEnv === "production" ? "postgres" : "memory");
  if (!["memory", "postgres"].includes(storeKind)) throw new Error("SPOTSIGNAL_STORE must be memory or postgres");
  const databaseUrl = env.DATABASE_URL ?? "";
  const appHmacSecret = env.APP_HMAC_SECRET ?? (nodeEnv === "production" ? "" : randomBytes(32).toString("hex"));
  const activityAlertsEnabled = env.ACTIVITY_ALERTS_ENABLED === "true";
  const botIngestToken = env.BOT_INGEST_TOKEN ?? "";
  const moderationToken = env.MODERATION_TOKEN ?? "";
  const secureCookies = env.SECURE_COOKIES === undefined ? nodeEnv === "production" : boolean(env.SECURE_COOKIES, "SECURE_COOKIES");

  if (nodeEnv === "production" && (appHmacSecret.length < 32 || /^(change_me|replace|example)/i.test(appHmacSecret))) throw new Error("APP_HMAC_SECRET must be a generated secret of at least 32 characters in production");
  if (nodeEnv === "production" && storeKind !== "postgres") throw new Error("production requires SPOTSIGNAL_STORE=postgres");
  if (storeKind === "postgres" && !databaseUrl) throw new Error("DATABASE_URL is required when SPOTSIGNAL_STORE=postgres");
  if (botIngestToken && botIngestToken.length < 32) throw new Error("BOT_INGEST_TOKEN must contain at least 32 characters");
  if (moderationToken && moderationToken.length < 32) throw new Error("MODERATION_TOKEN must contain at least 32 characters");

  const reportTtlMs = Object.fromEntries(Object.entries(DEFAULT_TTLS).map(([category, fallback]) => [
    category,
    integer(env[`${category.toUpperCase()}_TTL_MS`], fallback, MINUTE, 30 * DAY, `${category.toUpperCase()}_TTL_MS`)
  ]));
  const publishDelayMs = integer(env.PUBLISH_DELAY_MS, 15 * MINUTE, 5 * MINUTE, DAY, "PUBLISH_DELAY_MS");
  const activityPublishDelayMs = integer(env.ACTIVITY_PUBLISH_DELAY_MS, HOUR, HOUR, 24 * HOUR, "ACTIVITY_PUBLISH_DELAY_MS");
  for (const [category, ttlMs] of Object.entries(reportTtlMs)) {
    const delayMs = category === "activity" ? activityPublishDelayMs : publishDelayMs;
    if (delayMs >= ttlMs) throw new Error(`${category.toUpperCase()}_TTL_MS must be longer than its publication delay`);
  }

  return Object.freeze({
    nodeEnv,
    storeKind,
    databaseUrl,
    host: env.HOST ?? "127.0.0.1",
    port: integer(env.PORT, 8080, 1, 65535, "PORT"),
    secureCookies,
    appHmacSecret,
    botIngestToken,
    moderationToken,
    coordFuzzDegrees: finiteRange(env.COORD_FUZZ_DEGREES, 0.0005, 0.0005, 0.1, "COORD_FUZZ_DEGREES"),
    sensitiveCellMultiplier: integer(env.SENSITIVE_CELL_MULTIPLIER, 6, 6, 20, "SENSITIVE_CELL_MULTIPLIER"),
    resourceCellMultiplier: integer(env.RESOURCE_CELL_MULTIPLIER, 2, 2, 20, "RESOURCE_CELL_MULTIPLIER"),
    powDifficultyBits: integer(env.POW_DIFFICULTY_BITS, 18, nodeEnv === "production" ? 18 : 0, 24, "POW_DIFFICULTY_BITS"),
    powTtlMs: integer(env.POW_TTL_MS, 5 * MINUTE, 10_000, HOUR, "POW_TTL_MS"),
    challengeRateLimit: integer(env.CHALLENGE_RATE_LIMIT, 20, 1, 1000, "CHALLENGE_RATE_LIMIT"),
    readRateLimit: integer(env.READ_RATE_LIMIT, 60, 1, 1000, "READ_RATE_LIMIT"),
    writeRateLimit: integer(env.WRITE_RATE_LIMIT, 10, 1, 500, "WRITE_RATE_LIMIT"),
    botRateLimit: integer(env.BOT_RATE_LIMIT, 12, 1, 500, "BOT_RATE_LIMIT"),
    rateWindowMs: integer(env.RATE_WINDOW_MS, HOUR, MINUTE, DAY, "RATE_WINDOW_MS"),
    deviceReportLimit: integer(env.DEVICE_REPORT_LIMIT, 3, 1, 20, "DEVICE_REPORT_LIMIT"),
    maxVotesPerReportDevice: integer(env.MAX_VOTES_PER_REPORT_DEVICE, 1, 1, 1, "MAX_VOTES_PER_REPORT_DEVICE"),
    publishDelayMs,
    activityPublishDelayMs,
    reportTtlMs,
    activityAlertsEnabled,
    maxMapReports: integer(env.MAX_MAP_REPORTS, 200, 1, 500, "MAX_MAP_REPORTS"),
    alertPreferenceTtlMs: integer(env.ALERT_PREFERENCE_TTL_MS, DAY, HOUR, DAY, "ALERT_PREFERENCE_TTL_MS"),
    alertRadiusMeters: integer(env.ALERT_RADIUS_METERS, 3000, 100, 5000, "ALERT_RADIUS_METERS"),
    cleanupIntervalMs: integer(env.CLEANUP_INTERVAL_MS, 60 * MINUTE, MINUTE, DAY, "CLEANUP_INTERVAL_MS")
  });
}

function boolean(raw, name) {
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function integer(raw, fallback, min, max, name) {
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${name} must be an integer between ${min} and ${max}`);
  return value;
}

function finiteRange(raw, fallback, min, max, name) {
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isFinite(value) || value < min || value > max) throw new Error(`${name} must be a finite number between ${min} and ${max}`);
  return value;
}
