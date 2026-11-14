import { randomBytes, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import { loadConfig } from "./config.mjs";
import {
  clientKey,
  createChallengeStore,
  createWindowLimiter,
  deviceHash,
  fuzzCoordinates,
  parseCookies,
  safeBearer
} from "./privacy.mjs";
import { createStore } from "./store.mjs";

const DAY_MS = 86_400_000;
const REPORT_CATEGORIES = Object.freeze(["spot", "full", "hazard", "activity", "resource"]);
const STATIC_FILES = new Map([
  ["/", ["../public/index.html", "text/html; charset=utf-8"]],
  ["/app.js", ["../public/app.js", "text/javascript; charset=utf-8"]],
  ["/styles.css", ["../public/styles.css", "text/css; charset=utf-8"]],
  ["/manifest.webmanifest", ["../public/manifest.webmanifest", "application/manifest+json"]],
  ["/sw.js", ["../public/sw.js", "text/javascript; charset=utf-8"]],
  ["/icon.svg", ["../public/icon.svg", "image/svg+xml"]],
  ["/pow-worker.js", ["../public/pow-worker.js", "text/javascript; charset=utf-8"]],
  ["/vendor/leaflet.js", ["../node_modules/leaflet/dist/leaflet.js", "text/javascript; charset=utf-8"]],
  ["/vendor/leaflet.css", ["../node_modules/leaflet/dist/leaflet.css", "text/css; charset=utf-8"]]
]);

export async function createApp(options = {}) {
  const config = options.config ?? loadConfig();
  const now = options.now ?? (() => Date.now());
  const store = options.store ?? await createStore(config);
  const app = Fastify({
    logger: false,
    bodyLimit: 4096,
    trustProxy: false,
    ajv: { customOptions: { removeAdditional: false } }
  });
  const limiter = createWindowLimiter({ now });
  const challenges = createChallengeStore({ ttlMs: config.powTtlMs, difficultyBits: config.powDifficultyBits, now });

  app.decorate("store", store);
  app.addHook("onSend", async (_request, reply) => {
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
    reply.header("Cross-Origin-Resource-Policy", "same-origin");
    reply.header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  });
  app.setErrorHandler((error, _request, reply) => {
    if (error.statusCode === 413) return reply.code(413).send(apiError("E_REQUEST_SIZE", "Request is too large"));
    if (error.validation || error.statusCode === 400) return reply.code(400).send(apiError("E_REQUEST", "Request shape is invalid"));
    return reply.code(500).send(apiError("E_INTERNAL", "Request could not be completed"));
  });

  app.get("/api/health", async (_request, reply) => {
    reply.header("Cache-Control", "no-store");
    await store.health();
    return { ok: true };
  });

  app.get("/api/config", async (_request, reply) => {
    reply.header("Cache-Control", "no-store");
    return {
      categories: REPORT_CATEGORIES.filter(category => category !== "activity" || config.activityAlertsEnabled),
      activityReportsEnabled: config.activityAlertsEnabled,
      publicationDelayMinutes: Math.ceil(config.publishDelayMs / 60_000),
      activityDelayMinutes: Math.ceil(config.activityPublishDelayMs / 60_000),
      sensitiveAreaApproxMeters: Math.round(config.coordFuzzDegrees * config.sensitiveCellMultiplier * 111_000),
      resourceAreaApproxMeters: Math.round(config.coordFuzzDegrees * config.resourceCellMultiplier * 111_000)
    };
  });

  app.get("/api/device", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    if (!allow(request, reply, limiter, config, "device", config.readRateLimit, now)) return;
    let token = parseCookies(request.headers.cookie).get("spotsignal_device");
    if (!isDeviceToken(token)) {
      token = randomBytes(32).toString("base64url");
      const secure = config.secureCookies ? "; Secure" : "";
      reply.header("Set-Cookie", `spotsignal_device=${token}; Max-Age=${Math.floor(DAY_MS / 1000)}; Path=/; HttpOnly; SameSite=Strict${secure}`);
    }
    return { ready: true, expiresInSeconds: Math.floor(DAY_MS / 1000) };
  });

  app.get("/api/challenge", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const client = clientKey(request.ip, config.appHmacSecret);
    if (!limiter.take(`challenge:${client}`, config.challengeRateLimit, 60_000)) {
      return reply.code(429).send(apiError("E_RATE_LIMIT", "Too many challenges"));
    }
    const challenge = challenges.issue(client);
    if (!challenge) return reply.code(503).send(apiError("E_CAPACITY", "Challenge capacity is temporarily full"));
    return { challenge: challenge.challenge, difficultyBits: challenge.difficultyBits, expiresAt: new Date(challenge.expiresAt).toISOString() };
  });

  app.get("/api/alerts", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const hash = currentDeviceHash(request, config, now());
    if (!hash) return { enabled: false };
    return { enabled: await store.hasAlertPreference(hash, new Date(now())) };
  });

  app.post("/api/alerts", { schema: { body: alertSchema() } }, async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    if (!config.activityAlertsEnabled) return reply.code(403).send(apiError("E_ACTIVITY_DISABLED", "Activity reports are disabled"));
    const hash = currentDeviceHash(request, config, now());
    if (!hash) return reply.code(401).send(apiError("E_DEVICE", "Reload to initialize a private device token"));
    if (!consumeChallenge(request, reply, challenges, clientKey(request.ip, config.appHmacSecret))) return;
    const timestamp = new Date(now());
    if (request.body.enabled === false) {
      await store.setAlertPreference(hash, false, null, null, null, timestamp);
      return { enabled: false };
    }
    const radiusMeters = request.body.radiusMeters;
    if (![1000, 3000, 5000].includes(radiusMeters)) return reply.code(400).send(apiError("E_REQUEST", "Alert radius must be 1, 3, or 5 km"));
    const coarse = fuzzCoordinates(request.body.latitude, request.body.longitude, "activity", config);
    const expiresAt = new Date(timestamp.getTime() + config.alertPreferenceTtlMs);
    const result = await store.setAlertPreference(hash, true, coarse, radiusMeters, expiresAt, timestamp);
    return { enabled: true, expiresAt: new Date(result.expiresAt).toISOString(), radiusMeters };
  });

  app.get("/api/reports", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    if (!allow(request, reply, limiter, config, "reports", config.readRateLimit, now)) return;
    const limit = Number(request.query?.limit ?? config.maxMapReports);
    if (!Number.isInteger(limit) || limit < 1 || limit > config.maxMapReports) {
      return reply.code(400).send(apiError("E_REQUEST", `limit must be an integer from 1 through ${config.maxMapReports}`));
    }
    const hash = currentDeviceHash(request, config, now());
    const reports = await store.listReports({ now: new Date(now()), limit, deviceHash: hash, includeActivity: config.activityAlertsEnabled });
    return { reports: reports.map(toPublicReport) };
  });

  app.post("/api/reports", { schema: { body: reportSchema({ proof: true }) } }, async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const device = currentDeviceHash(request, config, now());
    if (!device) return reply.code(401).send(apiError("E_DEVICE", "Reload to initialize a private device token"));
    if (!consumeChallenge(request, reply, challenges, clientKey(request.ip, config.appHmacSecret))) return;
    if (!allow(request, reply, limiter, config, "reports-write", config.writeRateLimit, now)) return;
    const since = new Date(now() - config.rateWindowMs);
    if (await store.countRecentReports(device, since) >= config.deviceReportLimit) {
      return reply.code(429).send(apiError("E_DEVICE_RATE_LIMIT", "This browser has reached its report limit for now"));
    }
    const result = await saveReport(request.body, { store, config, now: new Date(now()), deviceHash: device });
    if (!result.ok) return reply.code(result.status).send(apiError(result.code, result.message));
    return reply.code(201).send({ accepted: true, report: toPublicReport(result.report) });
  });

  app.post("/api/reports/:id/votes", {
    schema: {
      params: { type: "object", required: ["id"], properties: { id: { type: "string", format: "uuid" } }, additionalProperties: false },
      body: { type: "object", required: ["vote", "challenge", "nonce"], properties: {
        vote: { type: "string", enum: ["confirm", "deny"] },
        challenge: { type: "string", minLength: 64, maxLength: 64, pattern: "^[a-f0-9]+$" },
        nonce: { type: "string", minLength: 1, maxLength: 128, pattern: "^\\d+$" }
      }, additionalProperties: false }
    }
  }, async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    const device = currentDeviceHash(request, config, now());
    if (!device) return reply.code(401).send(apiError("E_DEVICE", "Reload to initialize a private device token"));
    if (!consumeChallenge(request, reply, challenges, clientKey(request.ip, config.appHmacSecret))) return;
    if (!allow(request, reply, limiter, config, "vote", config.writeRateLimit, now)) return;
    const result = await store.voteReport(request.params.id, device, request.body.vote, new Date(now()));
    if (result.kind === "not_found") return reply.code(404).send(apiError("E_NOT_FOUND", "Report is unavailable"));
    if (result.kind === "vote_limit") return reply.code(409).send(apiError("E_VOTE_LIMIT", "This browser has already voted on this report"));
    return { report: toPublicReport(result.report) };
  });

  app.post("/api/bot/reports", { schema: { body: reportSchema({ proof: false }) } }, async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    if (!authorized(request.headers.authorization, config.botIngestToken)) {
      return reply.code(401).send(apiError("E_AUTH", "Bot ingestion is not authorized"));
    }
    const botClient = clientKey("telegram-bot", config.appHmacSecret);
    if (!limiter.take(`bot:${botClient}`, config.botRateLimit, config.rateWindowMs)) {
      return reply.code(429).send(apiError("E_RATE_LIMIT", "Bot report limit reached"));
    }
    const result = await saveReport(request.body, { store, config, now: new Date(now()), deviceHash: botClient, fromBot: true });
    if (!result.ok) return reply.code(result.status).send(apiError(result.code, result.message));
    return reply.code(201).send({ accepted: true, report: toPublicReport(result.report) });
  });

  app.get("/api/moderation/reports", async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    if (!authorized(request.headers.authorization, config.moderationToken)) {
      return reply.code(401).send(apiError("E_AUTH", "Moderation access is not authorized"));
    }
    return { reports: (await store.listModerationReports({ now: new Date(now()), limit: 200 })).map(toPublicReport) };
  });

  app.delete("/api/moderation/reports/:id", {
    schema: { params: { type: "object", required: ["id"], properties: { id: { type: "string", format: "uuid" } }, additionalProperties: false } }
  }, async (request, reply) => {
    reply.header("Cache-Control", "no-store");
    if (!authorized(request.headers.authorization, config.moderationToken)) {
      return reply.code(401).send(apiError("E_AUTH", "Moderation access is not authorized"));
    }
    if (!await store.deleteReport(request.params.id)) return reply.code(404).send(apiError("E_NOT_FOUND", "Report not found"));
    return { removed: true };
  });

  for (const [route, [relativePath, contentType]] of STATIC_FILES) {
    const asset = await readFile(fileURLToPath(new URL(relativePath, import.meta.url)));
    app.get(route, async (_request, reply) => {
      reply.type(contentType).header("Cache-Control", route === "/sw.js" ? "no-cache" : "public, max-age=300");
      if (route === "/sw.js") reply.header("Service-Worker-Allowed", "/");
      return reply.send(asset);
    });
  }

  app.addHook("onClose", async () => store.close());
  return app;
}

export async function saveReport(input, { store, config, now, deviceHash: hash, fromBot = false }) {
  if (!REPORT_CATEGORIES.includes(input.category)) return { ok: false, status: 400, code: "E_CATEGORY", message: "Category is not supported" };
  if (input.category === "activity" && !config.activityAlertsEnabled) {
    return { ok: false, status: 403, code: "E_ACTIVITY_DISABLED", message: "Activity reports are disabled" };
  }
  if (input.category === "activity" && input.activityOptIn !== true) {
    return { ok: false, status: 400, code: "E_ACTIVITY_OPT_IN", message: "Activity reports require explicit opt-in" };
  }
  if (input.category !== "activity" && input.activityOptIn === true) {
    return { ok: false, status: 400, code: "E_REQUEST", message: "Activity opt-in is only valid for activity reports" };
  }
  if (!Number.isFinite(input.latitude) || input.latitude < -90 || input.latitude > 90 || !Number.isFinite(input.longitude) || input.longitude < -180 || input.longitude > 180) {
    return { ok: false, status: 400, code: "E_COORDINATE", message: "Latitude or longitude is outside the valid range" };
  }
  if (!Number.isInteger(input.confidence) || input.confidence < 1 || input.confidence > 3) {
    return { ok: false, status: 400, code: "E_CONFIDENCE", message: "Confidence must be 1, 2, or 3" };
  }
  const coarse = fuzzCoordinates(input.latitude, input.longitude, input.category, config);
  const timestamp = time(now);
  const isActivity = input.category === "activity";
  const delay = isActivity ? Math.max(config.publishDelayMs, config.activityPublishDelayMs) : config.publishDelayMs;
  const createdAt = new Date(timestamp);
  const report = {
    submissionId: input.submissionId,
    category: input.category,
    latitude: coarse.latitude,
    longitude: coarse.longitude,
    confidence: input.confidence,
    deviceHash: hash,
    activityOptIn: isActivity && input.activityOptIn === true,
    createdAt,
    visibleAt: new Date(timestamp + delay),
    expiresAt: new Date(timestamp + config.reportTtlMs[input.category])
  };
  return { ok: true, report: await store.createReport(report) };
}

export function toPublicReport(report) {
  return {
    id: report.id,
    category: report.category,
    latitude: report.latitude,
    longitude: report.longitude,
    confidence: report.confidence,
    confirmCount: report.confirmCount,
    denyCount: report.denyCount,
    reportedDay: new Date(report.createdAt).toISOString().slice(0, 10),
    expiresDay: new Date(report.expiresAt).toISOString().slice(0, 10)
  };
}

function reportSchema({ proof }) {
  const properties = {
    submissionId: { type: "string", format: "uuid" },
    category: { type: "string", enum: REPORT_CATEGORIES },
    latitude: { type: "number", minimum: -90, maximum: 90 },
    longitude: { type: "number", minimum: -180, maximum: 180 },
    confidence: { type: "integer", minimum: 1, maximum: 3 },
    activityOptIn: { type: "boolean" }
  };
  const required = ["submissionId", "category", "latitude", "longitude", "confidence"];
  if (proof) {
    properties.challenge = { type: "string", minLength: 64, maxLength: 64, pattern: "^[a-f0-9]+$" };
    properties.nonce = { type: "string", minLength: 1, maxLength: 128, pattern: "^\\d+$" };
    required.push("challenge", "nonce");
  }
  return { type: "object", required, properties, additionalProperties: false };
}

function alertSchema() {
  const common = {
    challenge: { type: "string", minLength: 64, maxLength: 64, pattern: "^[a-f0-9]+$" },
    nonce: { type: "string", minLength: 1, maxLength: 128, pattern: "^\\d+$" }
  };
  return { oneOf: [
    { type: "object", required: ["enabled", "challenge", "nonce"], properties: { ...common, enabled: { const: false } }, additionalProperties: false },
    { type: "object", required: ["enabled", "latitude", "longitude", "radiusMeters", "challenge", "nonce"], properties: {
      ...common,
      enabled: { const: true },
      latitude: { type: "number", minimum: -90, maximum: 90 },
      longitude: { type: "number", minimum: -180, maximum: 180 },
      radiusMeters: { type: "integer", enum: [1000, 3000, 5000] }
    }, additionalProperties: false }
  ] };
}

function consumeChallenge(request, reply, challenges, client) {
  if (challenges.consume(request.body.challenge, request.body.nonce, client)) return true;
  reply.code(403).send(apiError("E_CHALLENGE", "Challenge is expired, invalid, or belongs to another client"));
  return false;
}

function currentDeviceHash(request, config, timestamp) {
  const token = parseCookies(request.headers.cookie).get("spotsignal_device");
  if (!isDeviceToken(token)) return null;
  return deviceHash(token, config.appHmacSecret, timestamp);
}

function isDeviceToken(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{40,50}$/.test(value);
}

function allow(request, reply, limiter, config, label, limit, now) {
  const key = clientKey(request.ip, config.appHmacSecret);
  if (limiter.take(`${label}:${key}`, limit, config.rateWindowMs)) return true;
  reply.code(429).send(apiError("E_RATE_LIMIT", "Too many requests; wait before retrying"));
  return false;
}

function authorized(header, expected) {
  return Boolean(expected) && safeBearer(header, expected);
}

function apiError(code, message) {
  return { code, message };
}

function time(value) {
  return value instanceof Date ? value.getTime() : Number(value);
}

export async function startServer() {
  const config = loadConfig();
  const app = await createApp({ config });
  const cleanupTimer = setInterval(() => {
    app.store.purgeExpired(new Date()).catch(() => {});
  }, config.cleanupIntervalMs);
  cleanupTimer.unref();
  await app.listen({ host: config.host, port: config.port });
  const shutdown = async () => {
    clearInterval(cleanupTimer);
    await app.close();
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
  return { app, close: shutdown };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await startServer();
}
