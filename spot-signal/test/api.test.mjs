import assert from "node:assert/strict";
import test from "node:test";
import { createApp } from "../src/server.mjs";
import { loadConfig } from "../src/config.mjs";
import { MemoryStore } from "../src/store.mjs";

const secret = "a".repeat(64);

function setup(t, { activityEnabled = false } = {}) {
  let clock = Date.UTC(2026, 0, 1, 12);
  const config = loadConfig({
    NODE_ENV: "test",
    APP_HMAC_SECRET: secret,
    POW_DIFFICULTY_BITS: "0",
    ACTIVITY_ALERTS_ENABLED: String(activityEnabled),
    PUBLISH_DELAY_MS: "300000",
    ACTIVITY_PUBLISH_DELAY_MS: "3600000"
  });
  const store = new MemoryStore(config);
  const app = createApp({ config, store, now: () => clock });
  t.after(async () => (await app).close());
  return { app, config, store, advance: milliseconds => { clock += milliseconds; } };
}

async function cookieFor(appPromise) {
  const app = await appPromise;
  const response = await app.inject({ method: "GET", url: "/api/device" });
  assert.equal(response.statusCode, 200);
  return response.headers["set-cookie"].split(";")[0];
}

async function challengeFor(appPromise) {
  const app = await appPromise;
  const response = await app.inject({ method: "GET", url: "/api/challenge" });
  assert.equal(response.statusCode, 200);
  return { challenge: response.json().challenge, nonce: "0" };
}

async function submitReport(appPromise, cookie, report) {
  const app = await appPromise;
  const proof = await challengeFor(appPromise);
  return app.inject({
    method: "POST",
    url: "/api/reports",
    headers: { cookie, "content-type": "application/json" },
    payload: { ...report, ...proof }
  });
}

test("PWA shell is served with security headers and no location request permission", async t => {
  const { app } = setup(t);
  const response = await (await app).inject({ url: "/" });
  assert.equal(response.statusCode, 200);
  assert.match(response.headers["content-security-policy"], /default-src 'self'/);
  assert.match(response.headers["permissions-policy"], /geolocation=\(\)/);
  assert.match(response.body, /Location access is not requested/);
  assert.match(response.body, /Do not report a person/);
});

test("challenge-protected report stores only coarse coordinates and publishes after delay", async t => {
  const { app, advance } = setup(t);
  const cookie = await cookieFor(app);
  const response = await submitReport(app, cookie, {
    category: "resource",
    latitude: 47.62173,
    longitude: -122.34744,
    confidence: 2,
    submissionId: "34a89f89-76e9-4b6d-8fc7-12fe7cb421aa"
  });
  assert.equal(response.statusCode, 201);
  const accepted = response.json().report;
  assert.notEqual(accepted.latitude, 47.62173);
  assert.notEqual(accepted.longitude, -122.34744);
  assert.equal("note" in accepted, false);
  assert.equal("submissionId" in accepted, false);

  const appInstance = await app;
  const beforeDelay = await appInstance.inject({ url: "/api/reports" });
  assert.deepEqual(beforeDelay.json().reports, []);
  advance(5 * 60_000);
  const afterDelay = await appInstance.inject({ url: "/api/reports" });
  assert.equal(afterDelay.json().reports.length, 1);
  assert.equal(afterDelay.json().reports[0].category, "resource");
});

test("report requests reject free text, unsupported categories, and missing proof", async t => {
  const { app } = setup(t);
  const cookie = await cookieFor(app);
  const appInstance = await app;
  const challenge = await challengeFor(app);
  const base = {
    category: "resource",
    latitude: 47.6,
    longitude: -122.3,
    confidence: 2,
    submissionId: "34a89f89-76e9-4b6d-8fc7-12fe7cb421ab",
    ...challenge
  };
  const withText = await appInstance.inject({
    method: "POST", url: "/api/reports", headers: { cookie, "content-type": "application/json" },
    payload: { ...base, note: "Someone sleeps here" }
  });
  assert.equal(withText.statusCode, 400);
  assert.equal(withText.json().code, "E_REQUEST");

  const noProof = await appInstance.inject({
    method: "POST", url: "/api/reports", headers: { cookie, "content-type": "application/json" },
    payload: { ...base, challenge: undefined, nonce: undefined }
  });
  assert.equal(noProof.statusCode, 400);
});

test("activity reports require global enablement, report opt-in, and a private alert-area opt-in", async t => {
  const { app, advance } = setup(t, { activityEnabled: true });
  const cookie = await cookieFor(app);
  const appInstance = await app;
  const noOptIn = await submitReport(app, cookie, {
    category: "activity", latitude: 47.62, longitude: -122.34, confidence: 2,
    submissionId: "34a89f89-76e9-4b6d-8fc7-12fe7cb421ac"
  });
  assert.equal(noOptIn.statusCode, 400);
  assert.equal(noOptIn.json().code, "E_ACTIVITY_OPT_IN");

  const accepted = await submitReport(app, cookie, {
    category: "activity", latitude: 47.62, longitude: -122.34, confidence: 2, activityOptIn: true,
    submissionId: "34a89f89-76e9-4b6d-8fc7-12fe7cb421ad"
  });
  assert.equal(accepted.statusCode, 201);
  advance(60 * 60_000);
  const noPreference = await appInstance.inject({ url: "/api/reports" });
  assert.deepEqual(noPreference.json().reports, []);

  const proof = await challengeFor(app);
  const preference = await appInstance.inject({
    method: "POST", url: "/api/alerts", headers: { cookie, "content-type": "application/json" },
    payload: { enabled: true, latitude: 47.62, longitude: -122.34, radiusMeters: 3000, challenge: proof.challenge, nonce: proof.nonce }
  });
  assert.equal(preference.statusCode, 200);
  const visibleToOptedInBrowser = await appInstance.inject({ url: "/api/reports", headers: { cookie } });
  assert.equal(visibleToOptedInBrowser.json().reports.length, 1);
  const hiddenFromOtherBrowsers = await appInstance.inject({ url: "/api/reports" });
  assert.deepEqual(hiddenFromOtherBrowsers.json().reports, []);
});

test("votes are limited to one per pseudonymous browser and protected by proof", async t => {
  const { app, advance } = setup(t);
  const cookie = await cookieFor(app);
  const accepted = await submitReport(app, cookie, {
    category: "resource", latitude: 40.7128, longitude: -74.0060, confidence: 1,
    submissionId: "34a89f89-76e9-4b6d-8fc7-12fe7cb421ae"
  });
  assert.equal(accepted.statusCode, 201);
  advance(5 * 60_000);
  const appInstance = await app;
  const reports = (await appInstance.inject({ url: "/api/reports" })).json().reports;
  const proof = await challengeFor(app);
  const vote = { vote: "confirm", challenge: proof.challenge, nonce: proof.nonce };
  const first = await appInstance.inject({
    method: "POST", url: `/api/reports/${reports[0].id}/votes`, headers: { cookie, "content-type": "application/json" }, payload: vote
  });
  assert.equal(first.statusCode, 200);
  assert.equal(first.json().report.confidence, 2);
  const secondProof = await challengeFor(app);
  const second = await appInstance.inject({
    method: "POST", url: `/api/reports/${reports[0].id}/votes`, headers: { cookie, "content-type": "application/json" },
    payload: { vote: "deny", challenge: secondProof.challenge, nonce: secondProof.nonce }
  });
  assert.equal(second.statusCode, 409);
  assert.equal(second.json().code, "E_VOTE_LIMIT");
});

test("bot ingestion and moderation endpoints fail closed without bearer secrets", async t => {
  const { app } = setup(t);
  const appInstance = await app;
  const bot = await appInstance.inject({
    method: "POST", url: "/api/bot/reports", headers: { "content-type": "application/json" },
    payload: { category: "resource", latitude: 47.6, longitude: -122.3, confidence: 2, submissionId: "34a89f89-76e9-4b6d-8fc7-12fe7cb421af" }
  });
  assert.equal(bot.statusCode, 401);
  const moderation = await appInstance.inject({ url: "/api/moderation/reports" });
  assert.equal(moderation.statusCode, 401);
});
