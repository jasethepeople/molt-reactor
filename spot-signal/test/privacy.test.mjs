import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  clientKey,
  createChallengeStore,
  createWindowLimiter,
  deviceHash,
  fuzzCoordinates,
  safeBearer,
  verifyProofOfWork
} from "../src/privacy.mjs";
import { loadConfig } from "../src/config.mjs";

test("public-client keys are keyed hashes, not raw addresses", () => {
  const first = clientKey("203.0.113.7", "secret-a");
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.notEqual(first, "203.0.113.7");
  assert.notEqual(first, clientKey("203.0.113.7", "secret-b"));
});

test("device pseudonyms are keyed and rotate at UTC midnight", () => {
  const token = "x".repeat(43);
  const firstDay = deviceHash(token, "secret", Date.UTC(2026, 0, 1, 23, 59));
  const secondDay = deviceHash(token, "secret", Date.UTC(2026, 0, 2, 0, 1));
  assert.notEqual(firstDay, secondDay);
  assert.match(firstDay, /^[a-f0-9]{64}$/);
});

test("proof of work checks the requested leading zero bits", () => {
  const challenge = "ab".repeat(32);
  let validNonce;
  for (let nonce = 0; nonce < 100_000; nonce += 1) {
    const digest = createHash("sha256").update(`${challenge}:${nonce}`).digest();
    if (digest[0] < 16) {
      validNonce = String(nonce);
      break;
    }
  }
  assert.ok(validNonce);
  assert.equal(verifyProofOfWork(challenge, validNonce, 4), true);
  assert.equal(verifyProofOfWork(challenge, validNonce, 5), false);
  assert.equal(verifyProofOfWork(challenge, "-1", 0), false);
});

test("challenge tokens are one-use, expiring, and client-bound", () => {
  let clock = 1_000;
  const challenges = createChallengeStore({ ttlMs: 100, difficultyBits: 0, now: () => clock });
  const first = challenges.issue("client-a");
  assert.equal(challenges.consume(first.challenge, "0", "client-b"), false);
  const second = challenges.issue("client-a");
  assert.equal(challenges.consume(second.challenge, "0", "client-a"), true);
  assert.equal(challenges.consume(second.challenge, "0", "client-a"), false);
  const third = challenges.issue("client-a");
  clock += 101;
  assert.equal(challenges.consume(third.challenge, "0", "client-a"), false);
});

test("window limits reset after their fixed time bucket", () => {
  let clock = 0;
  const limiter = createWindowLimiter({ now: () => clock });
  assert.equal(limiter.take("hashed-client", 2, 1_000), true);
  assert.equal(limiter.take("hashed-client", 2, 1_000), true);
  assert.equal(limiter.take("hashed-client", 2, 1_000), false);
  clock = 1_000;
  assert.equal(limiter.take("hashed-client", 2, 1_000), true);
});

test("coordinate cells are broadest for reports that could expose a sleeping place", () => {
  const config = loadConfig({ NODE_ENV: "test", APP_HMAC_SECRET: "x".repeat(64) });
  const sensitive = fuzzCoordinates(47.6205, -122.3493, "spot", config);
  const publicResource = fuzzCoordinates(47.6205, -122.3493, "resource", config);
  assert.ok(Math.abs(sensitive.latitude - 47.6205) <= 0.0015);
  assert.ok(Math.abs(sensitive.longitude - -122.3493) <= 0.0015);
  assert.notDeepEqual(sensitive, publicResource);
  assert.throws(() => fuzzCoordinates(91, 0, "resource", config));
});

test("production config keeps activity disabled and enforces coarse defaults", () => {
  const config = loadConfig({
    NODE_ENV: "production",
    APP_HMAC_SECRET: "x".repeat(64),
    DATABASE_URL: "postgres://example",
    SPOTSIGNAL_STORE: "postgres"
  });
  assert.equal(config.activityAlertsEnabled, false);
  assert.equal(config.coordFuzzDegrees, 0.0005);
  assert.equal(config.sensitiveCellMultiplier, 6);
  assert.equal(config.resourceCellMultiplier, 2);
  assert.throws(() => loadConfig({ NODE_ENV: "production", DATABASE_URL: "postgres://example" }));
});

test("bearer authentication is exact and fails closed for missing secrets", () => {
  const token = "t".repeat(40);
  assert.equal(safeBearer(`Bearer ${token}`, token), true);
  assert.equal(safeBearer(`bearer ${token}`, token), false);
  assert.equal(safeBearer(`Bearer ${token}x`, token), false);
  assert.equal(safeBearer(`Bearer ${token}`, ""), false);
});
