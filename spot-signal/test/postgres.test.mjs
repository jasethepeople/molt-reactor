import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import { loadConfig } from "../src/config.mjs";
import { createStore } from "../src/store.mjs";

const databaseUrl = process.env.TEST_DATABASE_URL;
const appDatabaseUrl = process.env.SPOTSIGNAL_TEST_APP_DATABASE_URL ?? databaseUrl;

test("PostGIS migration, coarse storage, activity scope, votes, and expiry", { skip: !databaseUrl }, async () => {
  const databaseName = decodeURIComponent(new URL(databaseUrl).pathname.slice(1));
  assert.match(databaseName, /(^|_)test$/i, "TEST_DATABASE_URL must point to a database ending in _test");
  const config = loadConfig({
    NODE_ENV: "test",
    SPOTSIGNAL_STORE: "postgres",
    DATABASE_URL: appDatabaseUrl,
    APP_HMAC_SECRET: "a".repeat(64),
    ACTIVITY_ALERTS_ENABLED: "true",
    POW_DIFFICULTY_BITS: "0"
  });
  const inspector = new Pool({ connectionString: databaseUrl });
  await inspector.query("CREATE EXTENSION IF NOT EXISTS postgis");
  const store = await createStore(config);
  const reportIds = [];
  const now = new Date();
  const deviceHash = "a".repeat(64);
  const alertHash = "b".repeat(64);
  const coarseResource = {
    submissionId: randomUUID(),
    category: "resource",
    latitude: 47.62173,
    longitude: -122.34744,
    confidence: 2,
    deviceHash,
    activityOptIn: false,
    createdAt: new Date(now.getTime() - 60_000),
    visibleAt: new Date(now.getTime() - 30_000),
    expiresAt: new Date(now.getTime() + 60 * 60_000)
  };

  try {
    const resource = await store.createReport(coarseResource);
    reportIds.push(resource.id);
    const saved = await inspector.query(
      "SELECT ST_Y(location) AS latitude, ST_X(location) AS longitude FROM reports WHERE id = $1",
      [resource.id]
    );
    assert.notEqual(Number(saved.rows[0].latitude), coarseResource.latitude);
    assert.notEqual(Number(saved.rows[0].longitude), coarseResource.longitude);
    assert.equal(Number(saved.rows[0].latitude), resource.latitude);
    assert.equal(Number(saved.rows[0].longitude), resource.longitude);

    const activity = await store.createReport({
      ...coarseResource,
      submissionId: randomUUID(),
      category: "activity",
      latitude: 47.62291,
      longitude: -122.34519,
      deviceHash: alertHash,
      activityOptIn: true
    });
    reportIds.push(activity.id);
    const hidden = await store.listReports({ now, limit: 50, deviceHash, includeActivity: true });
    assert.equal(hidden.some(report => report.id === activity.id), false);

    await store.setAlertPreference(alertHash, true, { latitude: 47.62291, longitude: -122.34519 }, 3000, new Date(now.getTime() + 60 * 60_000), now);
    const visible = await store.listReports({ now, limit: 50, deviceHash: alertHash, includeActivity: true });
    assert.equal(visible.some(report => report.id === activity.id), true);

    const firstVote = await store.voteReport(resource.id, alertHash, "confirm", now);
    assert.equal(firstVote.kind, "ok");
    const repeatVote = await store.voteReport(resource.id, alertHash, "deny", now);
    assert.equal(repeatVote.kind, "vote_limit");

    const expired = await store.createReport({
      ...coarseResource,
      submissionId: randomUUID(),
      deviceHash: "c".repeat(64),
      createdAt: new Date(now.getTime() - 3 * 60 * 60_000),
      visibleAt: new Date(now.getTime() - 2 * 60 * 60_000),
      expiresAt: new Date(now.getTime() - 60 * 60_000)
    });
    reportIds.push(expired.id);
    await store.purgeExpired(now);
    const purged = await inspector.query("SELECT 1 FROM reports WHERE id = $1", [expired.id]);
    assert.equal(purged.rowCount, 0);
  } finally {
    for (const id of reportIds) await store.deleteReport(id);
    await store.setAlertPreference(alertHash, false, null, null, null, now);
    await inspector.end();
    await store.close();
  }
});
