import assert from "node:assert/strict";
import test from "node:test";
import { parseReportCommand, submissionIdForUpdate } from "../src/bot.mjs";

test("Telegram command accepts only the fixed non-activity report schema", () => {
  assert.deepEqual(parseReportCommand("/report resource 47.6217 -122.3474 3"), {
    category: "resource",
    latitude: 47.6217,
    longitude: -122.3474,
    confidence: 3
  });
  assert.equal(parseReportCommand("/report activity 47.6 -122.3"), null);
  assert.equal(parseReportCommand("/report resource 47.6 -122.3 Someone sleeps here"), null);
  assert.equal(parseReportCommand("/report resource 91 -122.3"), null);
  assert.equal(parseReportCommand("/report resource 47.6 -181"), null);
});

test("Telegram update submission IDs are deterministic UUIDs without sender IDs", () => {
  const secret = "test-ingest-secret";
  const first = submissionIdForUpdate(918273, secret);
  assert.equal(first, submissionIdForUpdate(918273, secret));
  assert.match(first, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(first, submissionIdForUpdate(918274, secret));
});
