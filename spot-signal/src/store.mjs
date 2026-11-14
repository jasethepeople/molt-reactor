import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { fuzzCoordinates, haversineMeters } from "./privacy.mjs";

const migrationPath = fileURLToPath(new URL("../migrations/001_init.sql", import.meta.url));

export function createStore(config) {
  return config.storeKind === "postgres" ? PostgresStore.connect(config) : Promise.resolve(new MemoryStore(config));
}

export class MemoryStore {
  #config;
  #reports = new Map();
  #submissions = new Map();
  #votes = new Map();
  #alerts = new Map();

  constructor(config) {
    this.#config = config;
  }

  async health() {
    return { ok: true, backend: "memory" };
  }

  async countRecentReports(deviceHash, since) {
    const cutoff = time(since);
    return [...this.#reports.values()].filter(report => report.deviceHash === deviceHash && time(report.createdAt) >= cutoff && report.status === "active").length;
  }

  async hasSubmission(deviceHash, submissionId) {
    return this.#submissions.has(`${deviceHash}:${submissionId}`);
  }

  async createReport(report) {
    const coarse = fuzzCoordinates(report.latitude, report.longitude, report.category, this.#config);
    const submissionKey = `${report.deviceHash}:${report.submissionId}`;
    const existingId = this.#submissions.get(submissionKey);
    if (existingId) return publicRecord(this.#reports.get(existingId));
    const created = {
      ...report,
      ...coarse,
      id: randomUUID(),
      confirmCount: 0,
      denyCount: 0,
      status: "active"
    };
    this.#reports.set(created.id, created);
    this.#submissions.set(submissionKey, created.id);
    return publicRecord(created);
  }

  async listReports(options) {
    const timestamp = time(options.now);
    const preference = options.deviceHash ? this.#alerts.get(options.deviceHash) : null;
    return [...this.#reports.values()]
      .filter(report => report.status === "active" && time(report.visibleAt) <= timestamp && time(report.expiresAt) > timestamp)
      .filter(report => !options.since || time(report.createdAt) >= time(options.since))
      .filter(report => !options.id || report.id === options.id)
      .filter(report => !options.bbox || inBounds(report.latitude, report.longitude, options.bbox))
      .filter(report => report.category !== "activity" || this.#canSeeActivity(options, preference, report, timestamp))
      .sort((a, b) => time(b.createdAt) - time(a.createdAt))
      .slice(0, options.limit)
      .map(publicRecord);
  }

  async listModerationReports({ now, limit }) {
    const timestamp = time(now);
    return [...this.#reports.values()]
      .filter(report => report.status === "active" && time(report.expiresAt) > timestamp)
      .sort((a, b) => time(b.createdAt) - time(a.createdAt))
      .slice(0, limit)
      .map(publicRecord);
  }

  async getReport(id, options) {
    return (await this.listReports({ ...options, id, limit: 1 })).find(report => report.id === id) ?? null;
  }

  async deleteReport(id) {
    const report = this.#reports.get(id);
    if (!report) return false;
    this.#reports.delete(id);
    this.#submissions.delete(`${report.deviceHash}:${report.submissionId}`);
    this.#votes.delete(id);
    return true;
  }

  async voteReport(id, deviceHash, vote, now) {
    const report = this.#reports.get(id);
    const timestamp = time(now);
    if (!report || report.status !== "active" || time(report.expiresAt) <= timestamp || time(report.visibleAt) > timestamp) return { kind: "not_found" };
    let votes = this.#votes.get(id);
    if (!votes) {
      votes = new Map();
      this.#votes.set(id, votes);
    }
    if (votes.has(deviceHash)) return { kind: "vote_limit" };
    votes.set(deviceHash, vote);
    if (vote === "confirm") report.confirmCount += 1;
    else report.denyCount += 1;
    return { kind: "ok", report: publicRecord(report) };
  }

  async setAlertPreference(deviceHash, enabled, location, radiusMeters, expiresAt, now) {
    if (!enabled) {
      this.#alerts.delete(deviceHash);
      return { enabled: false };
    }
    const coarse = fuzzCoordinates(location.latitude, location.longitude, "activity", this.#config);
    const preference = {
      ...coarse,
      radiusMeters,
      expiresAt: time(expiresAt),
      createdAt: time(now)
    };
    this.#alerts.set(deviceHash, preference);
    return { enabled: true, expiresAt: new Date(preference.expiresAt), radiusMeters };
  }

  async hasAlertPreference(deviceHash, now = Date.now()) {
    const preference = this.#alerts.get(deviceHash);
    return Boolean(preference && preference.expiresAt > time(now));
  }

  async purgeExpired(now = Date.now()) {
    const timestamp = time(now);
    for (const [id, report] of this.#reports) {
      if (time(report.expiresAt) <= timestamp) await this.deleteReport(id);
    }
    for (const [key, preference] of this.#alerts) if (preference.expiresAt <= timestamp) this.#alerts.delete(key);
  }

  async close() {}

  #canSeeActivity(options, preference, report, timestamp) {
    if (!this.#config.activityAlertsEnabled || !options.deviceHash || !preference || preference.expiresAt <= timestamp) return false;
    return haversineMeters(preference, report) <= preference.radiusMeters;
  }
}

export class PostgresStore {
  #config;
  #pool;

  constructor(config, pool) {
    this.#config = config;
    this.#pool = pool;
  }

  static async connect(config) {
    const pool = new Pool({
      connectionString: config.databaseUrl,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000
    });
    const store = new PostgresStore(config, pool);
    try {
      await store.migrate();
      await store.health();
      return store;
    } catch (error) {
      await pool.end();
      throw error;
    }
  }

  async migrate() {
    const sql = await readFile(migrationPath, "utf8");
    await this.#pool.query(sql);
  }

  async health() {
    await this.#pool.query("SELECT 1");
    return { ok: true, backend: "postgres" };
  }

  async countRecentReports(deviceHash, since) {
    const result = await this.#pool.query(
      "SELECT count(*)::int AS count FROM reports WHERE device_hash = $1 AND created_at >= $2 AND status = 'active'",
      [deviceHash, since]
    );
    return result.rows[0].count;
  }

  async hasSubmission(deviceHash, submissionId) {
    const result = await this.#pool.query(
      "SELECT 1 FROM reports WHERE device_hash = $1 AND submission_id = $2",
      [deviceHash, submissionId]
    );
    return result.rowCount > 0;
  }

  async createReport(report) {
    const coarse = fuzzCoordinates(report.latitude, report.longitude, report.category, this.#config);
    const result = await this.#pool.query(
      `INSERT INTO reports (submission_id, category, location, confidence, device_hash, activity_opt_in, created_at, visible_at, expires_at)
       VALUES ($1, $2, ST_SetSRID(ST_MakePoint($3, $4), 4326), $5, $6, $7, $8, $9, $10)
       ON CONFLICT (device_hash, submission_id) DO NOTHING
       RETURNING id, category, ST_Y(location) AS latitude, ST_X(location) AS longitude,
                 confidence, confirm_count, deny_count, created_at, visible_at, expires_at, status`,
      [report.submissionId, report.category, coarse.longitude, coarse.latitude, report.confidence,
       report.deviceHash, report.activityOptIn, report.createdAt, report.visibleAt, report.expiresAt]
    );
    if (result.rows[0]) return publicRecord(result.rows[0]);
    const existing = await this.#pool.query(
      `SELECT id, category, ST_Y(location) AS latitude, ST_X(location) AS longitude,
              confidence, confirm_count, deny_count, created_at, visible_at, expires_at, status
       FROM reports WHERE device_hash = $1 AND submission_id = $2`,
      [report.deviceHash, report.submissionId]
    );
    if (!existing.rows[0]) throw new Error("idempotent report insert returned no row");
    return publicRecord(existing.rows[0]);
  }

  async listReports(options) {
    const values = [options.now, options.since ?? new Date(0), options.limit, options.deviceHash ?? null, this.#config.activityAlertsEnabled];
    const where = [
      "r.status = 'active'",
      "r.visible_at <= $1",
      "r.expires_at > $1",
      "r.created_at >= $2",
      `(
        r.category <> 'activity' OR (
          $5 = true AND EXISTS (
            SELECT 1 FROM alert_preferences ap
            WHERE ap.device_hash = $4 AND ap.enabled = true AND ap.expires_at > $1
              AND ST_DWithin(r.location::geography, ap.location::geography, ap.radius_m)
          )
        )
      )`
    ];
    if (options.id) {
      values.push(options.id);
      where.push(`r.id = $${values.length}`);
    }
    if (options.bbox) {
      values.push(options.bbox.west, options.bbox.south, options.bbox.east, options.bbox.north);
      const first = values.length - 3;
      where.push(`r.location && ST_MakeEnvelope($${first}, $${first + 1}, $${first + 2}, $${first + 3}, 4326)`);
    }
    const result = await this.#pool.query(
      `SELECT r.id, r.category, ST_Y(r.location) AS latitude, ST_X(r.location) AS longitude,
              r.confidence, r.confirm_count, r.deny_count, r.created_at, r.visible_at, r.expires_at, r.status
       FROM reports r WHERE ${where.join(" AND ")} ORDER BY r.created_at DESC LIMIT $3`,
      values
    );
    return result.rows.map(publicRecord);
  }

  async listModerationReports({ now, limit }) {
    const result = await this.#pool.query(
      `SELECT id, category, ST_Y(location) AS latitude, ST_X(location) AS longitude,
              confidence, confirm_count, deny_count, created_at, visible_at, expires_at, status
       FROM reports WHERE status = 'active' AND expires_at > $1
       ORDER BY created_at DESC LIMIT $2`,
      [now, limit]
    );
    return result.rows.map(publicRecord);
  }

  async getReport(id, options) {
    const rows = await this.listReports({ ...options, id, limit: 1 });
    return rows[0] ?? null;
  }

  async deleteReport(id) {
    const result = await this.#pool.query("DELETE FROM reports WHERE id = $1 RETURNING id", [id]);
    return result.rowCount > 0;
  }

  async voteReport(id, deviceHash, vote, now) {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      const report = await client.query(
        "SELECT id FROM reports WHERE id = $1 AND status = 'active' AND visible_at <= $2 AND expires_at > $2 FOR UPDATE",
        [id, now]
      );
      if (!report.rowCount) {
        await client.query("ROLLBACK");
        return { kind: "not_found" };
      }
      const inserted = await client.query(
        "INSERT INTO votes (report_id, device_hash, vote, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (report_id, device_hash) DO NOTHING RETURNING id",
        [id, deviceHash, vote, now]
      );
      if (!inserted.rowCount) {
        await client.query("ROLLBACK");
        return { kind: "vote_limit" };
      }
      const counter = vote === "confirm" ? "confirm_count" : "deny_count";
      await client.query(`UPDATE reports SET ${counter} = ${counter} + 1 WHERE id = $1`, [id]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    const updated = await this.getReport(id, { now, limit: 1, deviceHash, since: null });
    return { kind: "ok", report: updated };
  }

  async setAlertPreference(deviceHash, enabled, location, radiusMeters, expiresAt, now) {
    if (!enabled) {
      await this.#pool.query("DELETE FROM alert_preferences WHERE device_hash = $1", [deviceHash]);
      return { enabled: false };
    }
    const coarse = fuzzCoordinates(location.latitude, location.longitude, "activity", this.#config);
    await this.#pool.query(
      `INSERT INTO alert_preferences (device_hash, location, radius_m, enabled, created_at, expires_at)
       VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326), $4, true, $5, $6)
       ON CONFLICT (device_hash) DO UPDATE SET location = EXCLUDED.location, radius_m = EXCLUDED.radius_m,
         enabled = true, created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at`,
      [deviceHash, coarse.longitude, coarse.latitude, radiusMeters, now, expiresAt]
    );
    return { enabled: true, expiresAt, radiusMeters };
  }

  async hasAlertPreference(deviceHash, now = new Date()) {
    const result = await this.#pool.query(
      "SELECT 1 FROM alert_preferences WHERE device_hash = $1 AND enabled = true AND expires_at > $2",
      [deviceHash, now]
    );
    return result.rowCount > 0;
  }

  async purgeExpired(now = new Date()) {
    await this.#pool.query("DELETE FROM reports WHERE expires_at <= $1", [now]);
    await this.#pool.query("DELETE FROM alert_preferences WHERE expires_at <= $1", [now]);
  }

  async close() {
    await this.#pool.end();
  }
}

function publicRecord(report) {
  return {
    id: report.id,
    category: report.category,
    latitude: Number(report.latitude),
    longitude: Number(report.longitude),
    confidence: confidenceFrom(report.confirmCount ?? report.confirm_count, report.denyCount ?? report.deny_count, report.confidence),
    confirmCount: Number(report.confirmCount ?? report.confirm_count ?? 0),
    denyCount: Number(report.denyCount ?? report.deny_count ?? 0),
    createdAt: new Date(report.createdAt ?? report.created_at),
    visibleAt: new Date(report.visibleAt ?? report.visible_at),
    expiresAt: new Date(report.expiresAt ?? report.expires_at),
    status: report.status
  };
}

function confidenceFrom(confirmCount, denyCount, baseline = 1) {
  return Math.max(1, Math.min(3, Number(baseline) + Number(confirmCount ?? 0) - Number(denyCount ?? 0)));
}

function inBounds(latitude, longitude, bbox) {
  return longitude >= bbox.west && longitude <= bbox.east && latitude >= bbox.south && latitude <= bbox.north;
}

function time(value) {
  return value instanceof Date ? value.getTime() : Number(value);
}
