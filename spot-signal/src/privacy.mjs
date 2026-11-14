import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const DAY_MS = 86_400_000;

export function clientKey(address, secret) {
  return createHmac("sha256", secret).update("client:").update(String(address)).digest("hex");
}

export function deviceHash(token, secret, now = Date.now()) {
  const day = new Date(now).toISOString().slice(0, 10);
  return createHmac("sha256", secret).update("device:").update(day).update(":").update(token).digest("hex");
}

export function parseCookies(header = "") {
  const result = new Map();
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    if (name) result.set(name, part.slice(index + 1).trim());
  }
  return result;
}

export function safeBearer(header, expected) {
  if (typeof header !== "string" || typeof expected !== "string" || expected.length < 32) return false;
  const supplied = Buffer.from(header);
  const target = Buffer.from(`Bearer ${expected}`);
  return supplied.length === target.length && timingSafeEqual(supplied, target);
}

export function createChallengeStore({ ttlMs, difficultyBits, now = Date.now, maxEntries = 5000 }) {
  const entries = new Map();
  return {
    issue(client) {
      const current = now();
      purgeExpired(entries, current);
      if (entries.size >= maxEntries) return null;
      const challenge = randomBytes(32).toString("hex");
      const expiresAt = current + ttlMs;
      entries.set(challenge, { client, difficultyBits, expiresAt });
      return { challenge, difficultyBits, expiresAt };
    },
    consume(challenge, nonce, client) {
      if (typeof challenge !== "string") return false;
      const entry = entries.get(challenge);
      entries.delete(challenge);
      if (!entry || entry.expiresAt <= now() || entry.client !== client) return false;
      return verifyProofOfWork(challenge, nonce, entry.difficultyBits);
    },
    get size() {
      return entries.size;
    }
  };
}

export function verifyProofOfWork(challenge, nonce, difficultyBits) {
  if (typeof challenge !== "string" || typeof nonce !== "string" || !/^\d{1,128}$/.test(nonce)) return false;
  if (!Number.isInteger(difficultyBits) || difficultyBits < 0 || difficultyBits > 32) return false;
  const digest = createHash("sha256").update(challenge).update(":").update(nonce).digest();
  const fullBytes = Math.floor(difficultyBits / 8);
  for (let index = 0; index < fullBytes; index += 1) if (digest[index] !== 0) return false;
  const remaining = difficultyBits % 8;
  return remaining === 0 || (digest[fullBytes] >>> (8 - remaining)) === 0;
}

export function createWindowLimiter({ now = Date.now, maxEntries = 50_000 } = {}) {
  const windows = new Map();
  let lastPurge = 0;
  return {
    take(key, limit, windowMs) {
      const current = now();
      if (current - lastPurge >= 60_000) {
        purgeExpired(windows, current);
        lastPurge = current;
      }
      const start = Math.floor(current / windowMs) * windowMs;
      const bucket = `${key}:${windowMs}:${start}`;
      const entry = windows.get(bucket) ?? { count: 0, expiresAt: start + windowMs };
      entry.count += 1;
      windows.set(bucket, entry);
      if (windows.size > maxEntries) purgeOldest(windows, windows.size - maxEntries);
      return entry.count <= limit;
    },
    get size() {
      return windows.size;
    }
  };
}

export function fuzzCoordinates(latitude, longitude, category, config) {
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90) throw new Error("invalid latitude");
  if (!Number.isFinite(longitude) || longitude < -180 || longitude > 180) throw new Error("invalid longitude");
  const sensitive = ["spot", "full", "activity"].includes(category);
  const multiplier = sensitive ? config.sensitiveCellMultiplier : config.resourceCellMultiplier;
  const cell = config.coordFuzzDegrees * multiplier;
  return {
    latitude: cellCenter(latitude, cell, -90, 90),
    longitude: cellCenter(longitude, cell, -180, 180)
  };
}

export function cellCenter(value, cell, minimum, maximum) {
  if (!Number.isFinite(value) || !Number.isFinite(cell) || cell <= 0) throw new Error("invalid coordinate cell");
  const center = (Math.floor(value / cell) + 0.5) * cell;
  return Number(Math.min(maximum - cell / 2, Math.max(minimum + cell / 2, center)).toFixed(6));
}

export function haversineMeters(left, right) {
  const radians = value => value * Math.PI / 180;
  const dLat = radians(right.latitude - left.latitude);
  const dLon = radians(right.longitude - left.longitude);
  const lat1 = radians(left.latitude);
  const lat2 = radians(right.latitude);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 6_371_000 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function purgeExpired(entries, current) {
  for (const [key, value] of entries) if (value.expiresAt <= current) entries.delete(key);
}

function purgeOldest(entries, count) {
  for (const key of entries.keys()) {
    entries.delete(key);
    if (--count <= 0) break;
  }
}

export const DEVICE_TOKEN_TTL_MS = DAY_MS;
