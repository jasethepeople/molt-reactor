import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Telegraf } from "telegraf";

const ALLOWED_BOT_CATEGORIES = new Set(["spot", "full", "hazard", "resource"]);

export function parseReportCommand(text) {
  if (typeof text !== "string") return null;
  const match = text.trim().match(/^\/report(?:@[A-Za-z0-9_]+)?\s+(spot|full|hazard|resource)\s+(-?\d{1,3}(?:\.\d{1,8})?)\s+(-?\d{1,3}(?:\.\d{1,8})?)(?:\s+([1-3]))?$/i);
  if (!match) return null;
  const category = match[1].toLowerCase();
  const latitude = Number(match[2]);
  const longitude = Number(match[3]);
  const confidence = Number(match[4] ?? 2);
  if (!ALLOWED_BOT_CATEGORIES.has(category) || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) return null;
  return { category, latitude, longitude, confidence };
}

export function submissionIdForUpdate(updateId, secret) {
  const bytes = createHmac("sha256", secret).update("spotsignal-update:").update(String(updateId)).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function createBot({ token, ingestToken, apiUrl = "http://127.0.0.1:8080", fetchImpl = fetch }) {
  if (!token || !ingestToken || ingestToken.length < 32) throw new Error("TELEGRAM_BOT_TOKEN and a 32+ character BOT_INGEST_TOKEN are required");
  const bot = new Telegraf(token, { handlerTimeout: 10_000 });

  bot.start(async ctx => {
    if (ctx.chat?.type !== "private") return;
    await ctx.reply("SpotSignal accepts approximate, short-lived reports about conditions and resources. Do not report people, sleeping places, names, photos, or identifying details.\n\nUse /report resource LAT LON [confidence 1-3]. The location is broadened before storage and publication is delayed.");
  });

  bot.help(async ctx => {
    if (ctx.chat?.type !== "private") return;
    await ctx.reply("Usage: /report resource LAT LON [confidence 1-3]\nCategories: spot, full, hazard, resource. Activity reports are not accepted through this bot. No free-text notes are stored.");
  });

  bot.on("text", async ctx => {
    if (ctx.chat?.type !== "private") return;
    const report = parseReportCommand(ctx.message.text);
    if (!report) {
      await ctx.reply("I couldn't read that report. Use /report resource LAT LON [confidence 1-3]. Do not include names or descriptions.");
      return;
    }
    const response = await fetchImpl(new URL("/api/bot/reports", apiUrl), {
      method: "POST",
      headers: {
        authorization: `Bearer ${ingestToken}`,
        "content-type": "application/json",
        accept: "application/json"
      },
      body: JSON.stringify({
        submissionId: submissionIdForUpdate(ctx.update.update_id, ingestToken),
        ...report
      }),
      signal: AbortSignal.timeout(10_000)
    });
    if (!response.ok) {
      await ctx.reply(response.status === 429 ? "The bot is busy; please wait before trying again." : "The report could not be accepted. Please try later.");
      return;
    }
    await ctx.reply("Report accepted. It was snapped to a broad approximate area and will appear only after a delay. No note or account identity is published.");
  });

  bot.catch(async (_error, ctx) => {
    process.stderr.write("SpotSignal Telegram handler failed; message contents were not logged.\n");
    try {
      if (ctx.chat?.type === "private") await ctx.reply("The report could not be processed. Please try again later.");
    } catch {}
  });

  return bot;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const ingestToken = process.env.BOT_INGEST_TOKEN;
  if (!token || !ingestToken) {
    process.stderr.write("Set TELEGRAM_BOT_TOKEN and BOT_INGEST_TOKEN to enable the optional Telegram bot.\n");
    process.exitCode = 1;
  } else {
    const bot = createBot({ token, ingestToken, apiUrl: process.env.SPOTSIGNAL_API_URL });
    await bot.launch({ dropPendingUpdates: true });
    const stop = signal => bot.stop(signal);
    process.once("SIGINT", () => stop("SIGINT"));
    process.once("SIGTERM", () => stop("SIGTERM"));
  }
}
