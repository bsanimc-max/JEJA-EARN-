import express from "express";
import crypto from "crypto";
import Database from "better-sqlite3";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const db = new Database("jeja-earn.db");
const PORT = Number(process.env.PORT || 3000);
const BOT_TOKEN = process.env.BOT_TOKEN || "";
const WEBAPP_URL = process.env.WEBAPP_URL || "";
const XP_PER_AD = Number(process.env.XP_PER_REWARDED_AD || 100);
const XP_PER_REFERRAL = Number(process.env.XP_PER_REFERRAL || 2500);
const DAILY_XP = Number(process.env.DAILY_CHECKIN_XP || 10);

app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id TEXT UNIQUE NOT NULL,
  username TEXT,
  first_name TEXT,
  photo_url TEXT,
  xp INTEGER NOT NULL DEFAULT 0,
  streak INTEGER NOT NULL DEFAULT 0,
  last_checkin TEXT,
  referred_by TEXT,
  referrals INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ad_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id TEXT NOT NULL,
  ad_type TEXT NOT NULL,
  xp INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id TEXT NOT NULL,
  type TEXT NOT NULL,
  amount INTEGER NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function validateInitData(initData) {
  if (!initData || !BOT_TOKEN) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;
  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const calculated = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(calculated), Buffer.from(hash))) {
    return null;
  }

  const authDate = Number(params.get("auth_date") || 0);
  if (!authDate || Math.floor(Date.now() / 1000) - authDate > 86400) {
    return null;
  }

  try {
    return JSON.parse(params.get("user"));
  } catch {
    return null;
  }
}

function getUser(telegramId) {
  return db.prepare("SELECT * FROM users WHERE telegram_id = ?").get(String(telegramId));
}

function ensureUser(tgUser, referralCode = null) {
  let user = getUser(tgUser.id);
  if (user) {
    db.prepare(`
      UPDATE users SET username=?, first_name=?, photo_url=?
      WHERE telegram_id=?
    `).run(
      tgUser.username || null,
      tgUser.first_name || "",
      tgUser.photo_url || null,
      String(tgUser.id)
    );
    return getUser(tgUser.id);
  }

  let referredBy = null;
  if (referralCode && String(referralCode) !== String(tgUser.id)) {
    const referrer = getUser(referralCode);
    if (referrer) referredBy = String(referralCode);
  }

  db.prepare(`
    INSERT INTO users (telegram_id, username, first_name, photo_url, referred_by)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    String(tgUser.id),
    tgUser.username || null,
    tgUser.first_name || "",
    tgUser.photo_url || null,
    referredBy
  );

  if (referredBy) {
    db.prepare(`
      UPDATE users SET referrals = referrals + 1, xp = xp + ?
      WHERE telegram_id = ?
    `).run(XP_PER_REFERRAL, referredBy);

    db.prepare(`
      INSERT INTO transactions (telegram_id, type, amount, note)
      VALUES (?, 'referral', ?, ?)
    `).run(referredBy, XP_PER_REFERRAL, `Referral: ${tgUser.id}`);
  }

  return getUser(tgUser.id);
}

function auth(req, res, next) {
  const tgUser = validateInitData(req.headers["x-telegram-init-data"]);
  if (!tgUser) return res.status(401).json({ error: "Invalid Telegram session" });
  req.tgUser = tgUser;
  next();
}

app.get("/api/config", (_req, res) => {
  res.json({
    xpPerAd: XP_PER_AD,
    xpPerReferral: XP_PER_REFERRAL,
    dailyXp: DAILY_XP,
    adsgramBlockId: process.env.ADSGRAM_BLOCK_ID || ""
  });
});

app.post("/api/register", auth, (req, res) => {
  const referral = req.body?.referral || null;
  const user = ensureUser(req.tgUser, referral);
  res.json({ ok: true, user });
});

app.get("/api/me", auth, (req, res) => {
  const user = getUser(req.tgUser.id);
  if (!user) return res.status(404).json({ error: "User not registered" });
  res.json({ user });
});

app.post("/api/checkin", auth, (req, res) => {
  const user = getUser(req.tgUser.id);
  if (!user) return res.status(404).json({ error: "Register first" });

  const today = new Date().toISOString().slice(0, 10);
  if (user.last_checkin === today) {
    return res.status(400).json({ error: "Already checked in today" });
  }

  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  const newStreak = user.last_checkin === yesterday ? user.streak + 1 : 1;

  db.prepare(`
    UPDATE users SET xp=xp+?, streak=?, last_checkin=? WHERE telegram_id=?
  `).run(DAILY_XP, newStreak, today, String(req.tgUser.id));

  db.prepare(`
    INSERT INTO transactions (telegram_id, type, amount, note)
    VALUES (?, 'checkin', ?, ?)
  `).run(String(req.tgUser.id), DAILY_XP, `Daily check-in day ${newStreak}`);

  res.json({ ok: true, xp: DAILY_XP, streak: newStreak });
});

app.post("/api/ad-complete", auth, (req, res) => {
  const user = getUser(req.tgUser.id);
  if (!user) return res.status(404).json({ error: "Register first" });

  // IMPORTANT:
  // Only call this endpoint after the client-side AdsGram rewarded
  // promise resolves successfully. For production, add server-side
  // anti-abuse/rate limits and provider-specific verification if available.
  const lastMinute = db.prepare(`
    SELECT COUNT(*) AS c FROM ad_views
    WHERE telegram_id=? AND created_at >= datetime('now','-1 minute')
  `).get(String(req.tgUser.id));

  if (lastMinute.c >= 5) {
    return res.status(429).json({ error: "Too many ad claims. Try again later." });
  }

  db.prepare(`
    UPDATE users SET xp=xp+? WHERE telegram_id=?
  `).run(XP_PER_AD, String(req.tgUser.id));

  db.prepare(`
    INSERT INTO ad_views (telegram_id, ad_type, xp)
    VALUES (?, 'rewarded', ?)
  `).run(String(req.tgUser.id), XP_PER_AD);

  db.prepare(`
    INSERT INTO transactions (telegram_id, type, amount, note)
    VALUES (?, 'ad', ?, 'AdsGram rewarded ad')
  `).run(String(req.tgUser.id), XP_PER_AD);

  res.json({ ok: true, xp: XP_PER_AD });
});

app.get("/api/leaderboard", (_req, res) => {
  const rows = db.prepare(`
    SELECT username, first_name, referrals
    FROM users
    ORDER BY referrals DESC, xp DESC
    LIMIT 20
  `).all();
  res.json({ rows });
});

app.post("/api/bot/webhook", async (req, res) => {
  try {
    const update = req.body;
    const message = update?.message;
    if (!message?.chat?.id) return res.json({ ok: true });

    const chatId = message.chat.id;
    const text = message.text || "";

    if (text.startsWith("/start")) {
      const param = text.split(" ")[1] || null;
      ensureUser(message.from, param);

      const reply = {
        chat_id: chatId,
        text:
          `🔥 JEJA EARN\\n\\n` +
          `Earn XP from daily check-ins, rewarded ads and referrals.\\n\\n` +
          `Tap the button below to start.`,
        reply_markup: {
          inline_keyboard: [[
            { text: "🚀 Open JEJA EARN", web_app: { url: WEBAPP_URL } }
          ]]
        }
      };

      await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(reply)
      });
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false });
  }
});

app.get("*", (_req, res) => {
  res.sendFile(process.cwd() + "/public/index.html");
});

app.listen(PORT, () => {
  console.log(`JEJA EARN running on http://localhost:${PORT}`);
});
