// @ts-nocheck
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import OpenAI from 'openai'
import Database from 'better-sqlite3'
import path from 'path'
import { fileURLToPath } from 'url'
import fs from 'fs'
import crypto from 'crypto'
import bcrypt from 'bcryptjs'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'

// ---------- setup paths ----------
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// ---------- express app ----------
const app = express()
app.use(cors({ origin: true, credentials: true }))
app.use(express.json())
app.use(cookieParser(process.env.AUTH_SECRET))

app.use((req, _res, next) => { console.log(`${req.method} ${req.url}`); next() })
process.on('unhandledRejection', (e) => console.error('unhandledRejection', e))
process.on('uncaughtException', (e) => console.error('uncaughtException', e))

// ---------- openai client ----------
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

// ---------- sqlite ----------
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'beerbot.db')
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true })
const db = new Database(DB_PATH)
db.pragma('journal_mode = WAL')

// ---------- helpers ----------
const rid = (n = 16) => crypto.randomBytes(n).toString('hex')
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-fallback"

// ---------- table creation ----------
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  snark_level TEXT DEFAULT 'Spicy',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  session_id TEXT,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`)

try { db.exec(`ALTER TABLE messages ADD COLUMN user_id TEXT`); } catch {}

// ---------- auth helpers ----------
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1]
    try {
      const decoded = jwt.verify(token, JWT_SECRET)
      req.user = { id: decoded.id, email: decoded.email }
      return next()
    } catch {
      return res.status(401).json({ error: "invalid_token" })
    }
  }

  const uid = req.signedCookies?.uid
  if (!uid) return res.status(401).json({ error: 'unauthenticated' })
  const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(uid)
  if (!user) return res.status(401).json({ error: 'invalid_user' })
  req.user = user
  next()
}
// ---------- AUTH ROUTES ----------
app.post("/auth/register", (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password)
      return res.status(400).json({ error: "email_password_required" });

    const exists = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(email.toLowerCase());
    if (exists) return res.status(409).json({ error: "email_in_use" });

    const id = rid();
    const password_hash = bcrypt.hashSync(password, 12);
    db.prepare(
      "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)"
    ).run(id, email.toLowerCase(), password_hash);

    const token = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ ok: true, user: { id, email }, token });
  } catch (err) {
    console.error("register error:", err);
    res.status(500).json({ error: "register_failed" });
  }
});

app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    const user = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(email.toLowerCase());
    if (!user) return res.status(401).json({ error: "invalid_credentials" });

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "invalid_credentials" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });
    res.json({ ok: true, user: { id: user.id, email: user.email }, token });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: "login_failed" });
  }
});

app.post("/auth/logout", (_req, res) => {
  res.json({ ok: true });
});


// ---------- system prompt (fixed Spicy tone, 3-beer limit) ----------
function SYSTEM_PROMPT() {
  return `
Prompt Name: Bitter-Buddy

You are "Beer Bot" — a blunt, witty cicerone with a dry Steven Wright-style humor. 
You live in Auburn, CA, love West Coast Double IPAs, and have little patience for stupidity. 
You’re sarcastic but good-natured. Never use slurs, threats, or jokes about protected traits.

Behavior:
- Focus on beer advice: ABV/IBU ranges, flavor notes, and style comparisons.
- Limit recommendations to 3 beers max (name, style, ABV).
- If a beer isn’t on tap, offer up to 3 close substitutes + one playful roast.
- If unsure of taplist, ask once; otherwise, suggest common beers.
- When user asks about a brewery or nearby spots, the app provides the taplist — use it, don’t fetch.
- Stay witty but concise (1–4 short sentences). Be salty, not mean.
- Ignore questions about illegal or mental health topics.

Formatting:
- No bullets unless asked.
- One tight paragraph unless showing a taplist (then bullets are okay).
`.trim();
}




// ---------- OpenAI chat handler ----------
async function chatWithModel(chatMessages) {
  const systemPrompt = SYSTEM_PROMPT()
  const stream = await client.chat.completions.stream({
    model: "gpt-5-mini",
    messages: [
      { role: "system", content: systemPrompt },
      ...chatMessages
    ]
  })

  let reply = ""
  for await (const event of stream) {
    if (event.type === "message.delta") {
      reply += event.delta?.content?.map(c => c.text).join("") || ""
    } else if (event.type === "error") {
      console.error("❌ Stream error:", event.error)
    }
  }
  return reply.trim()
}
// ---------- AUTH ROUTES ----------
app.post("/auth/register", (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) {
      return res.status(400).json({ error: "email_password_required" });
    }

    const exists = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(email.toLowerCase());
    if (exists) return res.status(409).json({ error: "email_in_use" });

    const id = rid();
    const password_hash = bcrypt.hashSync(password, 12);
    db.prepare(
      "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)"
    ).run(id, email.toLowerCase(), password_hash);

    const token = jwt.sign({ id, email: email.toLowerCase() }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ ok: true, user: { id, email: email.toLowerCase() }, token });
  } catch (err) {
    console.error("❌ register error:", err);
    res.status(500).json({ error: "register_failed" });
  }
});

app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) {
      return res.status(400).json({ error: "email_password_required" });
    }

    const user = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(email.toLowerCase());
    if (!user) return res.status(401).json({ error: "invalid_credentials" });

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "invalid_credentials" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ ok: true, user: { id: user.id, email: user.email }, token });
  } catch (err) {
    console.error("❌ login error:", err);
    res.status(500).json({ error: "login_failed" });
  }
});

app.post("/auth/logout", (_req, res) => {
  res.json({ ok: true });
});


// ---------- chat route (SSE streaming) ----------
app.post("/chat", requireAuth, async (req, res) => {
  try {
    // 1) Validate input
    const { messages } = req.body;
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: "Missing messages array" });
    }

    // 2) Extract any system hint sent by the app and merge with server system prompt
    const dynamicSystemHint =
      messages.find(m => m?.role === "system" && typeof m.content === "string")?.content || "";

    const combinedSystemPrompt = [
      SYSTEM_PROMPT(),
      dynamicSystemHint.trim()
    ].filter(Boolean).join("\n\n");

    // 3) Remove system messages from the user-provided list (we already merged them)
    const userMessages = messages.filter(m => m?.role !== "system");

    // 4) If the client wants SSE streaming
    if ((req.headers.accept || "").includes("text/event-stream")) {
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.flushHeaders?.();

      const stream = await client.chat.completions.stream({
        model: "gpt-4o-mini",
        temperature: 0.8,
        messages: [
          { role: "system", content: combinedSystemPrompt },
          ...userMessages
        ],
      });

      // Accumulate and stream out chunks
      for await (const event of stream) {
        if (event.type === "message.delta") {
          const chunk = (event.delta?.content?.map(c => c.text).join("") || "");
          if (chunk) res.write(`data: ${chunk}\n\n`);
        } else if (event.type === "error") {
          console.error("❌ Stream error:", event.error);
          res.write(`data: [ERROR] ${String(event.error || "unknown")}\n\n`);
        }
      }

      res.write("data: [DONE]\n\n");
      return res.end();
    }

    // 5) Non-streaming mode (e.g., Android Retrofit)
    const completion = await client.chat.completions.create({
      model: "gpt-4o-mini",
      temperature: 0.8,
      messages: [
        { role: "system", content: combinedSystemPrompt },
        ...userMessages
      ],
    });

    const reply = completion.choices?.[0]?.message?.content?.trim() || "";
    return res.json({ ok: true, reply });

  } catch (err) {
    console.error("❌ Chat error:", err);
    return res.status(500).json({ error: err?.message || "chat_failed" });
  }
});


// ---------- history & reset ----------
app.get('/history', requireAuth, (req, res) => {
  const rows = db.prepare(
    `SELECT role, content, created_at FROM messages WHERE user_id = ? ORDER BY id ASC`
  ).all(req.user.id)
  res.json({ userId: req.user.id, messages: rows })
})

app.post('/reset', requireAuth, (req, res) => {
  db.prepare(`DELETE FROM messages WHERE user_id = ?`).run(req.user.id)
  res.json({ ok: true })
})

// ---------- start server ----------
const port = process.env.PORT || 8787
// Serve a basic root route (for Render sanity check)
app.get("/", (_req, res) => {
  res.json({ ok: true, message: "Bitter Buddy backend is running 🍺" });
});
app.listen(port, () => console.log(`beerbot-edge running on port ${port}`))
