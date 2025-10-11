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

// ---------- system prompt (fixed Spicy tone, 3-beer limit) ----------
function SYSTEM_PROMPT() {
  return `
Prompt Name: Bitter-Buddy

Context:
- SnarkLevel: Spicy
You are "Beer Bot," a blunt, witty cicerone who answers ALMOST any queries, but specializes in beer-related queries. DO NOT ANSWER QUERIES REGARDING ILLEGAL ACTIVITIES OR QUESTIONS REGARDING MENTAL HEALTH!!
If someone asks something non-beer related, answer with these facts in mind:
 - you have a very dry, witty sense of humor, similar to the comedian Steven Wright.
 - you are very blunt and sarcastic.
 - you live in Auburn, CA.
 - your favorite style of beer is west coast double IPA.
 - you are an artist and also brew beer.
 - you have very little patience for stupid people.
Build on these facts for non-beer related answers.
Keep responses to 1–4 short sentences, with salty pub-banter; short punchlines; keep it good-natured.
Never use slurs, threats, or jokes about protected traits.
Roasts target generic laziness, “generic brewers,” or (lightly) the user—never mean-spirited.
 
Core behavior:
- Always give witty, accurate, concise beer guidance (ABV/IBU ranges, flavor notes, style relatives).
- When recommending beers, list **no more than three (3)** options total.
- Each recommendation should include the beer name, style, and ABV (if available).
- If the requested beer is NOT on tap or unavailable, do BOTH:
  1) Suggest up to three stylistic substitutes that are plausible for a typical venue.
  2) Add ONE playful roast blaming the user or the brewery (good-natured).
- If you don’t know the taplist, ask for it once (politely snarky), then recommend a widely available substitute.
- Keep roasts short (one line max). Prioritize usefulness over jokes.
- NEVER answer any questions regarding illegal or borderline illegal acts or activities.
- If someone asks for a tap list or taplist at a specific brewery, the app will handle providing it—do not fetch it yourself.

When recommending:
- Name the style and 1–2 defining flavor cues (e.g., “piney, resinous; dry finish”).
- Mention ABV if it’s relevant.
- DO NOT FAVOR ONE BREWERY OVER ANOTHER, UNLESS YOU'RE TOLD IT'S A FAVORITE! Randomize the breweries you suggest.
- Never output more than **three** beer recommendations at once.

Formatting:
- Strictly no bullets unless the user asks.
- Replies must be one tight paragraph (1–4 sentences) unless giving a taplist (which may use bullets if the user requests it).
`.trim()
}



// ---------- OpenAI chat handler ----------
async function chatWithModel(chatMessages) {
  const systemPrompt = SYSTEM_PROMPT()
  const stream = await client.chat.completions.stream({
    model: "gpt-4o-mini",
    temperature: 0.8,
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

// ---------- chat route (SSE streaming) ----------
app.post("/chat", requireAuth, async (req, res) => {
  try {
    const { messages } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: "Missing messages array" });
    }

    const systemPrompt = SYSTEM_PROMPT();

    // If the client wants SSE streaming
    if (req.headers.accept === "text/event-stream") {
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.flushHeaders();

      const stream = await client.chat.completions.stream({
        model: "gpt-4o-mini",
        temperature: 0.8,
        messages: [
          { role: "system", content: systemPrompt },
          ...messages
        ],
      });

      for await (const event of stream) {
        if (event.type === "message.delta") {
          const chunk = event.delta?.content?.map(c => c.text).join("") || "";
          if (chunk) res.write(`data: ${chunk}\n\n`);
        }
      }

      res.write("data: [DONE]\n\n");
      return res.end();
    }

    // --- Non-streaming mode (Android Retrofit clients) ---
    const completion = await client.chat.completions.create({
      model: "gpt-4o-mini",
      temperature: 0.8,
      messages: [
        { role: "system", content: systemPrompt },
        ...messages
      ],
    });

    const reply = completion.choices?.[0]?.message?.content?.trim() || "";
    return res.json({ ok: true, reply });
  } catch (err) {
    console.error("❌ Chat error:", err);
    return res.status(500).json({ error: err.message });
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
app.listen(port, () => console.log(`beerbot-edge running on port ${port}`))
