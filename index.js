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

// taplist loader (server fallback; client can override per request)
function loadTaplist() {
  try {
    const p = path.join(__dirname, 'data', 'taplist.json')
    const content = fs.readFileSync(p, 'utf-8')
    return JSON.parse(content)
  } catch (err) {
    console.warn('⚠️ Could not load taplist.json:', err.message)
    return []
  }
}

// ---------- express app ----------
const app = express()
app.use(cors({ origin: true, credentials: true }))
app.use(express.json())
app.use(cookieParser(process.env.AUTH_SECRET))

// basic logging & crash visibility
app.use((req, _res, next) => { console.log(`${req.method} ${req.url}`); next() })
process.on('unhandledRejection', (e) => console.error('unhandledRejection', e))
process.on('uncaughtException', (e) => console.error('uncaughtException', e))

// serve index.html at /
app.get('/', (_req, res) => { res.sendFile(path.join(__dirname, 'index.html')) })

// health
app.get('/health', (_req, res) => res.json({ ok: true }))

// ---------- openai client ----------
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

// ---------- sqlite ----------
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'beerbot.db')
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true })
const db = new Database(DB_PATH)
db.pragma('journal_mode = WAL')

// create tables if not exist
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

// add user_id to messages if old DB
try { db.exec(`ALTER TABLE messages ADD COLUMN user_id TEXT`); } catch {}

// ---------- helpers ----------
const rid = (n = 16) => crypto.randomBytes(n).toString('hex')
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-fallback"

// ---------- SQL prepared statements ----------
const insertUser = db.prepare(`
  INSERT INTO users (id, email, password_hash) VALUES (@id, @email, @password_hash)
`)
const getUserByEmail = db.prepare(`SELECT * FROM users WHERE email = ?`)
const getUserById    = db.prepare(`SELECT * FROM users WHERE id = ?`)

const upsertSession = db.prepare(`
INSERT INTO sessions (id, snark_level)
VALUES (@id, @snark_level)
ON CONFLICT(id) DO UPDATE SET
snark_level=excluded.snark_level
  `)
const getSession = db.prepare(`SELECT * FROM sessions WHERE id = ?`)

const insertMsgUser = db.prepare(`
  INSERT INTO messages (user_id, session_id, role, content) VALUES (?, ?, ?, ?)
`)
const getRecentUserMessages = db.prepare(`
  SELECT role, content FROM messages WHERE user_id = ? ORDER BY id DESC LIMIT ?
`)

// ---------- auth middleware ----------
function requireAuth(req, res, next) {
  // Check Authorization header first
  const authHeader = req.headers.authorization
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1]
    try {
      const decoded = jwt.verify(token, JWT_SECRET)
      req.user = { id: decoded.id, email: decoded.email }
      return next()
    } catch (err) {
      return res.status(401).json({ error: "invalid_token" })
    }
  }

  // Fallback to cookie
  const uid = req.signedCookies?.uid
  if (!uid) return res.status(401).json({ error: 'unauthenticated' })
  const user = getUserById.get(uid)
  if (!user) return res.status(401).json({ error: 'invalid_user' })
  req.user = user
  next()
}

// ---------- auth routes ----------
app.post('/auth/register', (req, res) => {
  try {
    const { email, password } = req.body ?? {}
    if (!email || !password) return res.status(400).json({ error: 'email_password_required' })

    const exists = getUserByEmail.get(String(email).toLowerCase())
    if (exists) return res.status(409).json({ error: 'email_in_use' })

    const id = rid()
    const password_hash = bcrypt.hashSync(String(password), 12)
    insertUser.run({ id, email: String(email).toLowerCase(), password_hash })

    res.cookie('uid', id, {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      signed: !!process.env.AUTH_SECRET,
      maxAge: 1000 * 60 * 60 * 24 * 30
    })

    const token = jwt.sign({ id, email: String(email).toLowerCase() }, JWT_SECRET, { expiresIn: "7d" })

    res.json({ ok: true, user: { id, email: String(email).toLowerCase() }, token })
  } catch (err) {
    console.error('register error:', err)
    res.status(500).json({ error: 'register_failed', detail: String(err.message || err) })
  }
})

app.post('/auth/login', (req, res) => {
  try {
    const { email, password } = req.body ?? {}
    const user = getUserByEmail.get(String(email).toLowerCase())
    if (!user) return res.status(401).json({ error: 'invalid_credentials' })
    const ok = bcrypt.compareSync(String(password), user.password_hash)
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' })

    res.cookie('uid', user.id, {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      signed: !!process.env.AUTH_SECRET,
      maxAge: 1000 * 60 * 60 * 24 * 30
    })

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" })

    res.json({ ok: true, user: { id: user.id, email: user.email }, token })
  } catch (err) {
    console.error('login error:', err)
    res.status(500).json({ error: 'login_failed', detail: String(err.message || err) })
  }
})

app.post('/auth/logout', (req, res) => {
  res.clearCookie('uid')
  res.json({ ok: true })
})

app.get('/me', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email } })
})

// ---------- system prompt (fixed Spicy tone) ----------
function SYSTEM_PROMPT(taplist = []) {
  const tap = Array.isArray(taplist) ? taplist : []
  const TaplistJSON = JSON.stringify(tap, null, 2)

return `
Prompt Name: Bitter-Buddy

Context:
- SnarkLevel: Spicy            // fixed: snarky pub-banter
- Taplist: ${TaplistJSON}

You are "Beer Bot," a blunt, witty cicerone who answers ALMOST any queries, but specializes in beer-related queries. DO NOT ANSWER QUERIES REGARDING ILLEGAL ACTIVITIES OR QUESTIONS REGARDING MENTAL HEALTH!!
If someone asks something non-beer related, answer with these facts in mind:
 - you have a very dry, witty sense of humor, similar to the comedian Steven Wright.
 - you are very blunt and sarcastic.
 - you live in Auburn, CA.
 - your favorite style of beer is west coast double IPA.
 - you are an artist and also brew beer.
 - you have very littel patience for stupid people.
Build on these facts for non-beer related answers.
Keep responses to 1–4 short sentences, with salty pub-banter; short punchlines; keep it good-natured.
Never use slurs, threats, or jokes about protected traits.
Roasts target generic laziness, “generic brewers,” or (lightly) the user—never mean-spirited.
 

Core behavior :
- Always give witty, accurate, concise beer guidance (ABV/IBU ranges, flavor notes, style relatives).
- If the requested beer is NOT on tap or unavailable, do BOTH:
  1) Suggest the closest stylistic substitute that is plausible for a typical venue.
  2) Add ONE playful roast blaming the user or the brewery (good-natured).
- If you don’t know the taplist, ask for it once (politely snarky), then recommend a widely available substitute.
- Keep roasts short (one line max). Prioritize usefulness over jokes.
- NEVER answer any questions regarding illegal or border-line illegal acts or activities.
- If someone asks for a tap list or taplist at a specific brewery, give them the entire taplist, for that brewery ONLY, in bullet format.

When recommending:
- Name the style and 1–2 defining flavor cues (e.g., “piney, resinous; dry finish”).
- Mention ABV if it’s relevant.
- DO NOT FAVOR ONE BREWERY OVER ANOTHER, UNLESS YOU'RE TOLD IT'S A FAVORITE! Randomize the breweries you suggest.

Formatting:
- Strictly no bullets unless the user asks.
- Replies must be one tight paragraph (1–4 sentences).
`.trim()
}

// ---------- chat route ----------
async function chatWithModel(input) {
  const taplist = loadTaplist();
  const systemPrompt = SYSTEM_PROMPT(taplist);

  // Handle both string and message-array input
  let chatMessages = [];

  if (Array.isArray(input)) {
    // Already an array of {role, content}
    chatMessages = input;
  } else if (typeof input === "string") {
    // Legacy: single user message
    chatMessages = [{ role: "user", content: input }];
  } else {
    throw new Error("Invalid input type to chatWithModel");
  }

  console.log("🧠 chatWithModel input:", JSON.stringify(chatMessages, null, 2));

  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: systemPrompt },
      ...chatMessages
    ],
  });

  const reply = completion.choices?.[0]?.message?.content?.trim() || "";
  return reply;
}

const MAX_TURNS = 50; // last 50 user+assistant turns

app.post("/chat", requireAuth, async (req, res) => {
  try {
    const { message, messages } = req.body;

    // Support both old and new payload formats
    let finalPrompt = "";
    if (Array.isArray(messages) && messages.length > 0) {
      // 🧠 Combine messages into one conversation prompt
      finalPrompt = messages.map(m => `${m.role}: ${m.content}`).join("\n");
    } else if (typeof message === "string") {
      finalPrompt = message;
    } else {
      return res.status(400).json({ error: "Missing message or messages array" });
    }

    // Save only the last user message for history (optional)
    const lastUserMsg = Array.isArray(messages)
      ? messages.findLast(m => m.role === "user")
      : { content: message };

    if (lastUserMsg?.content) {
      insertMsgUser.run(req.user.id, req.user.id, "user", String(lastUserMsg.content));
    }

    // Call your model
    const reply = await chatWithModel(finalPrompt);

    // Save assistant reply
    insertMsgUser.run(req.user.id, req.user.id, "assistant", reply);

    res.json({ ok: true, reply });
  } catch (err) {
    console.error("❌ Chat error:", err);
    res.status(500).json({ error: err.message });
  }
})

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
app.listen(port, () => console.log(`beerbot-edge listening on http://localhost:${port}`))
