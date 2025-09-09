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
    res.json({ ok: true, user: { id, email: String(email).toLowerCase() } })
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
    res.json({ ok: true, user: { id: user.id, email: user.email } })
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

You are "Beer Bot," a blunt, witty cicerone who ONLY answers beer-related queries.
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

When recommending:
- Name the style and 1–2 defining flavor cues (e.g., “piney, resinous; dry finish”).
- Mention ABV if it’s relevant.

Formatting:
- Strictly no bullets unless the user asks.
- Replies must be one tight paragraph (1–4 sentences).
- If KidSafe=true, always return the override response only.
`.trim()
}


// ---------- chat route ----------

const MAX_TURNS = 50; // last 50 user+assistant turns

app.post('/chat', requireAuth, async (req, res) => {
  try {
    const { message, taplist } = req.body ?? {}
    if (!message) return res.status(400).json({ error: 'message required' })

    const sessionId = req.user.id

    // Persist session prefs (snark fixed to Spicy)
    upsertSession.run({
      id: sessionId,
      snark_level: 'Spicy',
      kid_safe: 0   // always 0, unused
    })

    // Recent history
    const need = MAX_TURNS * 2
    const recent = getRecentUserMessages.all(req.user.id, need).reverse()

    // Taplist (client override preferred)
    const taplistNow = Array.isArray(taplist) && taplist.length ? taplist : loadTaplist()

    console.log('BB/CHAT RECV →', JSON.stringify({
      received: { message },
      taplistSize: taplistNow.length
    }))

    // Save user message
    insertMsgUser.run(req.user.id, sessionId, 'user', String(message))

    // Build prompt + messages
    const input = [
      { role: 'system', content: SYSTEM_PROMPT(false, taplistNow) },
      ...recent,
      { role: 'user', content: String(message) }
    ]

    // OpenAI call
    const response = await client.responses.create({
      model: 'gpt-4.1-mini',
      input
    })
    const text = response.output_text ?? '(no reply)'

    // Save assistant reply
    insertMsgUser.run(req.user.id, sessionId, 'assistant', text)

    res
      .set('x-bb-used', 'system-prompt-spicy')
      .set('x-bb-snark', 'Spicy')
      .set('x-bb-taplist', String(taplistNow.length))
      .json({
        reply: text,
        meta: {
          used: 'system-prompt-spicy',
          snarkLevel: 'Spicy',
          taplistSize: taplistNow.length
        }
      })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'server_error', detail: String(err.message || err) })
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
