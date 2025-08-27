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

// --- setup paths ---
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const taplistPath = path.join(__dirname,'data', 'taplist.json')
let taplist = []
function loadTaplist() {
  try {
    const content = fs.readFileSync(TAPLIST_PATH, 'utf-8')
    taplist = JSON.parse(content)
    console.log(`✅ Loaded ${taplist.length} beers from taplist.json`)
  } catch (err) {
    console.warn('⚠️ Could not load taplist.json:', err.message)
    taplist = []
  }
}

loadTaplist()

// --- express app ---
const app = express()
// If frontend is same-origin, this is fine. If hosted elsewhere, set an allowlist.
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

// --- openai client ---
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

// --- sqlite (file path via DB_PATH; create dir if needed) ---
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
  snark_level TEXT DEFAULT 'Mild',
  kid_safe INTEGER DEFAULT 0,
  snobby INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,                -- per-user history
  session_id TEXT,             -- optional (legacy/session based)
  role TEXT NOT NULL,          -- 'system' | 'user' | 'assistant'
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`)

// If your old table lacked user_id, this no-ops on fresh DB and adds it on existing.
try { db.exec(`ALTER TABLE messages ADD COLUMN user_id TEXT`); } catch {}

// --- small helpers ---
const SNARK_LEVELS = ['Off', 'Mild', 'Medium', 'Spicy', 'Extra']
function normalizeSnark(input = 'Mild') {
  const v = String(input).trim().toLowerCase()
  if (v.startsWith('off')) return 'Off'
  if (v.startsWith('mild') || v === 'low' || v === '1') return 'Mild'
  if (v.startsWith('med') || v === '2') return 'Medium'
  if (v.startsWith('spic') || v === '3') return 'Spicy'
  return 'Extra'
}
const rid = (n = 16) => crypto.randomBytes(n).toString('hex')

// --- SQL prepared statements ---
// users
const insertUser = db.prepare(`
  INSERT INTO users (id, email, password_hash) VALUES (@id, @email, @password_hash)
`)
const getUserByEmail = db.prepare(`SELECT * FROM users WHERE email = ?`)
const getUserById    = db.prepare(`SELECT * FROM users WHERE id = ?`)

// sessions (kept for possible future per-user prefs)
const upsertSession = db.prepare(`
INSERT INTO sessions (id, snark_level, kid_safe, snobby)
VALUES (@id, @snark_level, @kid_safe, @snobby)
ON CONFLICT(id) DO UPDATE SET
  snark_level=excluded.snark_level,
  kid_safe=excluded.kid_safe,
  snobby=excluded.snobby
`)
const getSession = db.prepare(`SELECT * FROM sessions WHERE id = ?`)

// messages (per-user)
const insertMsgUser = db.prepare(`
  INSERT INTO messages (user_id, session_id, role, content) VALUES (?, ?, ?, ?)`)

const getRecentUserMessages = db.prepare(`
  SELECT role, content FROM messages WHERE user_id = ? ORDER BY id DESC LIMIT ?
`)

// --- auth middleware ---
function requireAuth(req, res, next) {
  const uid = req.signedCookies?.uid
  if (!uid) return res.status(401).json({ error: 'unauthenticated' })
  const user = getUserById.get(uid)
  if (!user) return res.status(401).json({ error: 'invalid_user' })
  req.user = user
  next()
}

// --- auth routes ---
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
      secure: true,                      // keep true on Render (https)
      signed: !!process.env.AUTH_SECRET, // sign only if secret provided
      maxAge: 1000 * 60 * 60 * 24 * 30   // 30 days
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

// --- system prompt ---
function SYSTEM_PROMPT(snark, kidSafe = false, snobby = false, taplist = []) {
  const tone =
    snark === 'Off' ? 'Be friendly, clear, and professional.'
    : snark === 'Mild' ? 'Light sarcasm, playful tone.'
    : snark === 'Medium' ? 'Noticeably snarky pub-banter; short playful roasts.'
    : snark === 'Spicy' ? 'Salty pub-banter; short punchlines; keep it good-natured.'
    : 'High snark; still playful, never cruel; one-liners allowed.'

  const profanity = kidSafe
    ? 'Absolutely no profanity. Use clean snark (“heck”, “dang”, “keg gremlins”).'
    : 'Mild profanity allowed in punchlines; never overdo it. No slurs, no sexual content.'

  const flavor = snobby
    ? 'Adopt a “snobby cicerone” vibe—confident, slightly superior, but helpful.'
    : 'Adopt a “rude-but-fun bartender” vibe—blunt, witty, but helpful.'

  let beerNames = Array.isArray(taplist) ? taplist.map(b => b.name).join(', ') : ''
  if (beerNames.length > 1000) beerNames = beerNames.slice(0, 1000) + '...'

  const taplistNotice = beerNames
    ? `Here are the beers currently on tap: ${beerNames}`
    : `No taplist is available currently.`

  return `
You are Beer Bot, a witty beer expert. Style: ${snobby ? 'Snobby' : 'Rude-Fun'}, SnarkLevel=${snark}, KidSafe=${kidSafe}.
${flavor}
${tone}
${profanity}
${taplistNotice}

Core behavior:
- Give accurate, concise beer guidance (ABV/IBU ranges, flavor notes, style relatives).
- 2–4 sentences, no bullets unless asked.
- Never use slurs or target protected traits. Never threaten. Never bully real individuals.
- If a requested beer is NOT on tap/available, do BOTH:
  1) Suggest the closest stylistic substitute a typical venue might have.
  2) Add ONE playful roast blaming the user or brewery (good-natured, one line).
- If you don’t know the taplist, ask for it once (politely snarky), then recommend a common substitute.
- If KidSafe=true, automatically use clean language.
`
}

// --- chat route (per-user history; requires login) ---
const MAX_TURNS = 100 // last 100 user+assistant turns

app.post('/chat', requireAuth, async (req, res) => {
  try {
    const { message, snarkLevel, kidSafe, snobby } = req.body ?? {}
    if (!message) return res.status(400).json({ error: 'message required' })

    const snark = normalizeSnark(snarkLevel ?? 'Mild')
    const ksafe = !!kidSafe
    const snob  = !!snobby

    // make sure a sessions row exists to satisfy FK (use user.id as session_id)
    const sessionId = req.user.id
    upsertSession.run({
      id: sessionId,
      snark_level: snark,
      kid_safe: ksafe ? 1 : 0,
      snobby: snob ? 1 : 0
    })

    // recent history (unchanged)
    const need = MAX_TURNS * 2
    const recent = getRecentUserMessages.all(req.user.id, need).reverse()

    const input = [
      { role: 'system', content: SYSTEM_PROMPT(snark, ksafe, snob) },
      ...recent,
      { role: 'user', content: String(message) }
    ]

    // save user message (note the 4 args now: user_id, session_id, role, content)
    insertMsgUser.run(req.user.id, sessionId, 'user', String(message))

    const response = await client.responses.create({ model: 'gpt-4.1-mini', input })
    const text = response.output_text ?? '(no reply)'

    // save assistant message
    insertMsgUser.run(req.user.id, sessionId, 'assistant', text)

    res.json({ reply: text })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'server_error', detail: String(err.message || err) })
  }
})


// --- history & reset (per user) ---
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

// --- start server ---
const port = process.env.PORT || 8787
app.listen(port, () => console.log(`beerbot-edge listening on http://localhost:${port}`))
