// @ts-nocheck
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import OpenAI from 'openai'
import Database from 'better-sqlite3'
import path from 'path'
import { fileURLToPath } from 'url'
import bcrypt from 'bcryptjs'
import cookieParser from 'cookie-parser'

// --- setup paths ---
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// --- express app ---
const app = express()
app.use(cors())
app.use(express.json())
app.use((req, _res, next) => { console.log(`${req.method} ${req.url}`); next(); });

process.on('unhandledRejection', (e) => console.error('unhandledRejection', e));
process.on('uncaughtException', (e) => console.error('uncaughtException', e));
app.get('/', (_, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --- openai client ---
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

// --- sqlite (file: beerbot.db) ---
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'beerbot.db')
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
  session_id TEXT NOT NULL,
  role TEXT NOT NULL,           -- 'system' | 'user' | 'assistant'
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
`)

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

function requireAuth(req, res, next) {
  const uid = req.signedCookies?.uid
  if (!uid) return res.status(401).json({ error: 'unauthenticated' })
  const user = getUserById.get(uid)
  if (!user) return res.status(401).json({ error: 'invalid_user' })
  req.user = user
  next()
}
// Register: { email, password }
app.post('/auth/register', (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) return res.status(400).json({ error: 'email_password_required' });

    const exists = getUserByEmail.get(String(email).toLowerCase());
    if (exists) return res.status(409).json({ error: 'email_in_use' });

    const id = rid();
    const password_hash = bcrypt.hashSync(String(password), 12);
    insertUser.run({ id, email: String(email).toLowerCase(), password_hash });

    res.cookie('uid', id, {
      httpOnly: true, sameSite: 'lax', secure: true,
      signed: !!process.env.AUTH_SECRET, maxAge: 1000*60*60*24*30
    });
    res.json({ ok: true, user: { id, email: String(email).toLowerCase() } });
  } catch (err) {
    console.error('register error:', err);
    res.status(500).json({ error: 'register_failed', detail: String(err.message || err) });
  }
})

// Login: { email, password }
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body ?? {}
  const user = getUserByEmail.get(String(email).toLowerCase())
  if (!user) return res.status(401).json({ error: 'invalid_credentials' })
  const ok = bcrypt.compareSync(String(password), user.password_hash)
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' })

  res.cookie('uid', user.id, {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    signed: true,
    maxAge: 1000 * 60 * 60 * 24 * 30
  })
  res.json({ ok: true, user: { id: user.id, email: user.email } })
})

app.post('/auth/logout', (req, res) => {
  res.clearCookie('uid')
  res.json({ ok: true })
})

app.get('/me', requireAuth, (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email } })
})


function SYSTEM_PROMPT(snark, kidSafe = false, snobby = false) {
  const tone =
    snark === 'Off'
      ? 'Be friendly, clear, and professional.'
      : snark === 'Mild'
      ? 'Light sarcasm, playful tone.'
      : snark === 'Medium'
      ? 'Noticeably snarky pub-banter; short playful roasts.'
      : snark === 'Spicy'
      ? 'Salty pub-banter; short punchlines; keep it good-natured.'
      : 'High snark; still playful, never cruel; one-liners allowed.'

  const profanity = kidSafe
    ? 'Absolutely no profanity. Use clean snark (“heck”, “dang”, “keg gremlins”).'
    : 'Mild profanity allowed in punchlines; never overdo it. No slurs, no sexual content.'

  const flavor = snobby
    ? 'Adopt a “snobby cicerone” vibe—confident, slightly superior, but helpful.'
    : 'Adopt a “rude-but-fun bartender” vibe—blunt, witty, but helpful.'

  return `
You are Beer Bot, a witty beer expert. Style: ${snobby ? 'Snobby' : 'Rude-Fun'}, SnarkLevel=${snark}, KidSafe=${kidSafe}.
${flavor}
${tone}
${profanity}

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

// --- DB statements ---
const upsertSession = db.prepare(`
INSERT INTO sessions (id, snark_level, kid_safe, snobby)
VALUES (@id, @snark_level, @kid_safe, @snobby)
ON CONFLICT(id) DO UPDATE SET
  snark_level=excluded.snark_level,
  kid_safe=excluded.kid_safe,
  snobby=excluded.snobby
`)

const getSession = db.prepare(`SELECT * FROM sessions WHERE id = ?`)

const insertMsg = db.prepare(`INSERT INTO messages (user_id, role, content) VALUES (?, ?, ?)`)

const getRecentUserMessages = db.prepare(`
SELECT role, content
FROM messages
WHERE user_id = ?
ORDER BY id DESC
LIMIT ?
`)

const MAX_TURNS = 10 // last 10 user+assistant turns

app.post('/chat', requireAuth, async (req, res) => {
  try {
    const { message, snarkLevel, kidSafe, snobby } = req.body ?? {}
    if (!message) return res.status(400).json({ error: 'message required' })

    // load preferences per user if you want—omitted here; feel free to store per-user settings in a new table.
    const snark = normalizeSnark(snarkLevel ?? 'Mild')
    const ksafe = !!kidSafe
    const snob  = !!snobby

    // recent history for this user
    const need = MAX_TURNS * 2
    const recent = getRecentUserMessages.all(req.user.id, need).reverse()

    const input = [
      { role: 'system', content: SYSTEM_PROMPT(snark, ksafe, snob) },
      ...recent,
      { role: 'user', content: String(message) }
    ]

    insertMsg.run(req.user.id, 'user', String(message))

    const response = await client.responses.create({
      model: 'gpt-4.1-mini',
      input
    })
    const text = response.output_text ?? '(no reply)'

    insertMsg.run(req.user.id, 'assistant', text)

    res.json({ reply: text })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'server_error', detail: String(err.message || err) })
  }
})

// optional helpers
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


const port = process.env.PORT || 8787
app.listen(port, () => console.log(`beerbot-edge listening on http://localhost:${port}`))
