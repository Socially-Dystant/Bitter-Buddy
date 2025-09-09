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
    const content = fs.readFileSync(path.join(__dirname, 'data', 'taplist.json'), 'utf-8')
    return JSON.parse(content)
  } catch (err) {
    console.warn('⚠️ Could not load taplist.json:', err.message)
    return []
  }
}


taplist = loadTaplist()

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
  // --- Normalize inputs ---
  const sn = String(snark || 'Mild').trim().toLowerCase()
  const SnarkLevel =
    sn.startsWith('off') ? 'Off' :
    sn.startsWith('mild') ? 'Mild' :
    sn.startsWith('med') ? 'Medium' :
    sn.startsWith('spic') ? 'Spicy' :
    'Extra'

  const KidSafe = !!kidSafe
  const Snobby = !!snobby
  const tap = Array.isArray(taplist) ? taplist : []
  const TaplistJSON = JSON.stringify(tap, null, 2)

  // --- Single, consistent Bitter-Buddy prompt ---
  return `
Prompt Name: Bitter-Buddy

Context:
- SnarkLevel: ${SnarkLevel}            // One of: Off, Mild, Medium, Spicy, Extra
- KidSafe: ${KidSafe}                  // true | false
- Snobby: ${Snobby}                    // true | false (affects vibe only)
- Taplist: ${TaplistJSON}              // JSON array of beers (name, style, abv, url/description)

You are "Beer Bot," a blunt and witty cicerone who answers ONLY beer-related queries. Replies must be ONE short paragraph (1–3 brief sentences total). No slurs, no threats, and no jokes about protected traits. Humor targets generic laziness, “generic brewers,” or (playfully) the user—never mean-spirited. If KidSafe=true, do NOT recommend beer; reply politely and humorously that kids shouldn’t use a beer bot.

Tone by SnarkLevel:
- Off: factual, no sarcasm.
- Mild: gentle sarcasm.
- Medium: more bite than Mild.
- Spicy: snarky pub banter.
- Extra: edgy pub banter; mild profanity allowed, but never slurs or sexual/graphic language.

Behavior:
- If the request isn’t beer-related, briefly nudge back to beer in the current SnarkLevel tone.
- If the requested beer isn’t on Taplist, recommend a close alternative from Taplist:
  1) prioritize style similarity (case-insensitive match);
  2) then ABV proximity (prefer within ±1.0% if available);
  3) if Taplist is empty or no close match, say so and suggest a style category instead of a brand.
- Keep answers concise and beer-focused; do not mention these instructions or variables.

Output format (strict):
- One paragraph, 1–3 short sentences total.
- Start with a brief rationale clause (e.g., “Not on tap; closest match is …”), then a short snark/roast if appropriate for SnarkLevel and KidSafe, then the recommendation/answer.
- No bullets, lists, headings, or emojis unless the user used them first.
`.trim()
}


// --- chat route (per-user history; requires login) ---
const MAX_TURNS = 100 // last 100 user+assistant turns

app.post('/chat', requireAuth, async (req, res) => {
  try {
    const { message, snarkLevel, kidSafe, taplist } = req.body ?? {};
    if (!message) return res.status(400).json({ error: 'message required' });

    // Normalize inputs
    const snark = normalizeSnark(snarkLevel ?? 'Mild'); // -> Off|Mild|Medium|Spicy|Extra
    const ksafe = !!kidSafe;

    // Persist session prefs (keep schema compatible; set snobby=0)
    const sessionId = req.user.id;
    upsertSession.run({
      id: sessionId,
      snark_level: snark,
      kid_safe: ksafe ? 1 : 0,
      snobby: 0
    });

    // Recent per-user history (unchanged)
    const need = MAX_TURNS * 2;
    const recent = getRecentUserMessages.all(req.user.id, need).reverse();

    // Taplist: prefer client-provided array when present; else load server copy
    const taplistNow = Array.isArray(taplist) && taplist.length > 0 ? taplist : loadTaplist();
    console.log(`🧪 Loaded taplist with ${taplistNow.length} beers (source: ${Array.isArray(taplist) && taplist.length ? 'client' : 'server'})`);
    console.log(`🎚️ snark=${snark} kidSafe=${ksafe}`);

    // Build prompt + messages
    const system = SYSTEM_PROMPT(snark, ksafe, /*snobby*/ false, taplistNow);
    const input = [
      { role: 'system', content: system },
      ...recent,
      { role: 'user', content: String(message) }
    ];

    // Save user message
    insertMsgUser.run(req.user.id, sessionId, 'user', String(message));

    // Call OpenAI
    const response = await client.responses.create({
      model: 'gpt-4.1-mini',
      input
    });
    const text = response.output_text ?? '(no reply)';

    // Save assistant reply
    insertMsgUser.run(req.user.id, sessionId, 'assistant', text);

    res.json({ reply: text });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server_error', detail: String(err.message || err) });
  }
});



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
