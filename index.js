// @ts-nocheck
import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import OpenAI from 'openai'
import Database from 'better-sqlite3'
import path from 'path'
import { fileURLToPath } from 'url'

// --- setup paths ---
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// --- express app ---
const app = express()
app.use(cors())
app.use(express.json())

// --- openai client ---
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

// --- sqlite (file: beerbot.db) ---
const db = new Database(path.join(__dirname, 'beerbot.db'))
db.pragma('journal_mode = WAL')

// create tables if not exist
db.exec(`
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

const insertMsg = db.prepare(`
INSERT INTO messages (session_id, role, content) VALUES (?, ?, ?)
`)

const getRecentMessages = db.prepare(`
SELECT role, content
FROM messages
WHERE session_id = ?
ORDER BY id DESC
LIMIT ?
`)

const deleteSessionMsgs = db.prepare(`DELETE FROM messages WHERE session_id = ?`)
const deleteSession = db.prepare(`DELETE FROM sessions WHERE id = ?`)

// keep only last N user+assistant turns (system is rebuilt each time)
const MAX_TURNS = 10  // tweak as you like (each "turn" ~ user+assistant)

// --- routes ---
// chat with memory
app.post('/chat', async (req, res) => {
  try {
    const {
      message,
      sessionId = 'default',    // pass a unique id per browser/user in production
      snarkLevel,               // optional override
      kidSafe,                  // optional override
      snobby                    // optional override
    } = req.body ?? {}

    if (!message) return res.status(400).json({ error: 'message required' })

    // load or create session
    const existing = getSession.get(sessionId)
    const snark = normalizeSnark(snarkLevel ?? existing?.snark_level ?? 'Mild')
    const ksafe = (kidSafe ?? existing?.kid_safe ?? 0) ? 1 : 0
    const snob  = (snobby ?? existing?.snobby ?? 0) ? 1 : 0

    upsertSession.run({
      id: sessionId,
      snark_level: snark,
      kid_safe: ksafe,
      snobby: snob
    })

    // load recent messages (last N turns * 2 roles)
    const need = MAX_TURNS * 2
    const recent = getRecentMessages.all(sessionId, need).reverse() // chronological

    // Build full input: fresh system + recent history + new user msg
    const input = [
      { role: 'system', content: SYSTEM_PROMPT(snark, !!ksafe, !!snob) },
      ...recent,
      { role: 'user', content: String(message) }
    ]

    // save user message
    insertMsg.run(sessionId, 'user', String(message))

    // call model
    const response = await client.responses.create({
      model: 'gpt-4.1-mini',
      input
    })

    const text = response.output_text ?? '(no reply)'
    // save assistant message
    insertMsg.run(sessionId, 'assistant', text)

    res.json({
      reply: text,
      meta: { sessionId, snarkLevel: snark, kidSafe: !!ksafe, snobby: !!snob, turnsKept: MAX_TURNS }
    })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'server_error', detail: String(err.message || err) })
  }
})

// view history (debug)
app.get('/history/:sessionId', (req, res) => {
  const s = req.params.sessionId || 'default'
  const rows = db.prepare(
    `SELECT role, content, created_at FROM messages WHERE session_id = ? ORDER BY id ASC`
  ).all(s)
  res.json({ sessionId: s, messages: rows })
})

// reset a session (clears memory)
app.post('/reset/:sessionId', (req, res) => {
  const s = req.params.sessionId || 'default'
  deleteSessionMsgs.run(s)
  deleteSession.run(s)
  res.json({ ok: true, sessionId: s })
})

// health
app.get('/health', (_, res) => res.json({ ok: true }))

// (optional) serve a simple homepage if you made index.html
app.get('/', (_, res) => {
  res.sendFile(path.join(__dirname, 'index.html'))
})

const port = process.env.PORT || 8787
app.listen(port, () => console.log(`beerbot-edge listening on http://localhost:${port}`))
