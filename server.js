const path = require('path');
const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();

const RSVP_DEADLINE_ISO = process.env.RSVP_DEADLINE_ISO || '2026-06-15T23:59:59+03:00';
const RSVP_DEADLINE = new Date(RSVP_DEADLINE_ISO);

const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || 'graduation';
const MONGODB_COLLECTION = process.env.MONGODB_COLLECTION || 'rsvps';

let mongoClient;
let mongoCollection;
let ensuredIndexes = false;

function isAfterDeadline() {
  return new Date() > RSVP_DEADLINE;
}

function normalizePhone(phone) {
  return String(phone || '').trim().replace(/\s+/g, '');
}

function normalizeText(value) {
  return String(value || '').trim();
}

async function getCollection() {
  if (!MONGODB_URI) {
    const err = new Error('Missing MONGODB_URI env var');
    err.code = 'MISSING_MONGODB_URI';
    throw err;
  }
  if (mongoCollection) return mongoCollection;

  mongoClient = mongoClient || new MongoClient(MONGODB_URI);
  await mongoClient.connect();
  const db = mongoClient.db(MONGODB_DB);
  mongoCollection = db.collection(MONGODB_COLLECTION);

  if (!ensuredIndexes) {
    ensuredIndexes = true;
    await mongoCollection.createIndex({ inviterPhone: 1 }, { unique: true });
    await mongoCollection.createIndex({ updatedAt: -1 });
  }

  return mongoCollection;
}

// Basic, in-memory rate limit (best-effort only)
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 15;
const rateBuckets = new Map();
function rateLimitOk(ip) {
  const now = Date.now();
  const cur = rateBuckets.get(ip) || { n: 0, resetAt: now + RATE_WINDOW_MS };
  if (now > cur.resetAt) {
    cur.n = 0;
    cur.resetAt = now + RATE_WINDOW_MS;
  }
  cur.n += 1;
  rateBuckets.set(ip, cur);
  return cur.n <= RATE_MAX;
}

app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

app.post('/api/rsvp', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() || req.ip;
    if (!rateLimitOk(ip)) {
      return res.status(429).json({ ok: false, error: 'Too many requests. Please try again in a minute.' });
    }

    if (isAfterDeadline()) {
      return res.status(403).json({ ok: false, error: 'RSVP unavailable (deadline passed).' });
    }

    const body = req.body || {};
    if (normalizeText(body.hp)) {
      // Honeypot field filled -> likely bot
      return res.status(400).json({ ok: false, error: 'Invalid submission.' });
    }

    const statusRaw = normalizeText(body.status).toLowerCase();
    const status = statusRaw === 'yes' ? 'yes' : statusRaw === 'no' ? 'no' : '';
    if (!status) return res.status(400).json({ ok: false, error: 'Please select Coming or Not coming.' });

    const inviterName = normalizeText(body.inviterName);
    const inviterPhone = normalizePhone(body.inviterPhone);
    const dietNote = normalizeText(body.dietNote);

    if (!inviterName) return res.status(400).json({ ok: false, error: 'Name is required.' });
    if (!inviterPhone) return res.status(400).json({ ok: false, error: 'Phone is required.' });

    let partySize = Number.isFinite(body.partySize) ? body.partySize : parseInt(String(body.partySize || ''), 10);
    if (!Number.isFinite(partySize)) partySize = 0;
    partySize = Math.floor(partySize);

    const guestNamesInput = Array.isArray(body.guestNames) ? body.guestNames : [];
    const guestNames = guestNamesInput
      .map((n) => normalizeText(n))
      .filter((n) => n.length > 0);

    let normalizedPartySize = 0;
    let normalizedGuestNames = [];
    if (status === 'no') {
      normalizedPartySize = 0;
      normalizedGuestNames = [];
    } else {
      if (!Number.isFinite(partySize) || partySize < 1) {
        return res.status(400).json({ ok: false, error: 'Party size must be at least 1.' });
      }
      if (partySize === 1) {
        if (guestNames.length !== 0) {
          return res.status(400).json({ ok: false, error: 'Guest names must be empty when party size is 1.' });
        }
      } else {
        const expected = partySize - 1;
        if (guestNames.length !== expected) {
          return res.status(400).json({ ok: false, error: `Please enter exactly ${expected} guest name(s).` });
        }
      }
      normalizedPartySize = partySize;
      normalizedGuestNames = guestNames;
    }

    const collection = await getCollection();
    const now = new Date();
    const doc = {
      status,
      inviterName,
      inviterPhone,
      partySize: normalizedPartySize,
      guestNames: normalizedGuestNames,
      dietNote: dietNote || '',
      updatedAt: now,
      deadlineIso: RSVP_DEADLINE_ISO
    };

    await collection.updateOne(
      { inviterPhone },
      {
        $set: doc,
        $setOnInsert: { createdAt: now }
      },
      { upsert: true }
    );

    return res.status(200).json({ ok: true, status });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);

    if (err && err.code === 'MISSING_MONGODB_URI') {
      return res.status(500).json({ ok: false, error: 'Server not configured (missing database connection).' });
    }

    // Common Atlas connection failures (network allowlist, bad credentials, etc.)
    const msg = String(err && err.message ? err.message : '');
    if (/ECONNREFUSED|ENOTFOUND|ETIMEDOUT|MongoNetworkError/i.test(msg)) {
      return res.status(500).json({ ok: false, error: 'Database connection failed. Please try again later.' });
    }

    return res.status(500).json({ ok: false, error: 'Server error. Please try again.' });
  }
});

app.get('/healthz', (_req, res) => {
  res.status(200).json({ ok: true, deadline: RSVP_DEADLINE_ISO });
});

app.use(express.static(path.join(__dirname), {
  extensions: ['html']
}));

// SPA-ish fallback to index.html
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const port = parseInt(process.env.PORT || '3000', 10);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Server listening on :${port}`);
});
