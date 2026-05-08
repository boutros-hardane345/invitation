const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const { MongoClient } = require('mongodb');

const app = express();

const RSVP_DEADLINE_ISO = process.env.RSVP_DEADLINE_ISO || '2026-06-15T23:59:59+03:00';
const RSVP_DEADLINE = new Date(RSVP_DEADLINE_ISO);

const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_DB = process.env.MONGODB_DB || 'graduation';
const MONGODB_COLLECTION = process.env.MONGODB_COLLECTION || 'rsvps';
const ADMIN_USER = process.env.ADMIN_USER || '';
const ADMIN_PASS = process.env.ADMIN_PASS || '';
const ADMIN_SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || '';

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

function parseBasicAuth(authHeader) {
  const auth = normalizeText(authHeader);
  if (!auth) return null;
  const m = auth.match(/^Basic\s+(.+)$/i);
  if (!m) return null;
  let decoded = '';
  try {
    decoded = Buffer.from(m[1], 'base64').toString('utf8');
  } catch {
    return null;
  }
  const idx = decoded.indexOf(':');
  if (idx === -1) return null;
  return {
    user: decoded.slice(0, idx),
    pass: decoded.slice(idx + 1)
  };
}

function requireAdmin(req, res) {
  if (!ADMIN_USER || !ADMIN_PASS) {
    res.status(500).json({ ok: false, error: 'Admin not configured.' });
    return false;
  }

  const creds = parseBasicAuth(req.headers && req.headers.authorization);
  if (!creds || creds.user !== ADMIN_USER || creds.pass !== ADMIN_PASS) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    res.status(401).json({ ok: false, error: 'Unauthorized' });
    return false;
  }

  return true;
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
app.use(express.urlencoded({ extended: false }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

if (ADMIN_SESSION_SECRET) {
  app.use(cookieParser(ADMIN_SESSION_SECRET));
}

function isHttpsReq(req) {
  if (req.secure) return true;
  const xf = normalizeText(req.headers && req.headers['x-forwarded-proto']);
  return xf.toLowerCase() === 'https';
}

const ADMIN_COOKIE_NAME = 'admin_session';
const ADMIN_COOKIE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

function adminConfigured() {
  return Boolean(ADMIN_USER && ADMIN_PASS && ADMIN_SESSION_SECRET);
}

function isAdminSession(req) {
  return Boolean(req.signedCookies && req.signedCookies[ADMIN_COOKIE_NAME] === '1');
}

function requireAdminPage(req, res, next) {
  if (!adminConfigured()) return res.status(500).type('html').send('Admin not configured.');
  if (!isAdminSession(req)) return res.redirect('/admin/login');
  return next();
}

function requireAdminApi(req, res, next) {
  if (!adminConfigured()) return res.status(500).json({ ok: false, error: 'Admin not configured.' });
  if (!isAdminSession(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  return next();
}

// Admin login rate limit (strict lockout window)
const ADMIN_LOGIN_WINDOW_MS = parseInt(process.env.ADMIN_LOGIN_RATE_WINDOW_MS || '600000', 10);
const ADMIN_LOGIN_MAX = parseInt(process.env.ADMIN_LOGIN_RATE_MAX || '10', 10);
const adminLoginBuckets = new Map();
function adminLoginOk(ip) {
  const now = Date.now();
  const cur = adminLoginBuckets.get(ip) || { n: 0, resetAt: now + ADMIN_LOGIN_WINDOW_MS };
  if (now > cur.resetAt) {
    cur.n = 0;
    cur.resetAt = now + ADMIN_LOGIN_WINDOW_MS;
  }
  cur.n += 1;
  adminLoginBuckets.set(ip, cur);
  return cur.n <= ADMIN_LOGIN_MAX;
}

app.get('/admin/login', (req, res) => {
  if (!adminConfigured()) return res.status(500).type('html').send('Admin not configured.');
  if (isAdminSession(req)) return res.redirect('/admin');
  return res.render('login', { error: '' });
});

app.post('/admin/login', (req, res) => {
  if (!adminConfigured()) return res.status(500).type('html').send('Admin not configured.');

  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() || req.ip;
  if (!adminLoginOk(ip)) {
    return res.status(429).render('login', { error: 'Too many attempts. Please try again later.' });
  }

  const username = normalizeText(req.body && req.body.username);
  const password = normalizeText(req.body && req.body.password);
  if (!username || !password || username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(401).render('login', { error: 'Invalid credentials.' });
  }

  res.cookie(ADMIN_COOKIE_NAME, '1', {
    httpOnly: true,
    signed: true,
    sameSite: 'lax',
    secure: isHttpsReq(req),
    maxAge: ADMIN_COOKIE_MAX_AGE_MS,
    path: '/'
  });
  return res.redirect('/admin');
});

app.post('/admin/logout', (req, res) => {
  if (!adminConfigured()) return res.status(500).type('html').send('Admin not configured.');
  res.clearCookie(ADMIN_COOKIE_NAME, { path: '/' });
  return res.redirect('/admin/login');
});

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

// ── ADMIN DASHBOARD ───────────────────────────────────
app.get('/admin', requireAdminPage, (req, res) => {

  res.status(200).type('html').send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>RSVP Admin</title>
    <script src="https://cdn.jsdelivr.net/npm/canvas-confetti@1"></script>
    <style>
      :root{--bg:#0a0a0a;--card:#111;--gold:#d4af37;--gold2:#f5d742;--muted:#bdbdbd;--danger:#c0392b;}
      *{box-sizing:border-box;}
      body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:#fff;padding:16px;}
      .wrap{max-width:1100px;margin:0 auto;}
      .top{display:flex;gap:12px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin-bottom:14px;}
      .title{font-weight:800;letter-spacing:0.5px;color:var(--gold2);}
      .bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
      .btn{border:1px solid rgba(212,175,55,0.65);background:#000;color:var(--gold2);padding:10px 12px;border-radius:10px;cursor:pointer;font-weight:700;}
      .btn:hover{border-color:var(--gold2);}
      .btn-danger{border-color:rgba(192,57,43,0.7);color:#ffb4a9;}
      .btn-danger:hover{border-color:#ffb4a9;}
      .input, .select{border:1px solid rgba(212,175,55,0.35);background:#000;color:#fff;padding:10px 12px;border-radius:10px;min-width:220px;}
      .select{min-width:160px;}
      .cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:12px 0;}
      @media(max-width:800px){.cards{grid-template-columns:1fr;}}
      .card{background:var(--card);border:1px solid rgba(212,175,55,0.25);border-radius:14px;padding:12px;}
      .label{color:var(--muted);font-size:12px;letter-spacing:1px;text-transform:uppercase;}
      .value{font-size:26px;font-weight:900;color:var(--gold2);margin-top:6px;}
      .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
      .toggle{display:flex;gap:8px;align-items:center;color:var(--muted);font-size:14px;}
      table{width:100%;border-collapse:collapse;margin-top:12px;background:var(--card);border:1px solid rgba(212,175,55,0.2);border-radius:14px;overflow:hidden;}
      th,td{padding:10px 10px;border-bottom:1px solid rgba(255,255,255,0.06);vertical-align:top;text-align:left;font-size:13px;}
      th{color:var(--gold);font-size:12px;letter-spacing:1px;text-transform:uppercase;background:#0c0c0c;}
      tr:hover td{background:#0c0c0c;}
      .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid rgba(212,175,55,0.35);color:var(--gold2);font-weight:800;font-size:12px;}
      .pill.no{border-color:rgba(192,57,43,0.5);color:#ffb4a9;}
      .muted{color:var(--muted);}
      .small{font-size:12px;line-height:1.4;color:var(--muted);}
      .err{display:none;margin-top:12px;background:#1b0f0f;border:1px solid rgba(192,57,43,0.6);color:#ffb4a9;border-radius:14px;padding:10px;}

      /* Mobile cards */
      #cards{display:none; margin-top:12px;}
      .rsvp-card{background:var(--card);border:1px solid rgba(212,175,55,0.2);border-radius:14px;padding:12px;display:grid;gap:10px;}
      .rsvp-card .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
      .rsvp-card .k{color:var(--muted);font-size:12px;letter-spacing:1px;text-transform:uppercase;}
      .rsvp-card .v{font-size:14px;line-height:1.4;}
      .rsvp-card .actions{display:flex;gap:10px;flex-wrap:wrap;}

      @media(max-width:720px){
        body{padding:12px;}
        .top{gap:10px;}
        .bar{width:100%;}
        .input{min-width:0;width:100%;}
        .select{min-width:0;}
        table{display:none;}
        #cards{display:grid;gap:10px;}
        .cards{grid-template-columns:1fr;}
      }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="top">
        <div class="title">RSVP Dashboard</div>
        <div class="bar">
          <select id="status" class="select">
            <option value="yes" selected>Coming</option>
            <option value="no">Declined</option>
            <option value="all">All</option>
          </select>
          <input id="q" class="input" placeholder="Search name / phone / guest" />
          <label class="toggle"><input id="showDeleted" type="checkbox" /> Show deleted</label>
          <button id="refresh" class="btn">Refresh</button>
          <button id="logout" class="btn btn-danger">Logout</button>
        </div>
      </div>

      <div id="err" class="err"></div>

      <div class="cards">
        <div class="card"><div class="label">Coming</div><div class="value" id="cYes">-</div></div>
        <div class="card"><div class="label">Declined</div><div class="value" id="cNo">-</div></div>
        <div class="card"><div class="label">Total Persons (Coming)</div><div class="value" id="cTotal">-</div></div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Phone</th>
            <th>Status</th>
            <th>Party</th>
            <th>Guests</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>

      <div id="cards"></div>
    </div>

    <script>
      (function(){
        const errEl = document.getElementById('err');
        const logout = document.getElementById('logout');
        const refresh = document.getElementById('refresh');
        const statusSel = document.getElementById('status');
        const qEl = document.getElementById('q');
        const showDeleted = document.getElementById('showDeleted');
        const tbody = document.getElementById('tbody');
        const cards = document.getElementById('cards');

        const GOLD = ['#d4af37','#f5d742','#b8860b','#ffffff','#e5c87b','#fffacd'];
        function canConfetti(){
          try{ return !window.matchMedia('(prefers-reduced-motion: reduce)').matches; }catch{ return true; }
        }
        function burst(size){
          if(!canConfetti() || typeof confetti !== 'function') return;
          confetti({ particleCount: size, spread: 75, origin: { x: 0.5, y: 0.25 }, colors: GOLD, startVelocity: 28, ticks: 220, gravity: 0.9, scalar: 1.0 });
        }

        function setErr(msg){
          errEl.textContent = msg || '';
          errEl.style.display = msg ? 'block' : 'none';
        }

        async function api(path){
          const res = await fetch(path);
          const data = await res.json().catch(()=>({ ok:false, error:'Bad response' }));
          if(!res.ok || !data.ok){
            throw new Error(data && data.error ? data.error : 'Request failed');
          }
          return data;
        }

        async function post(path){
          const res = await fetch(path, { method:'POST' });
          const data = await res.json().catch(()=>({ ok:false, error:'Bad response' }));
          if(!res.ok || !data.ok){
            throw new Error(data && data.error ? data.error : 'Request failed');
          }
          return data;
        }

        function renderRow(r){
          const tr = document.createElement('tr');
          const guests = Array.isArray(r.guestNames) && r.guestNames.length ? r.guestNames.join(', ') : '';
          const isDel = r.deleted === true;
          tr.innerHTML = [
            '<td>' + escapeHtml(r.inviterName || '') + (isDel ? ' <span class="muted">(deleted)</span>' : '') + '</td>',
            '<td>' + escapeHtml(r.inviterPhone || '') + '</td>',
            '<td>' + (r.status === 'yes' ? '<span class="pill">yes</span>' : '<span class="pill no">no</span>') + '</td>',
            '<td>' + (r.status === 'yes' ? String(r.partySize || 0) : '-') + '</td>',
            '<td class="small">' + escapeHtml(guests) + '</td>',
            '<td></td>'
          ].join('');
          const actionTd = tr.lastElementChild;
          if(isDel){
            const b = document.createElement('button');
            b.className = 'btn';
            b.textContent = 'Restore';
            b.onclick = async ()=>{
              if(!confirm('Restore this RSVP?')) return;
              setErr('');
              try{ await post('/api/admin/rsvps/' + encodeURIComponent(r.inviterPhone) + '/restore'); await loadAll(); }
              catch(e){ setErr(e.message || 'Restore failed'); }
            };
            actionTd.appendChild(b);
          } else {
            const b = document.createElement('button');
            b.className = 'btn btn-danger';
            b.textContent = 'Delete';
            b.onclick = async ()=>{
              if(!confirm('Delete RSVP for ' + (r.inviterName||'') + ' (' + (r.inviterPhone||'') + ')?')) return;
              setErr('');
              try{ await post('/api/admin/rsvps/' + encodeURIComponent(r.inviterPhone) + '/delete'); await loadAll(); }
              catch(e){ setErr(e.message || 'Delete failed'); }
            };
            actionTd.appendChild(b);
          }
          return tr;
        }

        function renderCard(r){
          const wrap = document.createElement('div');
          wrap.className = 'rsvp-card';
          const guests = Array.isArray(r.guestNames) && r.guestNames.length ? r.guestNames.join(', ') : '';
          const isDel = r.deleted === true;

          const top = document.createElement('div');
          top.innerHTML = '<div class="k">Name</div><div class="v">' + escapeHtml(r.inviterName || '') + (isDel ? ' <span class="muted">(deleted)</span>' : '') + '</div>';

          const grid = document.createElement('div');
          grid.className = 'grid';
          grid.innerHTML = [
            '<div><div class="k">Phone</div><div class="v">' + escapeHtml(r.inviterPhone || '') + '</div></div>',
            '<div><div class="k">Status</div><div class="v">' + (r.status === 'yes' ? '<span class="pill">yes</span>' : '<span class="pill no">no</span>') + '</div></div>',
            '<div><div class="k">Party</div><div class="v">' + (r.status === 'yes' ? String(r.partySize || 0) : '-') + '</div></div>',
            '<div><div class="k">Guests</div><div class="v small">' + escapeHtml(guests) + '</div></div>'
          ].join('');

          const actions = document.createElement('div');
          actions.className = 'actions';
          if(isDel){
            const b = document.createElement('button');
            b.className = 'btn';
            b.textContent = 'Restore';
            b.onclick = async ()=>{
              if(!confirm('Restore this RSVP?')) return;
              setErr('');
              try{ await post('/api/admin/rsvps/' + encodeURIComponent(r.inviterPhone) + '/restore'); burst(80); await loadAll(); }
              catch(e){ setErr(e.message || 'Restore failed'); }
            };
            actions.appendChild(b);
          } else {
            const b = document.createElement('button');
            b.className = 'btn btn-danger';
            b.textContent = 'Delete';
            b.onclick = async ()=>{
              if(!confirm('Delete RSVP for ' + (r.inviterName||'') + ' (' + (r.inviterPhone||'') + ')?')) return;
              setErr('');
              try{ await post('/api/admin/rsvps/' + encodeURIComponent(r.inviterPhone) + '/delete'); burst(60); await loadAll(); }
              catch(e){ setErr(e.message || 'Delete failed'); }
            };
            actions.appendChild(b);
          }

          wrap.appendChild(top);
          wrap.appendChild(grid);
          wrap.appendChild(actions);
          return wrap;
        }

        function escapeHtml(s){
          return String(s).replace(/[&<>\"']/g, (c)=>({ '&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;' }[c]));
        }

        async function loadStats(){
          const inc = showDeleted.checked ? 1 : 0;
          const data = await api('/api/admin/stats?includeDeleted=' + inc);
          document.getElementById('cYes').textContent = String(data.comingCount);
          document.getElementById('cNo').textContent = String(data.declinesCount);
          document.getElementById('cTotal').textContent = String(data.totalPersons);
        }

        async function loadList(){
          const inc = showDeleted.checked ? 1 : 0;
          const st = statusSel.value || 'yes';
          const q = (qEl.value || '').trim();
          const url = new URL('/api/admin/rsvps', location.origin);
          url.searchParams.set('includeDeleted', String(inc));
          url.searchParams.set('status', st);
          if(q) url.searchParams.set('q', q);
          url.searchParams.set('limit', '200');

          const data = await api(url.toString());
          tbody.innerHTML = '';
          cards.innerHTML = '';
          for(const r of data.items){
            tbody.appendChild(renderRow(r));
            cards.appendChild(renderCard(r));
          }
        }

        async function loadAll(){
          setErr('');
          try{
            await loadStats();
            await loadList();
            if(!window.__didBurst){ window.__didBurst = true; burst(90); }
          } catch(e){
            setErr(e.message || 'Failed to load');
          }
        }

        logout.addEventListener('click', ()=>{
          // Use a POST logout to clear cookie.
          fetch('/admin/logout', { method: 'POST' }).finally(()=>{ location.href = '/admin/login'; });
        });
        refresh.addEventListener('click', loadAll);
        statusSel.addEventListener('change', loadAll);
        showDeleted.addEventListener('change', loadAll);
        qEl.addEventListener('keydown', (e)=>{ if(e.key === 'Enter') loadAll(); });

        loadAll();
      })();
    </script>
  </body>
</html>`);
});

app.get('/api/admin/stats', requireAdminApi, async (req, res) => {
  try {
    const includeDeleted = normalizeText(req.query && req.query.includeDeleted) === '1';
    const baseFilter = includeDeleted ? {} : { deleted: { $ne: true } };

    const collection = await getCollection();
    const [comingCount, declinesCount] = await Promise.all([
      collection.countDocuments({ ...baseFilter, status: 'yes' }),
      collection.countDocuments({ ...baseFilter, status: 'no' })
    ]);

    const agg = await collection
      .aggregate([
        { $match: { ...baseFilter, status: 'yes' } },
        { $group: { _id: null, total: { $sum: '$partySize' } } }
      ])
      .toArray();
    const totalPersons = agg && agg[0] && typeof agg[0].total === 'number' ? agg[0].total : 0;

    res.status(200).json({ ok: true, comingCount, declinesCount, totalPersons });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error.' });
  }
});

app.get('/api/admin/rsvps', requireAdminApi, async (req, res) => {
  try {
    const includeDeleted = normalizeText(req.query && req.query.includeDeleted) === '1';
    const status = normalizeText(req.query && req.query.status) || 'yes';
    const q = normalizeText(req.query && req.query.q);
    let limit = parseInt(normalizeText(req.query && req.query.limit) || '100', 10);
    let skip = parseInt(normalizeText(req.query && req.query.skip) || '0', 10);
    if (!Number.isFinite(limit) || limit < 1) limit = 100;
    if (limit > 500) limit = 500;
    if (!Number.isFinite(skip) || skip < 0) skip = 0;

    const filter = includeDeleted ? {} : { deleted: { $ne: true } };
    if (status === 'yes' || status === 'no') filter.status = status;

    if (q) {
      const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [
        { inviterName: rx },
        { inviterPhone: rx },
        { guestNames: rx }
      ];
    }

    const collection = await getCollection();
    const items = await collection
      .find(filter, {
        projection: {
          _id: 0,
          inviterName: 1,
          inviterPhone: 1,
          status: 1,
          partySize: 1,
          guestNames: 1,
          deleted: 1
        }
      })
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    res.status(200).json({ ok: true, items, limit, skip });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error.' });
  }
});

app.post('/api/admin/rsvps/:inviterPhone/delete', requireAdminApi, async (req, res) => {
  try {
    const inviterPhone = normalizePhone(req.params && req.params.inviterPhone);
    if (!inviterPhone) return res.status(400).json({ ok: false, error: 'Missing phone.' });

    const collection = await getCollection();
    const now = new Date();
    const r = await collection.updateOne(
      { inviterPhone },
      { $set: { deleted: true, deletedAt: now, deletedReason: 'admin', updatedAt: now } }
    );
    if (!r.matchedCount) return res.status(404).json({ ok: false, error: 'Not found.' });
    res.status(200).json({ ok: true });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error.' });
  }
});

app.post('/api/admin/rsvps/:inviterPhone/restore', requireAdminApi, async (req, res) => {
  try {
    const inviterPhone = normalizePhone(req.params && req.params.inviterPhone);
    if (!inviterPhone) return res.status(400).json({ ok: false, error: 'Missing phone.' });

    const collection = await getCollection();
    const now = new Date();
    const r = await collection.updateOne(
      { inviterPhone },
      { $unset: { deleted: '', deletedAt: '', deletedReason: '' }, $set: { updatedAt: now } }
    );
    if (!r.matchedCount) return res.status(404).json({ ok: false, error: 'Not found.' });
    res.status(200).json({ ok: true });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(err);
    res.status(500).json({ ok: false, error: 'Server error.' });
  }
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
  console.log(`Node ${process.version} | OpenSSL ${process.versions.openssl || 'unknown'}`);
});
