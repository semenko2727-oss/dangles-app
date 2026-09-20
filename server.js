const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

// ---------- DATABASE SETUP ----------
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('president','coach','volunteer')),
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS teams (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      coach_id INTEGER REFERENCES users(id),
      roster JSONB NOT NULL DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS games (
      id SERIAL PRIMARY KEY,
      division TEXT,
      home TEXT,
      away TEXT,
      day_time TEXT,
      ref_name TEXT,
      ref_cert TEXT,
      volunteers JSONB NOT NULL DEFAULT '[]'
    );
  `);

  const { rows } = await pool.query('SELECT COUNT(*)::int AS c FROM games');
  if (rows[0].c === 0) {
    await pool.query(`
      INSERT INTO games (division, home, away, day_time, ref_name, ref_cert, volunteers) VALUES
      ('U11 House League','Carman','Miami','Sat 9:00 AM', NULL, 'Level 1+',
        '[{"task":"Timekeeper","filled":false,"name":null},{"task":"Scorekeeper","filled":false,"name":null}]'),
      ('Adult Rec','Carman','Roland','Sun 6:30 PM', NULL, 'Level 1',
        '[{"task":"Timekeeper","filled":false,"name":null}]')
    `);
  }
}

// ---------- AUTH HELPERS ----------
function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
}

function auth(req, res, next) {
  const token = req.cookies.dangles_token;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expired, please log in again' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have permission to do that' });
    }
    next();
  };
}

// ---------- AUTH ROUTES ----------
app.post('/api/signup', async (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password || !name || !['president', 'coach', 'volunteer'].includes(role)) {
    return res.status(400).json({ error: 'Missing or invalid fields' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (email, password_hash, name, role) VALUES ($1,$2,$3,$4) RETURNING id, email, name, role',
      [email.toLowerCase().trim(), hash, name.trim(), role]
    );
    const user = rows[0];
    const token = signToken(user);
    res.cookie('dangles_token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    res.json({ user: { name: user.name, role: user.role, email: user.email } });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'An account with that email already exists' });
    console.error(err);
    res.status(500).json({ error: 'Could not create account' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [(email || '').toLowerCase().trim()]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password || '', user.password_hash))) {
    return res.status(401).json({ error: 'Incorrect email or password' });
  }
  const token = signToken(user);
  res.cookie('dangles_token', token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  res.json({ user: { name: user.name, role: user.role, email: user.email } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('dangles_token');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: { name: req.user.name, role: req.user.role } });
});

// ---------- TEAMS ----------
app.get('/api/teams', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT t.id, t.name, t.roster, t.coach_id, u.name AS coach_name
    FROM teams t LEFT JOIN users u ON u.id = t.coach_id
    ORDER BY t.id
  `);
  res.json({ teams: rows });
});

app.post('/api/teams', auth, requireRole('president'), async (req, res) => {
  const { name } = req.body;
  const { rows } = await pool.query('INSERT INTO teams (name) VALUES ($1) RETURNING *', [name]);
  res.json({ team: rows[0] });
});

app.post('/api/teams/:id/coach', auth, requireRole('president'), async (req, res) => {
  const { coachEmail } = req.body;
  const { rows: userRows } = await pool.query('SELECT id, name FROM users WHERE email=$1 AND role=$2', [coachEmail.toLowerCase().trim(), 'coach']);
  if (!userRows[0]) return res.status(404).json({ error: 'No coach account found with that email' });
  await pool.query('UPDATE teams SET coach_id=$1 WHERE id=$2', [userRows[0].id, req.params.id]);
  res.json({ ok: true, coach: userRows[0].name });
});

async function canEditTeam(req, teamId) {
  if (req.user.role === 'president') return true;
  if (req.user.role !== 'coach') return false;
  const { rows } = await pool.query('SELECT coach_id FROM teams WHERE id=$1', [teamId]);
  return rows[0] && rows[0].coach_id === req.user.id;
}

app.post('/api/teams/:id/players', auth, async (req, res) => {
  if (!(await canEditTeam(req, req.params.id))) return res.status(403).json({ error: 'Only this team\'s coach or the president can edit this roster' });
  const { rows } = await pool.query('SELECT roster FROM teams WHERE id=$1', [req.params.id]);
  const roster = rows[0].roster;
  roster.push(req.body.name);
  await pool.query('UPDATE teams SET roster=$1 WHERE id=$2', [JSON.stringify(roster), req.params.id]);
  res.json({ roster });
});

app.delete('/api/teams/:id/players/:idx', auth, async (req, res) => {
  if (!(await canEditTeam(req, req.params.id))) return res.status(403).json({ error: 'Only this team\'s coach or the president can edit this roster' });
  const { rows } = await pool.query('SELECT roster FROM teams WHERE id=$1', [req.params.id]);
  const roster = rows[0].roster;
  roster.splice(req.params.idx, 1);
  await pool.query('UPDATE teams SET roster=$1 WHERE id=$2', [JSON.stringify(roster), req.params.id]);
  res.json({ roster });
});

// ---------- GAMES ----------
app.get('/api/games', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM games ORDER BY id');
  res.json({ games: rows });
});

app.post('/api/games', auth, requireRole('president'), async (req, res) => {
  const { division, home, away, dayTime, refCert } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO games (division, home, away, day_time, ref_cert, volunteers)
     VALUES ($1,$2,$3,$4,$5,'[{"task":"Timekeeper","filled":false,"name":null}]') RETURNING *`,
    [division || 'Division', home, away, dayTime, refCert || 'Level 1']
  );
  res.json({ game: rows[0] });
});

app.delete('/api/games/:id', auth, requireRole('president'), async (req, res) => {
  await pool.query('DELETE FROM games WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.post('/api/games/:id/claim-ref', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT ref_name FROM games WHERE id=$1', [req.params.id]);
  if (rows[0].ref_name) return res.status(409).json({ error: 'This game already has a ref' });
  await pool.query('UPDATE games SET ref_name=$1 WHERE id=$2', [req.user.name, req.params.id]);
  res.json({ ok: true });
});

app.post('/api/games/:id/volunteer/:idx/claim', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT volunteers FROM games WHERE id=$1', [req.params.id]);
  const volunteers = rows[0].volunteers;
  const slot = volunteers[req.params.idx];
  if (!slot || slot.filled) return res.status(409).json({ error: 'That slot is already taken' });
  slot.filled = true;
  slot.name = req.user.name;
  await pool.query('UPDATE games SET volunteers=$1 WHERE id=$2', [JSON.stringify(volunteers), req.params.id]);
  res.json({ ok: true });
});

app.get('*', (req, res) => {
res.sendFile(path.join(__dirname, 'index.html'));

initDb()
  .then(() => app.listen(PORT, () => console.log(`Dangles running on port ${PORT}`)))
  .catch(err => { console.error('DB init failed', err); process.exit(1); });
