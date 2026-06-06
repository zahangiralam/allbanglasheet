import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { getMemoryStore } from './storage.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || `${process.env.APP_BASE_URL || `http://localhost:${PORT}`}/api/auth/google/callback`;
const FRONTEND_DIR = path.resolve(__dirname, process.env.FRONTEND_DIR || '../zahangir_v7_auth');
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || 'true').toLowerCase() === 'true';

const googleClient = (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET)
  ? new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI)
  : null;
const store = getMemoryStore();

app.use(helmet());
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: true,
  legacyHeaders: false
}));

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'zahangir-v7-backend',
    auth: {
      bcrypt: true,
      jwt: true,
      googleOAuth: Boolean(googleClient)
    }
  });
});

function issueToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role, provider: user.provider },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function normalizeUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    provider: user.provider,
    avatar: user.avatar || null,
    createdAt: user.createdAt || new Date().toISOString()
  };
}

function requireAuth(req, res) {
  const token = req.cookies?.zv7_token;
  if (!token) {
    res.status(401).json({ message: 'Unauthorized' });
    return null;
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = findUserById(payload.sub);
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return null;
    }
    return user;
  } catch {
    res.status(401).json({ message: 'Unauthorized' });
    return null;
  }
}

function byUser(collection, userId) {
  return store[collection].filter(item => item.userId === userId);
}

function findUserByEmail(email) {
  return store.users.find(u => u.email.toLowerCase() === String(email || '').toLowerCase()) || null;
}

function findUserById(id) {
  return store.users.find(u => u.id === id) || null;
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'নাম, ইমেইল, এবং পাসওয়ার্ড প্রয়োজন' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ message: 'পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে' });
    }
    if (findUserByEmail(email)) {
      return res.status(409).json({ message: 'এই ইমেইলে ইতোমধ্যে অ্যাকাউন্ট আছে' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const isFirst = store.users.length === 0;

    const user = {
      id: randomUUID(),
      name: String(name).trim(),
      email: String(email).toLowerCase().trim(),
      passwordHash,
      provider: 'local',
      role: isFirst ? 'admin' : 'viewer',
      avatar: null,
      createdAt: new Date().toISOString()
    };

    store.users.push(user);

    const token = issueToken(user);
    res.cookie('zv7_token', token, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.status(201).json({
      token,
      user: normalizeUser(user)
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = findUserByEmail(email);
    if (!user || user.provider !== 'local') {
      return res.status(401).json({ message: 'ইমেইল বা পাসওয়ার্ড ভুল' });
    }
    const ok = await bcrypt.compare(String(password || ''), user.passwordHash || '');
    if (!ok) {
      return res.status(401).json({ message: 'ইমেইল বা পাসওয়ার্ড ভুল' });
    }

    const token = issueToken(user);
    res.cookie('zv7_token', token, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({
      token,
      user: normalizeUser(user)
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Login failed' });
  }
});

app.get('/api/auth/google', (_req, res) => {
  if (!googleClient) {
    return res.status(501).send('Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.');
  }

  const authUrl = googleClient.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: ['openid', 'email', 'profile'],
    redirect_uri: GOOGLE_REDIRECT_URI
  });

  return res.redirect(authUrl);
});

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    if (!googleClient) {
      return res.status(501).send('Google OAuth is not configured.');
    }

    const code = req.query.code;
    if (!code) return res.status(400).send('Missing OAuth code');

    const { tokens } = await googleClient.getToken({
      code: String(code),
      redirect_uri: GOOGLE_REDIRECT_URI
    });

    googleClient.setCredentials(tokens);

    const idToken = tokens.id_token;
    if (!idToken) return res.status(401).send('Google ID token missing');

    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const googleSub = payload.sub;
    const name = payload.name || payload.given_name || email?.split('@')[0] || 'Google User';
    const picture = payload.picture || null;

    let user = store.users.find(u => u.googleSub === googleSub || u.email === email) || null;
    if (!user) {
      const isFirst = store.users.length === 0;
      user = {
        id: randomUUID(),
        name,
        email,
        passwordHash: null,
        provider: 'google',
        googleSub,
        role: isFirst ? 'admin' : 'viewer',
        avatar: picture,
        createdAt: new Date().toISOString()
      };
      store.users.push(user);
    } else {
      user.name = name;
      user.avatar = picture || user.avatar;
      user.googleSub = googleSub;
      user.provider = 'google';
    }

    const token = issueToken(user);
    res.cookie('zv7_token', token, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.redirect('/');
  } catch (error) {
    console.error(error);
    return res.status(401).send('Google OAuth failed');
  }
});

app.post('/api/auth/google/verify', async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!googleClient) {
      return res.status(501).json({ message: 'GOOGLE_CLIENT_ID সেট করা নেই' });
    }
    if (!credential) {
      return res.status(400).json({ message: 'Google credential প্রয়োজন' });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const googleSub = payload.sub;
    const name = payload.name || payload.given_name || email?.split('@')[0] || 'Google User';
    const picture = payload.picture || null;

    let user = store.users.find(u => u.googleSub === googleSub || u.email === email) || null;
    if (!user) {
      const isFirst = store.users.length === 0;
      user = {
        id: randomUUID(),
        name,
        email,
        passwordHash: null,
        provider: 'google',
        googleSub,
        role: isFirst ? 'admin' : 'viewer',
        avatar: picture,
        createdAt: new Date().toISOString()
      };
      store.users.push(user);
    } else {
      user.name = name;
      user.avatar = picture || user.avatar;
      user.googleSub = googleSub;
      user.provider = 'google';
    }

    const token = issueToken(user);
    res.cookie('zv7_token', token, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({
      token,
      user: normalizeUser(user)
    });
  } catch (error) {
    console.error(error);
    return res.status(401).json({ message: 'Google token যাচাই ব্যর্থ হয়েছে' });
  }
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('zv7_token');
  return res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies?.zv7_token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = findUserById(payload.sub);
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ user: normalizeUser(user) });
  } catch {
    return res.status(401).json({ message: 'Unauthorized' });
  }
});


app.get('/api/todos', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  return res.json(byUser('todos', user.id));
});

app.post('/api/todos', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const { title, category, priority, dueDate, dueTime, note, done } = req.body || {};
  if (!title) return res.status(400).json({ message: 'Title is required' });
  const item = {
    id: randomUUID(),
    userId: user.id,
    title: String(title).trim(),
    category: category || 'সাধারণ',
    priority: priority || 'মাঝারি',
    dueDate: dueDate || null,
    dueTime: dueTime || null,
    note: note || '',
    done: !!done,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  store.todos.unshift(item);
  return res.status(201).json(item);
});

app.put('/api/todos/:id', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const item = store.todos.find(t => t.id === req.params.id && t.userId === user.id);
  if (!item) return res.status(404).json({ message: 'Todo not found' });
  const { title, category, priority, dueDate, dueTime, note, done } = req.body || {};
  if (title !== undefined) item.title = String(title).trim();
  if (category !== undefined) item.category = category;
  if (priority !== undefined) item.priority = priority;
  if (dueDate !== undefined) item.dueDate = dueDate;
  if (dueTime !== undefined) item.dueTime = dueTime;
  if (note !== undefined) item.note = note;
  if (done !== undefined) item.done = !!done;
  item.updatedAt = new Date().toISOString();
  return res.json(item);
});

app.delete('/api/todos/:id', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const idx = store.todos.findIndex(t => t.id === req.params.id && t.userId === user.id);
  if (idx === -1) return res.status(404).json({ message: 'Todo not found' });
  const [deleted] = store.todos.splice(idx, 1);
  return res.json(deleted);
});

app.get('/api/meetings', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  return res.json(byUser('meetings', user.id));
});

app.post('/api/meetings', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const { title, date, startTime, endTime, location, note, syncToCalendar } = req.body || {};
  if (!title || !date || !startTime) return res.status(400).json({ message: 'Title, date and time are required' });
  const item = {
    id: randomUUID(),
    userId: user.id,
    title: String(title).trim(),
    date,
    startTime,
    endTime: endTime || null,
    location: location || '',
    note: note || '',
    syncToCalendar: !!syncToCalendar,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  store.meetings.unshift(item);
  return res.status(201).json(item);
});

app.put('/api/meetings/:id', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const item = store.meetings.find(m => m.id === req.params.id && m.userId === user.id);
  if (!item) return res.status(404).json({ message: 'Meeting not found' });
  const { title, date, startTime, endTime, location, note, syncToCalendar } = req.body || {};
  if (title !== undefined) item.title = String(title).trim();
  if (date !== undefined) item.date = date;
  if (startTime !== undefined) item.startTime = startTime;
  if (endTime !== undefined) item.endTime = endTime;
  if (location !== undefined) item.location = location;
  if (note !== undefined) item.note = note;
  if (syncToCalendar !== undefined) item.syncToCalendar = !!syncToCalendar;
  item.updatedAt = new Date().toISOString();
  return res.json(item);
});

app.delete('/api/meetings/:id', (req, res) => {
  const user = requireAuth(req, res);
  if (!user) return;
  const idx = store.meetings.findIndex(m => m.id === req.params.id && m.userId === user.id);
  if (idx === -1) return res.status(404).json({ message: 'Meeting not found' });
  const [deleted] = store.meetings.splice(idx, 1);
  return res.json(deleted);
});


app.use(express.static(FRONTEND_DIR, {
  extensions: ['html']
}));

app.get('*', (_req, res) => {
  res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Zahangir backend running on http://localhost:${PORT}`);
});
