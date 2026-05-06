const express = require('express');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-' + crypto.randomBytes(16).toString('hex');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || process.env.ADMIN_EMAIL || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const isAdminEmail = (e) => ADMIN_EMAILS.includes(String(e || '').toLowerCase());

// 파이어베이스 초기화 (다운받은 JSON 키 사용)
if (!process.env.FIREBASE_JSON) {
  console.error('❌ FIREBASE_JSON 환경변수가 필요합니다 (다운받은 json 파일 내용 전체)');
  process.exit(1);
}
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

const app = express();
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()) }));
app.use(express.json({ limit: '5mb' }));

const todayStr = () => new Date().toISOString().slice(0, 10);

function calcMultiplier(user) {
  const ch = user.challenges || {};
  const single = ch.single?.joined;
  const family = ch.family?.joined;
  const familyMult = family ? 1 + (ch.family.members || 0) * 0.2 : 0;
  if (single && family) return user.rankingChoice === 'family' ? familyMult : 1.0;
  if (family) return familyMult;
  if (single) return 1.0;
  return 0;
}

function userToJSON(id, data) {
  return {
    id: id, email: data.email, name: data.name,
    syncToken: data.syncToken, challenges: data.challenges || {},
    rankingChoice: data.rankingChoice || null, isActive: data.isActive ?? true,
    createdAt: data.createdAt ? data.createdAt.toDate() : new Date(),
    role: data.role || 'user',
  };
}

async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: '인증이 필요합니다' });
    const { id } = jwt.verify(token, JWT_SECRET);
    const doc = await db.collection('users').doc(id).get();
    if (!doc.exists) return res.status(401).json({ message: '계정을 찾을 수 없습니다' });
    req.user = { id: doc.id, ...doc.data() };
    next();
  } catch (e) {
    res.status(401).json({ message: '인증 실패' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: '관리자 권한이 필요합니다' });
  }
  next();
}

app.get('/', (_, res) => res.json({ ok: true, name: 'walking-api-firebase' }));

// AUTH
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password || !name) return res.status(400).json({ message: '정보를 모두 입력하세요' });
    const snapshot = await db.collection('users').where('email', '==', email.toLowerCase()).get();
    if (!snapshot.empty) return res.status(409).json({ message: '이미 가입된 이메일입니다' });
    
    const passwordHash = await bcrypt.hash(password, 10);
    const syncToken = crypto.randomBytes(16).toString('hex');
    const newUser = {
      email: email.toLowerCase(), passwordHash, name, syncToken,
      challenges: { single: { joined: false }, family: { joined: false, members: 0 } },
      role: isAdminEmail(email) ? 'admin' : 'user',
      isActive: true, createdAt: admin.firestore.FieldValue.serverTimestamp()
    };
    
    const docRef = await db.collection('users').add(newUser);
    const token = jwt.sign({ id: docRef.id }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, user: userToJSON(docRef.id, newUser) });
  } catch (e) { res.status(500).json({ message: '서버 오류' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const snapshot = await db.collection('users').where('email', '==', email.toLowerCase()).limit(1).get();
    if (snapshot.empty) return res.status(401).json({ message: '정보가 올바르지 않습니다' });
    const doc = snapshot.docs[0];
    const user = doc.data();
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: '정보가 올바르지 않습니다' });
    const token = jwt.sign({ id: doc.id }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, user: userToJSON(doc.id, user) });
  } catch (e) { res.status(500).json({ message: '서버 오류' }); }
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json({ user: userToJSON(req.user.id, req.user) }));

// STEPS
app.get('/api/steps/today', authMiddleware, async (req, res) => {
  const date = todayStr();
  const docId = `${req.user.id}_${date}`;
  const doc = await db.collection('steps').doc(docId).get();
  const raw = doc.exists ? doc.data().rawSteps : 0;
  const mult = calcMultiplier(req.user);
  res.json({ rawSteps: raw, recognizedSteps: Math.round(raw * mult), multiplier: mult });
});

app.post('/api/steps/today', authMiddleware, async (req, res) => {
  const value = Math.max(0, Math.floor(Number(req.body?.steps) || 0));
  const date = todayStr();
  const docRef = db.collection('steps').doc(`${req.user.id}_${date}`);
  
  await db.runTransaction(async (t) => {
    const doc = await t.get(docRef);
    const current = doc.exists ? doc.data().rawSteps : 0;
    if (value > current) {
      t.set(docRef, { userId: req.user.id, date, rawSteps: value, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    }
  });
  
  const mult = calcMultiplier(req.user);
  res.json({ rawSteps: value, recognizedSteps: Math.round(value * mult), multiplier: mult });
});

app.post('/api/sync', async (req, res) => {
  try {
    const { token, steps } = req.body || {};
    const snapshot = await db.collection('users').where('syncToken', '==', String(token)).limit(1).get();
    if (snapshot.empty) return res.status(401).json({ message: '잘못된 토큰' });
    const userDoc = snapshot.docs[0];
    const value = Math.max(0, Math.floor(Number(steps) || 0));
    const date = todayStr();
    
    const docRef = db.collection('steps').doc(`${userDoc.id}_${date}`);
    await db.runTransaction(async (t) => {
      const doc = await t.get(docRef);
      const current = doc.exists ? doc.data().rawSteps : 0;
      if (value > current) {
        t.set(docRef, { userId: userDoc.id, date, rawSteps: value, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
      }
    });
    res.json({ ok: true, date, rawSteps: value });
  } catch (e) { res.status(500).json({ ok: false }); }
});

app.listen(PORT, () => console.log(`✅ Firebase Backend Listening on port ${PORT}`));
