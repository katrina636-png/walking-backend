/**
 * 걷기 챌린지 백엔드 (Firebase Firestore + Render 배포용)
 *
 * 환경변수:
 *   FIREBASE_SERVICE_ACCOUNT — Firebase 서비스 계정 키 JSON 전체 (한 줄로) (필수)
 *   JWT_SECRET   — 랜덤 32자 이상 (Render Blueprint가 자동 생성)
 *   CORS_ORIGIN  — Netlify 도메인 (예: https://my-site.netlify.app). '*' 도 가능
 *   ADMIN_EMAILS — 관리자로 지정할 이메일 (콤마로 구분)
 *   PORT         — Render가 자동으로 설정. 직접 안 건드려도 됨
 */
const express = require('express');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const PORT = process.env.PORT || 4000;
const FIREBASE_SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-' + crypto.randomBytes(16).toString('hex');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || process.env.ADMIN_EMAIL || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const isAdminEmail = (e) => ADMIN_EMAILS.includes(String(e || '').toLowerCase());

if (!FIREBASE_SERVICE_ACCOUNT) {
  console.error('❌ FIREBASE_SERVICE_ACCOUNT 환경변수가 필요합니다');
  process.exit(1);
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT);
} catch (e) {
  console.error('❌ FIREBASE_SERVICE_ACCOUNT JSON 파싱 실패:', e.message);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;
console.log(`✅ Firebase 연결됨 (project: ${serviceAccount.project_id})`);

const app = express();
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
}));
app.use(express.json({ limit: '5mb' }));

// ─────────── HELPERS ───────────
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

function userToJSON(u) {
  return {
    id: u.id, email: u.email, name: u.name,
    syncToken: u.syncToken,
    challenges: u.challenges, rankingChoice: u.rankingChoice,
    isActive: u.isActive, createdAt: u.createdAt,
    role: u.role || 'user',
  };
}

function postToJSON(p, currentUserId) {
  return {
    id: p.id, userId: p.userId, authorName: p.authorName,
    category: p.category, title: p.title, content: p.content,
    image: p.image,
    likeCount: (p.likes || []).length,
    likedByMe: currentUserId ? (p.likes || []).includes(String(currentUserId)) : false,
    comments: p.comments || [],
    commentCount: (p.comments || []).length,
    createdAt: p.createdAt,
  };
}

// Firestore 문서 → 일반 객체 변환 (Timestamp → Date 변환 포함)
function docToObj(doc) {
  if (!doc.exists) return null;
  const data = doc.data();
  for (const k in data) {
    if (data[k] && typeof data[k].toDate === 'function') {
      data[k] = data[k].toDate();
    } else if (Array.isArray(data[k])) {
      data[k] = data[k].map(item => {
        if (item && typeof item === 'object') {
          for (const ik in item) {
            if (item[ik] && typeof item[ik].toDate === 'function') {
              item[ik] = item[ik].toDate();
            }
          }
        }
        return item;
      });
    }
  }
  return { id: doc.id, ...data };
}

const stepDocId = (userId, date) => `${userId}_${date}`;

async function findUserByEmail(email) {
  const snap = await db.collection('users').where('email', '==', email.toLowerCase()).limit(1).get();
  return snap.empty ? null : docToObj(snap.docs[0]);
}
async function findUserById(id) {
  return docToObj(await db.collection('users').doc(id).get());
}
async function findUserBySyncToken(token) {
  const snap = await db.collection('users').where('syncToken', '==', token).limit(1).get();
  return snap.empty ? null : docToObj(snap.docs[0]);
}

async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: '인증이 필요합니다' });
    const { id } = jwt.verify(token, JWT_SECRET);
    const user = await findUserById(id);
    if (!user) return res.status(401).json({ message: '계정을 찾을 수 없습니다' });
    req.user = user;
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

// ─────────── ROUTES ───────────
app.get('/', (_, res) => res.json({ ok: true, name: 'walking-challenge-api', time: new Date() }));
app.get('/health', (_, res) => res.json({ ok: true }));

// AUTH
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password || !name) return res.status(400).json({ message: '이메일, 비밀번호, 이름을 입력하세요' });
    if (password.length < 4) return res.status(400).json({ message: '비밀번호는 4자 이상이어야 합니다' });
    const exists = await findUserByEmail(email);
    if (exists) return res.status(409).json({ message: '이미 가입된 이메일입니다' });
    const passwordHash = await bcrypt.hash(password, 10);
    const userData = {
      email: email.toLowerCase(),
      passwordHash, name,
      syncToken: crypto.randomBytes(16).toString('hex'),
      challenges: { single: { joined: false }, family: { joined: false, members: 0 } },
      rankingChoice: null,
      isActive: true,
      role: isAdminEmail(email) ? 'admin' : 'user',
      createdAt: new Date(),
    };
    const ref = await db.collection('users').add(userData);
    const user = { id: ref.id, ...userData };
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, user: userToJSON(user) });
  } catch (e) { console.error(e); res.status(500).json({ message: '서버 오류' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: '이메일과 비밀번호를 입력하세요' });
    const user = await findUserByEmail(email);
    if (!user) return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다' });
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, user: userToJSON(user) });
  } catch (e) { console.error(e); res.status(500).json({ message: '서버 오류' }); }
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json({ user: userToJSON(req.user) }));

app.post('/api/auth/regenerate-sync-token', authMiddleware, async (req, res) => {
  const newToken = crypto.randomBytes(16).toString('hex');
  await db.collection('users').doc(req.user.id).update({ syncToken: newToken });
  req.user.syncToken = newToken;
  res.json({ user: userToJSON(req.user) });
});

// STEPS
app.get('/api/steps/today', authMiddleware, async (req, res) => {
  const date = todayStr();
  const doc = await db.collection('stepRecords').doc(stepDocId(req.user.id, date)).get();
  const raw = doc.exists ? (doc.data().rawSteps || 0) : 0;
  const mult = calcMultiplier(req.user);
  res.json({ rawSteps: raw, recognizedSteps: Math.round(raw * mult), multiplier: mult });
});

// $max equivalent — 더 큰 값만 반영 (트랜잭션으로 race 방지)
app.post('/api/steps/today', authMiddleware, async (req, res) => {
  const value = Math.max(0, Math.floor(Number(req.body?.steps) || 0));
  const date = todayStr();
  const ref = db.collection('stepRecords').doc(stepDocId(req.user.id, date));
  let finalValue = value;
  await db.runTransaction(async (tx) => {
    const doc = await tx.get(ref);
    const current = doc.exists ? (doc.data().rawSteps || 0) : 0;
    finalValue = Math.max(current, value);
    tx.set(ref, {
      userId: req.user.id, date,
      rawSteps: finalValue, updatedAt: new Date(),
    }, { merge: true });
  });
  const mult = calcMultiplier(req.user);
  res.json({ rawSteps: finalValue, recognizedSteps: Math.round(finalValue * mult), multiplier: mult });
});

// 강제 덮어쓰기 (초기화/수정용)
app.put('/api/steps/today', authMiddleware, async (req, res) => {
  const value = Math.max(0, Math.floor(Number(req.body?.steps) || 0));
  const date = todayStr();
  await db.collection('stepRecords').doc(stepDocId(req.user.id, date)).set({
    userId: req.user.id, date, rawSteps: value, updatedAt: new Date(),
  }, { merge: true });
  const mult = calcMultiplier(req.user);
  res.json({ rawSteps: value, recognizedSteps: Math.round(value * mult), multiplier: mult });
});

// SYNC (syncToken 기반, JWT 안 씀)
app.post('/api/sync', async (req, res) => {
  try {
    const { token, steps } = req.body || {};
    if (!token) return res.status(400).json({ message: 'token이 필요합니다' });
    const user = await findUserBySyncToken(String(token));
    if (!user) return res.status(401).json({ message: '잘못된 토큰' });
    const value = Math.max(0, Math.floor(Number(steps) || 0));
    const date = todayStr();
    const ref = db.collection('stepRecords').doc(stepDocId(user.id, date));
    let finalValue = value;
    await db.runTransaction(async (tx) => {
      const doc = await tx.get(ref);
      const current = doc.exists ? (doc.data().rawSteps || 0) : 0;
      finalValue = Math.max(current, value);
      tx.set(ref, {
        userId: user.id, date, rawSteps: finalValue, updatedAt: new Date(),
      }, { merge: true });
    });
    res.json({ ok: true, date, rawSteps: finalValue });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, message: '서버 오류' }); }
});

// CHALLENGES
async function patchUser(id, updates) {
  await db.collection('users').doc(id).update(updates);
  return await findUserById(id);
}

app.post('/api/challenges/single/join', authMiddleware, async (req, res) => {
  const u = await patchUser(req.user.id, { 'challenges.single': { joined: true } });
  res.json({ user: userToJSON(u) });
});
app.post('/api/challenges/single/leave', authMiddleware, async (req, res) => {
  const updates = { 'challenges.single': { joined: false } };
  if (req.user.rankingChoice === 'single') {
    updates.rankingChoice = req.user.challenges.family?.joined ? 'family' : null;
  }
  const u = await patchUser(req.user.id, updates);
  res.json({ user: userToJSON(u) });
});
app.post('/api/challenges/family/join', authMiddleware, async (req, res) => {
  let { members } = req.body || {};
  members = Math.min(4, Math.max(1, parseInt(members, 10) || 1));
  const updates = { 'challenges.family': { joined: true, members } };
  if (!req.user.rankingChoice) updates.rankingChoice = 'family';
  const u = await patchUser(req.user.id, updates);
  res.json({ user: userToJSON(u) });
});
app.post('/api/challenges/family/leave', authMiddleware, async (req, res) => {
  const updates = { 'challenges.family': { joined: false, members: 0 } };
  if (req.user.rankingChoice === 'family') {
    updates.rankingChoice = req.user.challenges.single?.joined ? 'single' : null;
  }
  const u = await patchUser(req.user.id, updates);
  res.json({ user: userToJSON(u) });
});
app.post('/api/challenges/ranking-choice', authMiddleware, async (req, res) => {
  const { choice } = req.body || {};
  if (![null, 'single', 'family'].includes(choice)) return res.status(400).json({ message: '잘못된 선택' });
  const u = await patchUser(req.user.id, { rankingChoice: choice });
  res.json({ user: userToJSON(u) });
});

// RANKING
app.get('/api/ranking', authMiddleware, async (req, res) => {
  const period = req.query.period || 'daily';
  const today = todayStr();
  let from = today;
  if (period === 'weekly') {
    const d = new Date(); d.setDate(d.getDate() - 6);
    from = d.toISOString().slice(0, 10);
  } else if (period === 'monthly') {
    const d = new Date(); d.setDate(d.getDate() - 29);
    from = d.toISOString().slice(0, 10);
  }
  const stepsSnap = await db.collection('stepRecords')
    .where('date', '>=', from).where('date', '<=', today).get();
  const stepsByUser = {};
  stepsSnap.docs.forEach(d => {
    const data = d.data();
    stepsByUser[data.userId] = (stepsByUser[data.userId] || 0) + (data.rawSteps || 0);
  });
  const usersSnap = await db.collection('users').where('isActive', '==', true).get();
  const ranking = usersSnap.docs
    .map(d => docToObj(d))
    .map(u => {
      const mult = calcMultiplier(u);
      if (mult === 0) return null;
      const raw = stepsByUser[u.id] || 0;
      if (raw === 0) return null;
      const ch = u.challenges || {};
      let type = 'single';
      if (ch.single?.joined && ch.family?.joined) type = u.rankingChoice || 'single';
      else if (ch.family?.joined) type = 'family';
      return {
        userId: u.id, name: u.name, type,
        rawSteps: raw,
        recognizedSteps: Math.round(raw * mult),
        multiplier: mult,
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.recognizedSteps - a.recognizedSteps)
    .map((r, i) => ({ ...r, rank: i + 1 }));
  const me = ranking.find(r => String(r.userId) === String(req.user.id));
  res.json({ period, ranking, me: me || { eligible: false } });
});

// POSTS
app.get('/api/posts', authMiddleware, async (req, res) => {
  const { category } = req.query;
  let q = (category && category !== '전체')
    ? db.collection('posts').where('category', '==', category)
    : db.collection('posts');
  q = q.orderBy('createdAt', 'desc').limit(100);
  const snap = await q.get();
  const items = snap.docs.map(d => postToJSON(docToObj(d), req.user.id));
  res.json({ items });
});

app.get('/api/posts/:id', authMiddleware, async (req, res) => {
  const doc = await db.collection('posts').doc(req.params.id).get();
  if (!doc.exists) return res.status(404).json({ message: '게시글을 찾을 수 없습니다' });
  res.json(postToJSON(docToObj(doc), req.user.id));
});

app.post('/api/posts', authMiddleware, async (req, res) => {
  const { category, title, content, image } = req.body || {};
  if (!title || !content) return res.status(400).json({ message: '제목과 내용을 입력하세요' });
  const data = {
    userId: req.user.id, authorName: req.user.name,
    category: category || '기타',
    title, content, image: image || null,
    likes: [], comments: [],
    createdAt: new Date(),
  };
  const ref = await db.collection('posts').add(data);
  res.json(postToJSON({ id: ref.id, ...data }, req.user.id));
});

app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  const ref = db.collection('posts').doc(req.params.id);
  const doc = await ref.get();
  if (!doc.exists) return res.status(404).json({ message: '없음' });
  if (String(doc.data().userId) !== String(req.user.id)) return res.status(403).json({ message: '본인 글만 삭제 가능' });
  await ref.delete();
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', authMiddleware, async (req, res) => {
  const ref = db.collection('posts').doc(req.params.id);
  const updated = await db.runTransaction(async (tx) => {
    const doc = await tx.get(ref);
    if (!doc.exists) throw new Error('없음');
    const likes = [...(doc.data().likes || [])];
    const uid = String(req.user.id);
    const idx = likes.indexOf(uid);
    if (idx >= 0) likes.splice(idx, 1); else likes.push(uid);
    tx.update(ref, { likes });
    return { ...doc.data(), id: doc.id, likes };
  });
  res.json(postToJSON(updated, req.user.id));
});

app.post('/api/posts/:id/comments', authMiddleware, async (req, res) => {
  const text = (req.body?.text || '').trim();
  if (!text) return res.status(400).json({ message: '내용을 입력하세요' });
  const ref = db.collection('posts').doc(req.params.id);
  const newComment = {
    id: crypto.randomBytes(8).toString('hex'),
    userId: String(req.user.id),
    authorName: req.user.name,
    text, createdAt: new Date(),
  };
  await ref.update({ comments: FieldValue.arrayUnion(newComment) });
  const doc = await ref.get();
  res.json(postToJSON(docToObj(doc), req.user.id));
});

app.delete('/api/posts/:postId/comments/:commentId', authMiddleware, async (req, res) => {
  const ref = db.collection('posts').doc(req.params.postId);
  const updated = await db.runTransaction(async (tx) => {
    const doc = await tx.get(ref);
    if (!doc.exists) throw new Error('없음');
    const comments = [...(doc.data().comments || [])];
    const i = comments.findIndex(c => c.id === req.params.commentId);
    if (i < 0) throw new Error('댓글 없음');
    if (comments[i].userId !== String(req.user.id)) throw new Error('본인 댓글만 삭제 가능');
    comments.splice(i, 1);
    tx.update(ref, { comments });
    return { ...doc.data(), id: doc.id, comments };
  });
  res.json(postToJSON(updated, req.user.id));
});

// ─────────── ADMIN ROUTES ───────────
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const usersSnap = await db.collection('users').orderBy('createdAt', 'desc').get();
  const today = todayStr();
  const todaySnap = await db.collection('stepRecords').where('date', '==', today).get();
  const stepsByUserId = {};
  todaySnap.docs.forEach(d => { stepsByUserId[d.data().userId] = d.data().rawSteps; });
  res.json({
    users: usersSnap.docs.map(d => {
      const u = docToObj(d);
      return {
        id: u.id, email: u.email, name: u.name,
        role: u.role || 'user', isActive: u.isActive, createdAt: u.createdAt,
        challenges: u.challenges, rankingChoice: u.rankingChoice,
        todayRawSteps: stepsByUserId[u.id] || 0,
      };
    }),
  });
});

app.patch('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const ref = db.collection('users').doc(req.params.id);
  const doc = await ref.get();
  if (!doc.exists) return res.status(404).json({ message: '회원을 찾을 수 없음' });
  const updates = {};
  const { isActive, name } = req.body || {};
  if (typeof isActive === 'boolean') updates.isActive = isActive;
  if (typeof name === 'string' && name.trim()) updates.name = name.trim();
  if (Object.keys(updates).length) await ref.update(updates);
  const u = await findUserById(req.params.id);
  res.json({ user: userToJSON(u) });
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const ref = db.collection('users').doc(req.params.id);
  const doc = await ref.get();
  if (!doc.exists) return res.status(404).json({ message: '회원을 찾을 수 없음' });
  const u = doc.data();
  if (u.role === 'admin') return res.status(403).json({ message: '관리자는 삭제할 수 없습니다' });
  if (req.params.id === req.user.id) return res.status(403).json({ message: '본인 계정은 삭제할 수 없습니다' });
  // 본인 걸음 기록 + 게시글 일괄 삭제
  const [stepsSnap, postsSnap] = await Promise.all([
    db.collection('stepRecords').where('userId', '==', req.params.id).get(),
    db.collection('posts').where('userId', '==', req.params.id).get(),
  ]);
  const batch = db.batch();
  stepsSnap.docs.forEach(d => batch.delete(d.ref));
  postsSnap.docs.forEach(d => batch.delete(d.ref));
  batch.delete(ref);
  await batch.commit();
  res.json({ ok: true });
});

app.put('/api/admin/users/:id/steps', authMiddleware, adminMiddleware, async (req, res) => {
  const value = Math.max(0, Math.floor(Number(req.body?.steps) || 0));
  const date = req.body?.date || todayStr();
  await db.collection('stepRecords').doc(stepDocId(req.params.id, date)).set({
    userId: req.params.id, date, rawSteps: value, updatedAt: new Date(),
  }, { merge: true });
  res.json({ ok: true });
});

app.delete('/api/admin/posts/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await db.collection('posts').doc(req.params.id).delete();
  res.json({ ok: true });
});

app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  const today = todayStr();
  const [usersSnap, postsSnap, todaySteps, allSteps] = await Promise.all([
    db.collection('users').get(),
    db.collection('posts').get(),
    db.collection('stepRecords').where('date', '==', today).get(),
    db.collection('stepRecords').get(),
  ]);
  let totalUsers = 0, activeUsers = 0, joinedSingle = 0, joinedFamily = 0;
  usersSnap.docs.forEach(d => {
    const u = d.data();
    totalUsers++;
    if (u.isActive) activeUsers++;
    if (u.challenges?.single?.joined) joinedSingle++;
    if (u.challenges?.family?.joined) joinedFamily++;
  });
  const todayTotalSteps = todaySteps.docs.reduce((s, d) => s + (d.data().rawSteps || 0), 0);
  const totalSteps = allSteps.docs.reduce((s, d) => s + (d.data().rawSteps || 0), 0);
  res.json({
    totalUsers, activeUsers, joinedSingle, joinedFamily,
    totalPosts: postsSnap.size,
    todayTotalSteps, totalSteps,
  });
});

// ─────────── START ───────────
async function start() {
  // ADMIN_EMAILS에 등록된 이메일을 자동으로 관리자로 승격
  if (ADMIN_EMAILS.length > 0) {
    try {
      const chunks = [];
      for (let i = 0; i < ADMIN_EMAILS.length; i += 30) {
        chunks.push(ADMIN_EMAILS.slice(i, i + 30));
      }
      let count = 0;
      for (const chunk of chunks) {
        const snap = await db.collection('users').where('email', 'in', chunk).get();
        if (!snap.empty) {
          const batch = db.batch();
          snap.docs.forEach(d => {
            batch.update(d.ref, { role: 'admin', isActive: true });
            count++;
          });
          await batch.commit();
        }
      }
      console.log(`👑 관리자 자동 승격: ${count}명 (대상: ${ADMIN_EMAILS.join(', ')})`);
    } catch (e) {
      console.warn('⚠️ 관리자 승격 중 오류:', e.message);
    }
  } else {
    console.warn('⚠️ ADMIN_EMAILS 환경변수가 비어있습니다. 관리자 계정이 없습니다.');
  }
  app.listen(PORT, () => console.log(`✅ Listening on port ${PORT}`));
}

start().catch(err => {
  console.error('❌ 시작 실패:', err);
  process.exit(1);
});
