/**
 * 걷기 챌린지 백엔드 (Render 배포용 단일 파일)
 *
 * 환경변수:
 *   MONGODB_URI  — MongoDB Atlas 접속 문자열 (필수)
 *   JWT_SECRET   — 랜덤 32자 이상 (Render Blueprint가 자동 생성)
 *   CORS_ORIGIN  — Netlify 도메인 (예: https://my-site.netlify.app). '*' 도 가능
 *   PORT         — Render가 자동으로 설정. 직접 안 건드려도 됨
 */
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-' + crypto.randomBytes(16).toString('hex');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || process.env.ADMIN_EMAIL || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const isAdminEmail = (e) => ADMIN_EMAILS.includes(String(e || '').toLowerCase());

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI 환경변수가 필요합니다');
  process.exit(1);
}

const app = express();
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
}));
app.use(express.json({ limit: '5mb' })); // 사진은 base64로 받음

// ─────────── MONGOOSE 모델 ───────────
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  name: { type: String, required: true },
  syncToken: {
    type: String,
    default: () => crypto.randomBytes(16).toString('hex'),
    unique: true, index: true,
  },
  challenges: {
    single: { joined: { type: Boolean, default: false } },
    family: {
      joined: { type: Boolean, default: false },
      members: { type: Number, default: 0 },
    },
  },
  rankingChoice: { type: String, default: null },
  isActive: { type: Boolean, default: true },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', UserSchema);

const StepSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  date: { type: String, required: true }, // YYYY-MM-DD
  rawSteps: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now },
});
StepSchema.index({ userId: 1, date: 1 }, { unique: true });
const StepRecord = mongoose.model('StepRecord', StepSchema);

const PostSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  authorName: String,
  category: String,
  title: String,
  content: String,
  image: String, // base64 data URL or null
  likes: [String],
  comments: [{
    id: String,
    userId: String,
    authorName: String,
    text: String,
    createdAt: { type: Date, default: Date.now },
  }],
  createdAt: { type: Date, default: Date.now, index: true },
});
const Post = mongoose.model('Post', PostSchema);

// ─────────── 헬퍼 ───────────
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

function userToJSON(user) {
  return {
    id: user._id, email: user.email, name: user.name,
    syncToken: user.syncToken,
    challenges: user.challenges, rankingChoice: user.rankingChoice,
    isActive: user.isActive, createdAt: user.createdAt,
    role: user.role || 'user',
  };
}

function postToJSON(p, currentUserId) {
  return {
    id: p._id, userId: p.userId, authorName: p.authorName,
    category: p.category, title: p.title, content: p.content,
    image: p.image,
    likeCount: p.likes.length,
    likedByMe: currentUserId ? p.likes.includes(String(currentUserId)) : false,
    comments: p.comments,
    commentCount: p.comments.length,
    createdAt: p.createdAt,
  };
}

async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: '인증이 필요합니다' });
    const { id } = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(id);
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
    const exists = await User.findOne({ email: email.toLowerCase() });
    if (exists) return res.status(409).json({ message: '이미 가입된 이메일입니다' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      email: email.toLowerCase(), passwordHash, name,
      challenges: { single: { joined: false }, family: { joined: false, members: 0 } },
      role: isAdminEmail(email) ? 'admin' : 'user',
    });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, user: userToJSON(user) });
  } catch (e) { console.error(e); res.status(500).json({ message: '서버 오류' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: '이메일과 비밀번호를 입력하세요' });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: '이메일 또는 비밀번호가 올바르지 않습니다' });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, user: userToJSON(user) });
  } catch (e) { console.error(e); res.status(500).json({ message: '서버 오류' }); }
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json({ user: userToJSON(req.user) }));

// 동기화 토큰 재발급 (필요 시)
app.post('/api/auth/regenerate-sync-token', authMiddleware, async (req, res) => {
  req.user.syncToken = crypto.randomBytes(16).toString('hex');
  await req.user.save();
  res.json({ user: userToJSON(req.user) });
});

// STEPS
app.get('/api/steps/today', authMiddleware, async (req, res) => {
  const date = todayStr();
  const rec = await StepRecord.findOne({ userId: req.user._id, date });
  const raw = rec?.rawSteps || 0;
  const mult = calcMultiplier(req.user);
  res.json({ rawSteps: raw, recognizedSteps: Math.round(raw * mult), multiplier: mult });
});

// POST: $max 적용 — 더 큰 값만 갱신 (어뷰징/실수 방지)
app.post('/api/steps/today', authMiddleware, async (req, res) => {
  const value = Math.max(0, Math.floor(Number(req.body?.steps) || 0));
  const date = todayStr();
  const rec = await StepRecord.findOneAndUpdate(
    { userId: req.user._id, date },
    {
      $max: { rawSteps: value },
      $set: { updatedAt: new Date() },
      $setOnInsert: { userId: req.user._id, date },
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
  const mult = calcMultiplier(req.user);
  res.json({ rawSteps: rec.rawSteps, recognizedSteps: Math.round(rec.rawSteps * mult), multiplier: mult });
});

// PUT: 강제 덮어쓰기 (초기화/수정용)
app.put('/api/steps/today', authMiddleware, async (req, res) => {
  const value = Math.max(0, Math.floor(Number(req.body?.steps) || 0));
  const date = todayStr();
  const rec = await StepRecord.findOneAndUpdate(
    { userId: req.user._id, date },
    { $set: { rawSteps: value, updatedAt: new Date() } },
    { upsert: true, new: true }
  );
  const mult = calcMultiplier(req.user);
  res.json({ rawSteps: rec.rawSteps, recognizedSteps: Math.round(rec.rawSteps * mult), multiplier: mult });
});

// ── SYNC: iOS 단축어 / Android Tasker 등에서 호출하는 경량 엔드포인트 ──
// 인증: JWT 대신 사용자 syncToken (휴대폰 자동화에 JWT 갱신은 어려움)
// $max 적용: 작은 값으로 덮어쓰기 방지 (e.g. 자정 직후 0이 와도 안전)
app.post('/api/sync', async (req, res) => {
  try {
    const { token, steps } = req.body || {};
    if (!token) return res.status(400).json({ message: 'token이 필요합니다' });
    const user = await User.findOne({ syncToken: String(token) });
    if (!user) return res.status(401).json({ message: '잘못된 토큰' });
    const value = Math.max(0, Math.floor(Number(steps) || 0));
    const date = todayStr();
    const rec = await StepRecord.findOneAndUpdate(
      { userId: user._id, date },
      {
        $max: { rawSteps: value },
        $set: { updatedAt: new Date() },
        $setOnInsert: { userId: user._id, date },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.json({ ok: true, date, rawSteps: rec.rawSteps });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, message: '서버 오류' }); }
});

// CHALLENGES
app.post('/api/challenges/single/join', authMiddleware, async (req, res) => {
  req.user.challenges.single = { joined: true };
  await req.user.save();
  res.json({ user: userToJSON(req.user) });
});
app.post('/api/challenges/single/leave', authMiddleware, async (req, res) => {
  req.user.challenges.single = { joined: false };
  if (req.user.rankingChoice === 'single') {
    req.user.rankingChoice = req.user.challenges.family?.joined ? 'family' : null;
  }
  await req.user.save();
  res.json({ user: userToJSON(req.user) });
});
app.post('/api/challenges/family/join', authMiddleware, async (req, res) => {
  let { members } = req.body || {};
  members = Math.min(4, Math.max(1, parseInt(members, 10) || 1));
  req.user.challenges.family = { joined: true, members };
  if (!req.user.rankingChoice) req.user.rankingChoice = 'family';
  await req.user.save();
  res.json({ user: userToJSON(req.user) });
});
app.post('/api/challenges/family/leave', authMiddleware, async (req, res) => {
  req.user.challenges.family = { joined: false, members: 0 };
  if (req.user.rankingChoice === 'family') {
    req.user.rankingChoice = req.user.challenges.single?.joined ? 'single' : null;
  }
  await req.user.save();
  res.json({ user: userToJSON(req.user) });
});
app.post('/api/challenges/ranking-choice', authMiddleware, async (req, res) => {
  const { choice } = req.body || {};
  if (![null, 'single', 'family'].includes(choice)) return res.status(400).json({ message: '잘못된 선택' });
  req.user.rankingChoice = choice;
  await req.user.save();
  res.json({ user: userToJSON(req.user) });
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
  const stepAgg = await StepRecord.aggregate([
    { $match: { date: { $gte: from, $lte: today } } },
    { $group: { _id: '$userId', rawSteps: { $sum: '$rawSteps' } } },
  ]);
  const stepsByUser = Object.fromEntries(stepAgg.map(s => [String(s._id), s.rawSteps]));
  const users = await User.find({ isActive: true });
  const ranking = users
    .map(u => {
      const mult = calcMultiplier(u);
      if (mult === 0) return null;
      const raw = stepsByUser[String(u._id)] || 0;
      if (raw === 0) return null;
      const ch = u.challenges || {};
      let type = 'single';
      if (ch.single?.joined && ch.family?.joined) type = u.rankingChoice || 'single';
      else if (ch.family?.joined) type = 'family';
      return {
        userId: u._id, name: u.name, type,
        rawSteps: raw,
        recognizedSteps: Math.round(raw * mult),
        multiplier: mult,
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.recognizedSteps - a.recognizedSteps)
    .map((r, i) => ({ ...r, rank: i + 1 }));
  const me = ranking.find(r => String(r.userId) === String(req.user._id));
  res.json({ period, ranking, me: me || { eligible: false } });
});

// POSTS
app.get('/api/posts', authMiddleware, async (req, res) => {
  const { category } = req.query;
  const q = {};
  if (category && category !== '전체') q.category = category;
  const items = await Post.find(q).sort({ createdAt: -1 }).limit(100).lean();
  res.json({ items: items.map(p => postToJSON(p, req.user._id)) });
});
app.get('/api/posts/:id', authMiddleware, async (req, res) => {
  const p = await Post.findById(req.params.id).lean();
  if (!p) return res.status(404).json({ message: '게시글을 찾을 수 없습니다' });
  res.json(postToJSON(p, req.user._id));
});
app.post('/api/posts', authMiddleware, async (req, res) => {
  const { category, title, content, image } = req.body || {};
  if (!title || !content) return res.status(400).json({ message: '제목과 내용을 입력하세요' });
  const post = await Post.create({
    userId: req.user._id, authorName: req.user.name,
    category: category || '기타',
    title, content, image: image || null,
    likes: [], comments: [],
  });
  res.json(postToJSON(post.toObject(), req.user._id));
});
app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  const p = await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ message: '없음' });
  if (String(p.userId) !== String(req.user._id)) return res.status(403).json({ message: '본인 글만 삭제 가능' });
  await Post.deleteOne({ _id: p._id });
  res.json({ ok: true });
});
app.post('/api/posts/:id/like', authMiddleware, async (req, res) => {
  const p = await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ message: '없음' });
  const uid = String(req.user._id);
  const idx = p.likes.indexOf(uid);
  if (idx >= 0) p.likes.splice(idx, 1); else p.likes.push(uid);
  await p.save();
  res.json(postToJSON(p.toObject(), req.user._id));
});
app.post('/api/posts/:id/comments', authMiddleware, async (req, res) => {
  const text = (req.body?.text || '').trim();
  if (!text) return res.status(400).json({ message: '내용을 입력하세요' });
  const p = await Post.findById(req.params.id);
  if (!p) return res.status(404).json({ message: '없음' });
  p.comments.push({
    id: crypto.randomBytes(8).toString('hex'),
    userId: String(req.user._id),
    authorName: req.user.name,
    text, createdAt: new Date(),
  });
  await p.save();
  res.json(postToJSON(p.toObject(), req.user._id));
});
app.delete('/api/posts/:postId/comments/:commentId', authMiddleware, async (req, res) => {
  const p = await Post.findById(req.params.postId);
  if (!p) return res.status(404).json({ message: '없음' });
  const i = p.comments.findIndex(c => c.id === req.params.commentId);
  if (i < 0) return res.status(404).json({ message: '댓글 없음' });
  if (p.comments[i].userId !== String(req.user._id)) return res.status(403).json({ message: '본인 댓글만 삭제 가능' });
  p.comments.splice(i, 1);
  await p.save();
  res.json(postToJSON(p.toObject(), req.user._id));
});

// ─────────── ADMIN ROUTES ───────────
// 모든 회원 목록 + 오늘 걸음수
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 }).lean();
  const today = todayStr();
  const todayRecords = await StepRecord.find({ date: today }).lean();
  const stepsByUserId = Object.fromEntries(todayRecords.map(s => [String(s.userId), s.rawSteps]));
  res.json({
    users: users.map(u => ({
      id: u._id,
      email: u.email,
      name: u.name,
      role: u.role || 'user',
      isActive: u.isActive,
      createdAt: u.createdAt,
      challenges: u.challenges,
      rankingChoice: u.rankingChoice,
      todayRawSteps: stepsByUserId[String(u._id)] || 0,
    })),
  });
});

// 회원 정보 일부 수정 (활성/이름)
app.patch('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const u = await User.findById(req.params.id);
  if (!u) return res.status(404).json({ message: '회원을 찾을 수 없음' });
  const { isActive, name } = req.body || {};
  if (typeof isActive === 'boolean') u.isActive = isActive;
  if (typeof name === 'string' && name.trim()) u.name = name.trim();
  await u.save();
  res.json({ user: userToJSON(u) });
});

// 회원 완전 삭제 (걸음/게시글/댓글까지 정리)
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const u = await User.findById(req.params.id);
  if (!u) return res.status(404).json({ message: '회원을 찾을 수 없음' });
  if (u.role === 'admin') return res.status(403).json({ message: '관리자는 삭제할 수 없습니다' });
  if (String(u._id) === String(req.user._id)) return res.status(403).json({ message: '본인 계정은 삭제할 수 없습니다' });
  await StepRecord.deleteMany({ userId: u._id });
  await Post.deleteMany({ userId: u._id });
  // 다른 글의 댓글에서도 이 회원의 댓글 제거 (선택)
  await Post.updateMany(
    { 'comments.userId': String(u._id) },
    { $pull: { comments: { userId: String(u._id) } } }
  );
  await User.deleteOne({ _id: u._id });
  res.json({ ok: true });
});

// 회원의 오늘 걸음수 강제 변경 (관리자 정정용)
app.put('/api/admin/users/:id/steps', authMiddleware, adminMiddleware, async (req, res) => {
  const value = Math.max(0, Math.floor(Number(req.body?.steps) || 0));
  const date = req.body?.date || todayStr();
  await StepRecord.findOneAndUpdate(
    { userId: req.params.id, date },
    { $set: { rawSteps: value, updatedAt: new Date() }, $setOnInsert: { userId: req.params.id, date } },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
  res.json({ ok: true });
});

// 게시글 강제 삭제 (작성자 무관)
app.delete('/api/admin/posts/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await Post.deleteOne({ _id: req.params.id });
  res.json({ ok: true });
});

// 대시보드 통계
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  const today = todayStr();
  const [totalUsers, activeUsers, joinedSingle, joinedFamily, totalPosts, todayAgg, allAgg] = await Promise.all([
    User.countDocuments(),
    User.countDocuments({ isActive: true }),
    User.countDocuments({ 'challenges.single.joined': true }),
    User.countDocuments({ 'challenges.family.joined': true }),
    Post.countDocuments(),
    StepRecord.aggregate([{ $match: { date: today } }, { $group: { _id: null, total: { $sum: '$rawSteps' } } }]),
    StepRecord.aggregate([{ $group: { _id: null, total: { $sum: '$rawSteps' } } }]),
  ]);
  res.json({
    totalUsers, activeUsers, joinedSingle, joinedFamily, totalPosts,
    todayTotalSteps: todayAgg[0]?.total || 0,
    totalSteps: allAgg[0]?.total || 0,
  });
});

// ─────────── START ───────────
mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ MongoDB connected');
    // 환경변수에 등록된 이메일은 기존 가입 여부와 무관하게 관리자로 승격
    if (ADMIN_EMAILS.length > 0) {
      const r = await User.updateMany(
        { email: { $in: ADMIN_EMAILS } },
        { $set: { role: 'admin', isActive: true } }
      );
      console.log(`👑 Admin promotion check: ${r.modifiedCount} updated (admins: ${ADMIN_EMAILS.join(', ')})`);
    } else {
      console.warn('⚠️ ADMIN_EMAILS 환경변수가 비어있습니다. 관리자 계정이 없습니다.');
    }
    app.listen(PORT, () => console.log(`✅ Listening on port ${PORT}`));
  })
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });
