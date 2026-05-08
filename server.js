require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 11000;

// ═══════════════════════════════════════════
// ENVIRONMENT VALIDATION
// ═══════════════════════════════════════════
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI environment variable is required');
  process.exit(1);
}

const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const NODE_ENV = process.env.NODE_ENV || 'development';

// ═══════════════════════════════════════════
// SECURITY MIDDLEWARE
// ═══════════════════════════════════════════
/*
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
    }
  },
  crossOriginEmbedderPolicy: false
}));
*/
/*
app.use(cors({
  origin: process.env.CORS_ORIGIN || true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));
*/
app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

// ═══════════════════════════════════════════
// SESSION CONFIGURATION
// ═══════════════════════════════════════════
app.use(session({
  secret: SESSION_SECRET,
  name: 'kdxfb_sid',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    ttl: 7 * 24 * 60 * 60,
    autoRemove: 'native',
    crypto: {
      secret: process.env.STORE_SECRET || crypto.randomBytes(32).toString('hex')
    }
  }),
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

// ═══════════════════════════════════════════
// RATE LIMITING
// ═══════════════════════════════════════════
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, error: 'Too many requests, please try again later' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, error: 'Too many authentication attempts' }
});

app.use('/api', apiLimiter);
app.use('/api/auth', authLimiter);

// ═══════════════════════════════════════════
// DATABASE CONNECTION
// ═══════════════════════════════════════════
async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10
    });
    console.log('[DB] Connected successfully');
  } catch (e) {
    console.error('[DB] Connection error:', e.message);
    setTimeout(connectDB, 5000);
  }
}
connectDB();

mongoose.connection.on('error', (err) => {
  console.error('[DB] Runtime error:', err);
});

// ═══════════════════════════════════════════
// DATABASE SCHEMAS
// ═══════════════════════════════════════════
const KdxfUser = mongoose.model('KdxfUser', new mongoose.Schema({
  username: { type: String, unique: true, required: true, lowercase: true, trim: true, index: true },
  password: { type: String, required: true, select: false },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date,
  agreedToS: { type: Boolean, default: false },
  role: { type: String, default: 'user', enum: ['user', 'admin'] }
}));

const FbAccount = mongoose.model('FbAccount', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'KdxfUser', required: true, index: true },
  fbUserId: { type: String, required: true },
  fbName: String,
  accessToken: { type: String, select: false },
  cookies: { type: String, select: false },
  deviceId: { type: String, select: false },
  machineId: { type: String, select: false },
  isActive: { type: Boolean, default: true },
  inPool: { type: Boolean, default: true },
  addedToPoolAt: { type: Date, default: Date.now },
  lastUsed: Date,
  actionsDone: { type: Number, default: 0 },
  actionsReceived: { type: Number, default: 0 },
  consecutiveFails: { type: Number, default: 0 },
  lastChecked: Date
}));

const Cooldown = mongoose.model('Cooldown', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'KdxfUser', required: true, index: true },
  accountId: { type: mongoose.Schema.Types.ObjectId, ref: 'FbAccount', required: true },
  lastFollow: Date,
  lastReaction: Date,
  lastShare: Date
}));

const Process = mongoose.model('Process', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'KdxfUser', required: true, index: true },
  type: { type: String, enum: ['follow', 'reaction', 'share'], required: true },
  target: String,
  targetId: String,
  status: { type: String, enum: ['running', 'paused', 'stopped', 'completed'], default: 'running' },
  totalCount: Number,
  successCount: { type: Number, default: 0 },
  failedCount: { type: Number, default: 0 },
  accounts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'FbAccount' }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}));

const Analytics = mongoose.model('Analytics', new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'KdxfUser', required: true, index: true },
  date: { type: Date, default: Date.now },
  type: String,
  success: Number,
  failed: Number,
  accountId: String
}));

// ═══════════════════════════════════════════
// ENCRYPTION HELPERS
// ═══════════════════════════════════════════
function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const key = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
  try {
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const key = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(parts.join(':'), 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    return null;
  }
}

// ═══════════════════════════════════════════
// FACEBOOK HELPERS
// ═══════════════════════════════════════════
async function extractID(url) {
  try {
    const r = await axios.post('https://id.traodoisub.com/api.php', 
      new URLSearchParams({ link: url }), {
        headers: { 
          'Content-Type': 'application/x-www-form-urlencoded', 
          'User-Agent': 'Mozilla/5.0' 
        },
        timeout: 10000
      }
    );
    return r.data.id || null;
  } catch (e) {
    return null;
  }
}

async function extractPostID(url) {
  const clean = url.split(/[?#]/)[0].replace(/\/$/, '');
  const patterns = [
    { regex: /facebook\.com\/groups\/(\d+|[^\/]+)\/(?:permalink|posts)\/(\d+)/i, 
      handler: async ([, g, p]) => /^\d+$/.test(g) ? `${g}_${p}` : ((await extractID(`https://facebook.com/groups/${g}`)) ? `${await extractID(`https://facebook.com/groups/${g}`)}_${p}` : p) },
    { regex: /facebook\.com\/(\d+|[^\/]+)\/(posts|videos|photos)\/(\d+|pfbid\w+)/i, 
      handler: async ([, id, , p]) => /^\d+$/.test(id) ? `${id}_${p}` : ((await extractID(`https://facebook.com/${id}`)) ? `${await extractID(`https://facebook.com/${id}`)}_${p}` : p) },
    { regex: /facebook\.com\/photo\?.*fbid=(\d+)/i, 
      handler: async ([, p]) => (await extractID(clean)) ? `${await extractID(clean)}_${p}` : p },
    { regex: /\/(\d+)$/i, handler: ([, p]) => p },
    { regex: /\/(pfbid\w+)$/i, handler: ([, p]) => p }
  ];
  
  for (const { regex, handler } of patterns) {
    const m = clean.match(regex);
    if (m) try { return await handler(m); } catch {}
  }
  return null;
}

function randHex(l) { 
  return Array.from({ length: l }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join(''); 
}

// ═══════════════════════════════════════════
// GET POOL STATS (GLOBAL)
// ═══════════════════════════════════════════
async function getGlobalPoolStats() {
  try {
    const totalAccounts = await FbAccount.countDocuments({ isActive: true, inPool: true, consecutiveFails: { $lt: 3 } });
    return totalAccounts;
  } catch (e) {
    return 0;
  }
}

// ═══════════════════════════════════════════
// COOLDOWN CHECK (30 MINUTES PER ACCOUNT)
// ═══════════════════════════════════════════
async function checkCooldown(accountId, toolType) {
  let cooldown = await Cooldown.findOne({ accountId });
  const now = new Date();
  const COOLDOWN_MINUTES = 30;
  
  if (!cooldown) {
    // Get the account to find owner
    const account = await FbAccount.findById(accountId);
    if (!account) return false;
    
    await Cooldown.create({ 
      owner: account.owner,
      accountId, 
      [toolType]: now 
    });
    return false;
  }
  
  const lastUsed = cooldown[toolType] || new Date(0);
  const diffMinutes = (now - lastUsed) / (1000 * 60);
  
  if (diffMinutes < COOLDOWN_MINUTES) {
    return Math.ceil(COOLDOWN_MINUTES - diffMinutes);
  }
  
  cooldown[toolType] = now;
  await cooldown.save();
  return false;
}

// ═══════════════════════════════════════════
// ACCOUNT VERIFICATION
// ═══════════════════════════════════════════
async function verifyAccount(account) {
  try {
    const response = await axios.get('https://graph.facebook.com/me', {
      params: { access_token: account.accessToken },
      headers: { 'User-Agent': 'Mozilla/5.0' },
      timeout: 10000
    });
    
    if (response.data && response.data.id) {
      account.isActive = true;
      account.consecutiveFails = 0;
      account.lastChecked = new Date();
      await account.save();
      return true;
    }
  } catch (e) {
    account.consecutiveFails = (account.consecutiveFails || 0) + 1;
    account.lastChecked = new Date();
    
    if (account.consecutiveFails >= 3) {
      account.isActive = false;
      account.inPool = false;
    }
    await account.save();
    return false;
  }
}

// ═══════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════
const auth = async (req, res, next) => {
  try {
    if (req.session.kdxfUserId) {
      const u = await KdxfUser.findById(req.session.kdxfUserId);
      if (u) { req.kdxfUser = u; return next(); }
    }
    
    const h = req.headers.authorization;
    if (h && h.startsWith('Bearer ')) {
      const d = decrypt(h.split(' ')[1]);
      if (d) {
        const [uid] = d.split(':');
        const u = await KdxfUser.findById(uid);
        if (u) {
          req.session.kdxfUserId = u._id;
          req.kdxfUser = u;
          return next();
        }
      }
    }
    
    res.status(401).json({ 
      success: false, 
      error: 'Authentication required', 
      code: 'AUTH_REQUIRED' 
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Authentication failed' });
  }
};

// Hash password before save
KdxfUser.schema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  next();
});

// ═══════════════════════════════════════════
// API ROUTES
// ═══════════════════════════════════════════

// Health check (includes global pool stats)
app.get('/api/health', async (req, res) => {
  const poolSize = await getGlobalPoolStats();
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    globalPool: poolSize
  });
});

// ═══════ AUTH ROUTES ═══════

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password required' });
    }
    
    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ success: false, error: 'Username must be 3-30 characters' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }
    
    const exists = await KdxfUser.findOne({ username: username.toLowerCase() });
    if (exists) {
      return res.status(409).json({ success: false, error: 'Username already taken' });
    }
    
    const user = new KdxfUser({
      username: username.toLowerCase(),
      password,
      agreedToS: req.body.agreedToS || false
    });
    
    await user.save();
    
    const token = encrypt(`${user._id}:${uuidv4()}`);
    req.session.kdxfUserId = user._id;
    
    res.json({
      success: true,
      userId: user._id,
      username: user.username,
      token
    });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password required' });
    }
    
    const user = await KdxfUser.findOne({ username: username.toLowerCase() }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    user.lastLogin = new Date();
    await user.save();
    
    const token = encrypt(`${user._id}:${uuidv4()}`);
    req.session.kdxfUserId = user._id;
    
    res.json({
      success: true,
      userId: user._id,
      username: user.username,
      token
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.post('/api/auth/logout', auth, async (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Logout failed' });
    }
    res.clearCookie('kdxfb_sid');
    res.json({ success: true, message: 'Disconnected successfully' });
  });
});

app.get('/api/auth/session', auth, async (req, res) => {
  try {
    const accounts = await FbAccount.find({ owner: req.kdxfUser._id });
    
    // Clean dead accounts in background
    const deadAccounts = accounts.filter(a => !a.isActive || a.consecutiveFails >= 3);
    if (deadAccounts.length > 0) {
      await FbAccount.deleteMany({ 
        _id: { $in: deadAccounts.map(a => a._id) },
        owner: req.kdxfUser._id
      });
    }
    
    const activeAccounts = accounts.filter(a => a.isActive && a.consecutiveFails < 3);
    
    // Get global pool stats
    const globalPoolSize = await getGlobalPoolStats();
    
    // Calculate today's actions for this user
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayActions = await Analytics.aggregate([
      {
        $match: {
          owner: new mongoose.Types.ObjectId(req.kdxfUser._id),
          date: { $gte: today }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: { $add: ['$success', '$failed'] } }
        }
      }
    ]);
    
    const todayTotal = todayActions.length > 0 ? todayActions[0].total : 0;
    
    res.json({
      success: true,
      user: {
        id: req.kdxfUser._id,
        username: req.kdxfUser.username,
        role: req.kdxfUser.role
      },
      fbAccounts: activeAccounts.map(a => ({
        id: a._id,
        fbUserId: a.fbUserId,
        fbName: a.fbName,
        isActive: a.isActive,
        inPool: a.inPool,
        actionsDone: a.actionsDone,
        actionsReceived: a.actionsReceived
      })),
      stats: {
        totalAccounts: activeAccounts.length,
        activeAccounts: activeAccounts.filter(a => a.isActive).length,
        poolAccounts: activeAccounts.filter(a => a.inPool && a.isActive).length,
        todayActions: todayTotal,
        globalPool: globalPoolSize
      }
    });
  } catch (e) {
    console.error('Session error:', e);
    res.status(500).json({ success: false, error: 'Failed to fetch session' });
  }
});

// ═══════ FB ACCOUNTS ROUTES ═══════

app.post('/api/accounts/add', auth, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password required' });
    }
    
    const deviceId = uuidv4();
    const machineId = randHex(22);
    const params = new URLSearchParams({
      adid: randHex(16),
      email,
      password,
      format: 'json',
      device_id: deviceId,
      cpl: 'true',
      family_device_id: deviceId,
      locale: 'en_US',
      client_country_code: 'US',
      credentials_type: 'device_based_login_password',
      generate_session_cookies: '1',
      generate_analytics_claim: '1',
      generate_machine_id: '1',
      machine_id: machineId,
      fb_api_req_friendly_name: 'authenticate',
      fb_api_caller_class: 'com.facebook.account.login.protocol.Fb4aAuthHandler',
      api_key: '882a8490361da98702bf97a021ddc14d',
      access_token: '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
    });
    
    const fbRes = await axios.get(
      `https://b-api.facebook.com/method/auth.login?${params}`,
      {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        timeout: 15000
      }
    );
    
    if (!fbRes.data.session_cookies) {
      throw new Error(fbRes.data.error_msg || 'Failed to authenticate with Facebook');
    }
    
    const cookies = fbRes.data.session_cookies
      .map(c => `${c.name}=${c.value}`)
      .join('; ');
    
    const profile = await axios.get(
      `https://graph.facebook.com/me?fields=name&access_token=${fbRes.data.access_token}`,
      {
        headers: { 'Cookie': cookies, 'User-Agent': 'Mozilla/5.0' },
        timeout: 10000
      }
    );
    
    // Check if account already exists for THIS user (prevent duplicates per user)
    const existing = await FbAccount.findOne({
      owner: req.kdxfUser._id,
      fbUserId: fbRes.data.uid
    }).select('+accessToken +cookies');
    
    if (existing) {
      existing.accessToken = fbRes.data.access_token;
      existing.cookies = cookies;
      existing.isActive = true;
      existing.inPool = true;
      existing.consecutiveFails = 0;
      existing.fbName = profile.data.name || 'Facebook User';
      existing.lastUsed = new Date();
      await existing.save();
      
      return res.json({
        success: true,
        account: {
          id: existing._id,
          fbUserId: existing.fbUserId,
          fbName: existing.fbName,
          isActive: true,
          inPool: true,
          actionsDone: existing.actionsDone,
          actionsReceived: existing.actionsReceived
        }
      });
    }
    
    // Create new account
    const acc = new FbAccount({
      owner: req.kdxfUser._id,
      fbUserId: fbRes.data.uid,
      fbName: profile.data.name || 'Facebook User',
      accessToken: fbRes.data.access_token,
      cookies,
      deviceId,
      machineId,
      isActive: true,
      inPool: true,
      lastUsed: new Date()
    });
    
    await acc.save();
    
    res.json({
      success: true,
      account: {
        id: acc._id,
        fbUserId: acc.fbUserId,
        fbName: acc.fbName,
        isActive: true,
        inPool: true,
        actionsDone: 0,
        actionsReceived: 0
      }
    });
    
  } catch (e) {
    console.error('Add account error:', e);
    res.status(500).json({
      success: false,
      error: e.response?.data?.error_msg || e.message || 'Failed to add account'
    });
  }
});

app.put('/api/accounts/:id/toggle-pool', auth, async (req, res) => {
  try {
    const acc = await FbAccount.findOne({ _id: req.params.id, owner: req.kdxfUser._id });
    if (!acc) {
      return res.status(404).json({ success: false, error: 'Account not found' });
    }
    
    acc.inPool = !acc.inPool;
    if (acc.inPool) {
      acc.addedToPoolAt = new Date();
    }
    await acc.save();
    
    res.json({
      success: true,
      account: { id: acc._id, inPool: acc.inPool }
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to toggle pool status' });
  }
});

app.delete('/api/accounts/:id', auth, async (req, res) => {
  try {
    await FbAccount.findOneAndDelete({ _id: req.params.id, owner: req.kdxfUser._id });
    await Cooldown.deleteMany({ accountId: req.params.id });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to remove account' });
  }
});

// ═══════ TOOLS ROUTES ═══════

app.post('/api/tools/follow', auth, async (req, res) => {
  try {
    const { link, limit = 10 } = req.body;
    
    if (!link) {
      return res.status(400).json({ success: false, error: 'Target URL required' });
    }
    
    // Check if user has at least one account
    const userHasAccounts = await FbAccount.countDocuments({ 
      owner: req.kdxfUser._id, 
      isActive: true 
    });
    
    if (userHasAccounts === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'You must add at least one Facebook account to use this tool' 
      });
    }
    
    const targetId = await extractID(link);
    if (!targetId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook URL' });
    }
    
    // Get pool accounts (excluding own accounts - use others' accounts)
    const pool = await FbAccount.find({
      owner: { $ne: req.kdxfUser._id },
      isActive: true,
      inPool: true,
      consecutiveFails: { $lt: 3 }
    }).select('+accessToken +cookies').limit(parseInt(limit));
    
    if (!pool.length) {
      return res.status(400).json({ 
        success: false, 
        error: 'No active accounts available in global pool. Wait for other users to add accounts.' 
      });
    }
    
    // Filter accounts by cooldown
    const availableAccounts = [];
    for (const acc of pool) {
      const cooldown = await checkCooldown(acc._id, 'lastFollow');
      if (!cooldown) {
        availableAccounts.push(acc);
      }
    }
    
    if (!availableAccounts.length) {
      const cooldowns = await Promise.all(pool.map(async acc => {
        const cd = await checkCooldown(acc._id, 'lastFollow');
        return cd;
      }));
      const minCooldown = Math.min(...cooldowns.filter(Boolean));
      return res.status(429).json({
        success: false,
        cooldown: minCooldown,
        message: `All pool accounts on cooldown. Wait ${minCooldown} minutes.`
      });
    }
    
    const proc = new Process({
      owner: req.kdxfUser._id,
      type: 'follow',
      target: link,
      targetId,
      totalCount: availableAccounts.length,
      status: 'running',
      accounts: availableAccounts.map(a => a._id)
    });
    await proc.save();
    
    let ok = 0, failed = 0;
    
    await Promise.all(availableAccounts.map(async (acc) => {
      try {
        await axios.post(
          `https://graph.facebook.com/v18.0/${targetId}/subscribers`,
          {},
          {
            headers: {
              'Authorization': `Bearer ${acc.accessToken}`,
              'Cookie': acc.cookies,
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 10000
          }
        );
        
        ok++;
        acc.actionsReceived = (acc.actionsReceived || 0) + 1;
        acc.lastUsed = new Date();
        acc.consecutiveFails = 0;
        await acc.save();
        
      } catch (e) {
        failed++;
        acc.consecutiveFails = (acc.consecutiveFails || 0) + 1;
        
        if (e.response?.status === 401 || e.response?.status === 403) {
          acc.isActive = false;
          acc.inPool = false;
        }
        
        if (acc.consecutiveFails >= 3) {
          acc.isActive = false;
          acc.inPool = false;
        }
        
        await acc.save();
      }
    }));
    
    proc.successCount = ok;
    proc.failedCount = failed;
    proc.status = 'completed';
    proc.updatedAt = new Date();
    await proc.save();
    
    // Track analytics for the requesting user
    await Analytics.create({
      owner: req.kdxfUser._id,
      type: 'follow',
      success: ok,
      failed,
      accountId: targetId
    });
    
    // Clean dead accounts globally
    await FbAccount.deleteMany({
      isActive: false,
      consecutiveFails: { $gte: 3 }
    });
    
    res.json({
      success: true,
      processId: proc._id,
      count: ok,
      totalAttempted: availableAccounts.length
    });
    
  } catch (e) {
    console.error('Follow error:', e);
    res.status(500).json({ success: false, error: 'Follow operation failed' });
  }
});

app.post('/api/tools/reactions', auth, async (req, res) => {
  try {
    const { link, type = 'LIKE', limit = 10 } = req.body;
    
    if (!link) {
      return res.status(400).json({ success: false, error: 'Post URL required' });
    }
    
    // Check if user has at least one account
    const userHasAccounts = await FbAccount.countDocuments({ 
      owner: req.kdxfUser._id, 
      isActive: true 
    });
    
    if (userHasAccounts === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'You must add at least one Facebook account to use this tool' 
      });
    }
    
    const postId = await extractPostID(link);
    if (!postId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook post URL' });
    }
    
    const pool = await FbAccount.find({
      owner: { $ne: req.kdxfUser._id },
      isActive: true,
      inPool: true,
      consecutiveFails: { $lt: 3 }
    }).select('+accessToken +cookies').limit(parseInt(limit));
    
    if (!pool.length) {
      return res.status(400).json({ 
        success: false, 
        error: 'No active accounts available in global pool.' 
      });
    }
    
    const availableAccounts = [];
    for (const acc of pool) {
      const cooldown = await checkCooldown(acc._id, 'lastReaction');
      if (!cooldown) {
        availableAccounts.push(acc);
      }
    }
    
    if (!availableAccounts.length) {
      return res.status(429).json({
        success: false,
        cooldown: 30,
        message: 'All pool accounts on cooldown. Wait 30 minutes.'
      });
    }
    
    const proc = new Process({
      owner: req.kdxfUser._id,
      type: 'reaction',
      target: link,
      targetId: postId,
      totalCount: availableAccounts.length,
      status: 'running',
      accounts: availableAccounts.map(a => a._id)
    });
    await proc.save();
    
    let ok = 0, failed = 0;
    
    await Promise.all(availableAccounts.map(async (acc) => {
      try {
        await axios.post(
          `https://graph.facebook.com/v18.0/${postId}/reactions`,
          { type: type.toUpperCase() },
          {
            params: { access_token: acc.accessToken },
            headers: {
              'Cookie': acc.cookies,
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 10000
          }
        );
        
        ok++;
        acc.actionsReceived = (acc.actionsReceived || 0) + 1;
        acc.lastUsed = new Date();
        acc.consecutiveFails = 0;
        await acc.save();
        
      } catch (e) {
        failed++;
        acc.consecutiveFails = (acc.consecutiveFails || 0) + 1;
        
        if (e.response?.status === 401 || e.response?.status === 403) {
          acc.isActive = false;
          acc.inPool = false;
        }
        
        if (acc.consecutiveFails >= 3) {
          acc.isActive = false;
          acc.inPool = false;
        }
        
        await acc.save();
      }
    }));
    
    proc.successCount = ok;
    proc.failedCount = failed;
    proc.status = 'completed';
    proc.updatedAt = new Date();
    await proc.save();
    
    await Analytics.create({
      owner: req.kdxfUser._id,
      type: 'reaction',
      success: ok,
      failed,
      accountId: postId
    });
    
    await FbAccount.deleteMany({
      isActive: false,
      consecutiveFails: { $gte: 3 }
    });
    
    res.json({
      success: true,
      processId: proc._id,
      count: ok,
      totalAttempted: availableAccounts.length
    });
    
  } catch (e) {
    console.error('Reaction error:', e);
    res.status(500).json({ success: false, error: 'Reaction operation failed' });
  }
});

app.post('/api/tools/share', auth, async (req, res) => {
  try {
    const { link, delay = 5, limit = 10, accountId } = req.body;
    
    if (!link) {
      return res.status(400).json({ success: false, error: 'Post URL required' });
    }
    
    // Check if user has at least one account
    const userHasAccounts = await FbAccount.countDocuments({ 
      owner: req.kdxfUser._id, 
      isActive: true 
    });
    
    if (userHasAccounts === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'You must add at least one Facebook account to use this tool' 
      });
    }
    
    const postId = await extractID(link);
    if (!postId) {
      return res.status(400).json({ success: false, error: 'Invalid Facebook URL' });
    }
    
    let account;
    if (accountId) {
      account = await FbAccount.findOne({
        _id: accountId,
        owner: req.kdxfUser._id
      }).select('+accessToken +cookies');
    } else {
      account = await FbAccount.findOne({
        owner: req.kdxfUser._id,
        isActive: true
      }).select('+accessToken +cookies');
    }
    
    if (!account) {
      return res.status(400).json({
        success: false,
        error: 'No active account found. Add an account first.'
      });
    }
    
    // Check cooldown
    const cooldown = await checkCooldown(account._id, 'lastShare');
    if (cooldown) {
      return res.status(429).json({
        success: false,
        cooldown,
        message: `Account on cooldown. Wait ${cooldown} minutes.`
      });
    }
    
    // Verify account before sharing
    const isValid = await verifyAccount(account);
    if (!isValid) {
      return res.status(400).json({
        success: false,
        error: 'Account token expired or invalid'
      });
    }
    
    const shareLimit = Math.min(parseInt(limit), 200);
    
    const proc = new Process({
      owner: req.kdxfUser._id,
      type: 'share',
      target: link,
      targetId: postId,
      totalCount: shareLimit,
      status: 'running',
      accounts: [account._id]
    });
    await proc.save();
    
    let ok = 0, fails = 0;
    const maxConsecutiveFails = 5;
    
    for (let i = 0; i < shareLimit; i++) {
      try {
        await axios.post(
          `https://graph.facebook.com/me/feed?link=https://m.facebook.com/${postId}&published=0&access_token=${account.accessToken}`,
          null,
          {
            headers: {
              'Cookie': account.cookies,
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
              'Referer': 'https://www.facebook.com/',
              'Authority': 'graph.facebook.com'
            },
            timeout: 10000
          }
        );
        
        ok++;
        fails = 0;
        account.actionsDone = (account.actionsDone || 0) + 1;
        account.consecutiveFails = 0;
        await account.save();
        
        // Update process progress
        proc.successCount = ok;
        proc.failedCount = shareLimit - (i + 1) + (shareLimit - i - 1 - ok);
        proc.updatedAt = new Date();
        await proc.save();
        
      } catch (e) {
        fails++;
        account.consecutiveFails = (account.consecutiveFails || 0) + 1;
        
        if (e.response?.status === 401 || e.response?.status === 403) {
          account.isActive = false;
          account.inPool = false;
          await account.save();
          break;
        }
        
        if (fails >= maxConsecutiveFails) {
          await account.save();
          break;
        }
        
        await account.save();
        
        // Update progress even on failure
        proc.failedCount = (proc.failedCount || 0) + 1;
        proc.updatedAt = new Date();
        await proc.save();
      }
      
      if (i < shareLimit - 1) {
        await new Promise(r => setTimeout(r, parseInt(delay) * 1000));
      }
    }
    
    proc.successCount = ok;
    proc.failedCount = shareLimit - ok;
    proc.status = 'completed';
    proc.updatedAt = new Date();
    await proc.save();
    
    await Analytics.create({
      owner: req.kdxfUser._id,
      type: 'share',
      success: ok,
      failed: shareLimit - ok,
      accountId: postId
    });
    
    res.json({
      success: true,
      processId: proc._id,
      count: ok,
      totalAttempted: shareLimit
    });
    
  } catch (e) {
    console.error('Share error:', e);
    res.status(500).json({ success: false, error: 'Share operation failed' });
  }
});

// ═══════ PROCESSES ROUTES ═══════

app.get('/api/processes', auth, async (req, res) => {
  try {
    const procs = await Process.find({ owner: req.kdxfUser._id })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json({ success: true, processes: procs });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to fetch processes' });
  }
});

app.put('/api/processes/:id/pause', auth, async (req, res) => {
  try {
    const p = await Process.findOne({ _id: req.params.id, owner: req.kdxfUser._id });
    if (!p) {
      return res.status(404).json({ success: false, error: 'Process not found' });
    }
    
    p.status = 'paused';
    p.updatedAt = new Date();
    await p.save();
    
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to pause process' });
  }
});

app.put('/api/processes/:id/resume', auth, async (req, res) => {
  try {
    const p = await Process.findOne({ _id: req.params.id, owner: req.kdxfUser._id });
    if (!p) {
      return res.status(404).json({ success: false, error: 'Process not found' });
    }
    
    p.status = 'running';
    p.updatedAt = new Date();
    await p.save();
    
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to resume process' });
  }
});

app.delete('/api/processes/:id', auth, async (req, res) => {
  try {
    await Process.findOneAndDelete({ _id: req.params.id, owner: req.kdxfUser._id });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to stop process' });
  }
});

// ═══════ ANALYTICS ROUTES ═══════

app.get('/api/analytics', auth, async (req, res) => {
  try {
    const { period = 'today' } = req.query;
    let start;
    const now = new Date();
    
    if (period === 'today') {
      start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    } else if (period === 'week') {
      start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    } else if (period === 'month') {
      start = new Date(now.getFullYear(), now.getMonth(), 1);
    }
    
    const data = await Analytics.aggregate([
      {
        $match: {
          owner: new mongoose.Types.ObjectId(req.kdxfUser._id),
          date: { $gte: start }
        }
      },
      {
        $group: {
          _id: '$type',
          totalSuccess: { $sum: '$success' },
          totalFailed: { $sum: '$failed' }
        }
      }
    ]);
    
    res.json({ success: true, period, analytics: data });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to fetch analytics' });
  }
});

// ═══════════════════════════════════════════
// SERVE FRONTEND (SPA)
// ═══════════════════════════════════════════
app.get('*', (req, res, next) => {
  // Don't interfere with API routes
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ═══════════════════════════════════════════
// ERROR HANDLING
// ═══════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ═══════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`[Server] Running on port ${PORT} [${NODE_ENV}]`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[Server] SIGTERM received. Closing...');
  mongoose.connection.close();
  process.exit(0);
});
