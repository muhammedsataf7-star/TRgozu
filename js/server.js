/**
 * TR-GOZU güvenli backend
 * - Helmet güvenlik başlıkları, CORS kısıtı, gövde boyutu sınırı
 * - Rate limiting (genel + kimlik doğrulama)
 * - bcrypt ile şifre hash, JWT ile oturum
 * - Hassas uçlar: yalnız yetkili JWT ile tam liste; vatandaş yalnız kendi e-postası
 * - OpenWeather: API anahtarı yalnız sunucuda (.env); istemci /api/weather/* üzerinden
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const ROOT = path.join(__dirname, '..');
/** E-posta / şifre ile kayıtlı vatandaşlar (TC günlük dosyası users.json ile karıştırılmaz) */
const CITIZENS_FILE = path.join(__dirname, 'citizens.json');
const SOS_FILE = path.join(__dirname, 'sos.json');
const MESSAGES_FILE = path.join(__dirname, 'messages.json');
const VOLUNTEERS_FILE = path.join(__dirname, 'volunteers.json');

const JWT_SECRET = process.env.JWT_SECRET || 'tr-gozu-dev-only-change-in-production';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '12h';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const WEATHER_API_KEY = process.env.WEATHER_API_KEY || '';
const PORT = parseInt(process.env.PORT || '3000', 10);

const adminKeysSet = () => {
    const raw = process.env.ADMIN_KEYS || '';
    const keys = raw.split(',').map((k) => k.trim()).filter(Boolean);
    if (keys.length) return new Set(keys);
    return new Set(['AFAD2026', 'UMKE911', 'AKUT123', 'ADMIN']);
};

app.set('trust proxy', 1);

app.use(
    helmet({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false
    })
);

app.use(
    cors({
        origin(origin, cb) {
            if (!origin) return cb(null, true);
            const allowed = (process.env.CORS_ORIGINS || '')
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean);
            if (allowed.length === 0) {
                if (process.env.NODE_ENV === 'production') {
                    return cb(null, false);
                }
                return cb(null, true);
            }
            if (allowed.some((a) => origin === a || origin.startsWith(a))) return cb(null, true);
            return cb(null, false);
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization']
    })
);

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX || '300', 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Çok fazla istek. Lütfen daha sonra deneyin.' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '40', 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Çok fazla giriş denemesi.' }
});

app.use(generalLimiter);
app.use(express.json({ limit: '128kb' }));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

const readJSON = (file) => {
    if (!fs.existsSync(file)) return [];
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
        return [];
    }
};

/** JSON dizi dosyaları — bozuk veya {} ise [] */
const readJSONArray = (file) => {
    const data = readJSON(file);
    return Array.isArray(data) ? data : [];
};

const writeJSON = (file, data) => {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
};

const isEmail = (s) => typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim());

function signToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function requireAuth(requiredRole) {
    return (req, res, next) => {
        const h = req.headers.authorization;
        if (!h || !h.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Oturum gerekli (Authorization Bearer).' });
        }
        try {
            const decoded = jwt.verify(h.slice(7), JWT_SECRET);
            if (requiredRole && decoded.role !== requiredRole) {
                return res.status(403).json({ success: false, message: 'Bu işlem için yetkiniz yok.' });
            }
            req.user = decoded;
            next();
        } catch (e) {
            return res.status(401).json({ success: false, message: 'Geçersiz veya süresi dolmuş oturum.' });
        }
    };
}

function stripSensitiveUsers(list) {
    return (list || []).map((u) => {
        const { pass, passHash, sifre, ...rest } = u;
        return rest;
    });
}

function fetchUrlJson(url) {
    if (typeof globalThis.fetch === 'function') {
        return globalThis.fetch(url).then((r) => {
            if (!r.ok) throw new Error(String(r.status));
            return r.json();
        });
    }
    return new Promise((resolve, reject) => {
        https
            .get(url, (r) => {
                let d = '';
                r.on('data', (c) => {
                    d += c;
                });
                r.on('end', () => {
                    try {
                        resolve(JSON.parse(d));
                    } catch (e) {
                        reject(e);
                    }
                });
            })
            .on('error', reject);
    });
}

// --- OpenWeather proxy (anahtar sunucuda kalır) ---
function weatherProxy(req, res, subpath) {
    if (!WEATHER_API_KEY) {
        return res.status(503).json({ success: false, message: 'Hava servisi yapılandırılmadı (WEATHER_API_KEY).' });
    }
    const q = req.query;
    const lat = q.lat;
    const lon = q.lon;
    if (lat == null || lon == null || Number.isNaN(Number(lat)) || Number.isNaN(Number(lon))) {
        return res.status(400).json({ success: false, message: 'lat ve lon gerekli.' });
    }
    const sp = new URLSearchParams({
        lat: String(lat),
        lon: String(lon),
        appid: WEATHER_API_KEY,
        units: q.units || 'metric',
        lang: q.lang || 'tr'
    });
    if (q.cnt != null) sp.set('cnt', String(q.cnt));
    const url = `https://api.openweathermap.org/data/2.5/${subpath}?${sp}`;
    return fetchUrlJson(url)
        .then((data) => res.json(data))
        .catch(() => res.status(502).json({ success: false, message: 'Hava servisi ulaşılamadı.' }));
}

app.get('/api/weather/weather', (req, res) => weatherProxy(req, res, 'weather'));
app.get('/api/weather/forecast', (req, res) => weatherProxy(req, res, 'forecast'));
app.get('/api/weather/air_pollution', (req, res) => weatherProxy(req, res, 'air_pollution'));

// --- Kimlik doğrulama (paylaşılan mantık) ---
async function handleRegister(req, res) {
    const email = (req.body.email || '').trim().toLowerCase();
    const pass = req.body.password || req.body.pass;
    if (!isEmail(email)) return res.status(400).json({ success: false, message: 'Geçersiz e-posta.' });
    if (typeof pass !== 'string' || pass.length < 8) {
        return res.status(400).json({ success: false, message: 'Şifre en az 8 karakter olmalıdır.' });
    }
    let users = readJSONArray(CITIZENS_FILE);
    if (users.find((u) => u.email === email)) {
        return res.status(400).json({ success: false, message: 'Bu e-posta zaten kayıtlı.' });
    }
    const passHash = await bcrypt.hash(pass, BCRYPT_ROUNDS);
    users.push({
        email,
        passHash,
        created: new Date().toISOString(),
        lat: null,
        lng: null,
        lastActive: null,
        healthStatus: null,
        battery: null,
        isSOS: false,
        isPanic: false
    });
    writeJSON(CITIZENS_FILE, users);
    const token = signToken({ email, role: 'citizen' });
    return res.json({ success: true, message: 'Kayıt başarılı.', token, role: 'citizen' });
}

async function handleLogin(req, res) {
    const email = (req.body.email || '').trim().toLowerCase();
    const pass = req.body.password || req.body.pass;
    if (!isEmail(email) || typeof pass !== 'string') {
        return res.status(400).json({ success: false, message: 'E-posta ve şifre gerekli.' });
    }
    const users = readJSONArray(CITIZENS_FILE);
    const user = users.find((u) => u.email === email);
    if (!user) return res.status(404).json({ success: false, message: 'Kullanıcı bulunamadı.' });

    let ok = false;
    if (user.passHash) {
        ok = await bcrypt.compare(pass, user.passHash);
    } else if (user.pass) {
        ok = user.pass === pass;
        if (ok) {
            user.passHash = await bcrypt.hash(pass, BCRYPT_ROUNDS);
            delete user.pass;
            const idx = users.findIndex((u) => u.email === email);
            if (idx >= 0) users[idx] = user;
            writeJSON(CITIZENS_FILE, users);
        }
    }
    if (!ok) return res.status(401).json({ success: false, message: 'Şifre hatalı.' });

    const token = signToken({ email, role: 'citizen' });
    return res.json({ success: true, message: 'Giriş başarılı.', token, role: 'citizen' });
}

app.post('/api/auth/register', authLimiter, handleRegister);
app.post('/api/auth/login', authLimiter, handleLogin);

app.post('/api/auth/admin-login', authLimiter, (req, res) => {
    const key = (req.body.key || '').trim();
    const keys = adminKeysSet();
    if (!key || !keys.has(key)) {
        return res.status(401).json({ success: false, message: 'Geçersiz yetkili anahtarı.' });
    }
    const token = signToken({ email: 'admin@trgozu.local', role: 'admin', unit: key });
    return res.json({
        success: true,
        message: 'Yetkili oturumu açıldı.',
        token,
        role: 'admin',
        unit: key
    });
});

// Eski uç (geriye dönük): { mode, email, pass }
app.post('/save-user', authLimiter, async (req, res) => {
    const mode = req.body.mode;
    const email = (req.body.email || '').trim().toLowerCase();
    const pass = req.body.pass || req.body.password;
    req.body = { email, password: pass };
    if (mode === 'reg') return handleRegister(req, res);
    if (mode === 'login') return handleLogin(req, res);
    return res.status(400).json({ success: false, message: 'Geçersiz istek.' });
});

// --- Korunan API ---
app.post('/api/citizen/update', requireAuth('citizen'), (req, res) => {
    const bodyEmail = (req.body.email || '').trim().toLowerCase();
    if (!bodyEmail || bodyEmail !== (req.user.email || '').toLowerCase()) {
        return res.status(403).json({ success: false, message: 'Sadece kendi hesabınızı güncelleyebilirsiniz.' });
    }
    const { email, lat, lng, lastActive, lastMoveAt, healthStatus, healthNote, battery, isSOS, isPanic } = req.body;
    let users = readJSONArray(CITIZENS_FILE);
    const idx = users.findIndex((u) => u.email === email);
    if (idx === -1) {
        users.push({
            email,
            lat,
            lng,
            lastActive,
            lastMoveAt,
            healthStatus,
            healthNote,
            battery,
            isSOS: isSOS || false,
            isPanic: isPanic || false
        });
    } else {
        if (lat !== undefined) users[idx].lat = lat;
        if (lng !== undefined) users[idx].lng = lng;
        if (lastActive !== undefined) users[idx].lastActive = lastActive;
        if (lastMoveAt !== undefined) users[idx].lastMoveAt = lastMoveAt;
        if (healthStatus !== undefined) users[idx].healthStatus = healthStatus;
        if (healthNote !== undefined) users[idx].healthNote = healthNote;
        if (battery !== undefined) users[idx].battery = battery;
        if (isSOS !== undefined) users[idx].isSOS = isSOS;
        if (isPanic !== undefined) users[idx].isPanic = isPanic;
    }
    writeJSON(CITIZENS_FILE, users);
    res.json({ success: true });
});

app.get('/api/citizens', requireAuth('admin'), (req, res) => {
    res.json(stripSensitiveUsers(readJSONArray(CITIZENS_FILE)));
});

app.post('/api/sos', requireAuth('citizen'), (req, res) => {
    const uid = (req.body.user || req.body.email || '').trim().toLowerCase();
    if (uid && uid !== (req.user.email || '').toLowerCase()) {
        return res.status(403).json({ success: false, message: 'SOS yalnızca kendi adınıza gönderilebilir.' });
    }
    const list = readJSONArray(SOS_FILE);
    list.push({ ...req.body, user: req.user.email });
    writeJSON(SOS_FILE, list);
    res.json({ success: true });
});

app.get('/api/sos', requireAuth('admin'), (req, res) => {
    res.json(readJSONArray(SOS_FILE));
});

app.post('/api/messages', requireAuth('citizen'), (req, res) => {
    const from = (req.body.from || '').trim().toLowerCase();
    if (from && from !== (req.user.email || '').toLowerCase()) {
        return res.status(403).json({ success: false, message: 'Gönderen adresi oturumla eşleşmiyor.' });
    }
    const msgs = readJSONArray(MESSAGES_FILE);
    msgs.push({ ...req.body, from: req.user.email });
    writeJSON(MESSAGES_FILE, msgs);
    res.json({ success: true });
});

app.get('/api/messages/:userId', requireAuth(), (req, res) => {
    const userId = decodeURIComponent(req.params.userId).trim().toLowerCase();
    const role = req.user.role;
    const tokenEmail = (req.user.email || '').toLowerCase();
    if (role !== 'admin' && userId !== tokenEmail) {
        return res.status(403).json({ success: false, message: 'Bu mesajlara erişim yetkiniz yok.' });
    }
    const msgs = readJSONArray(MESSAGES_FILE);
    res.json(msgs.filter((m) => m.from === userId || m.to === userId));
});

app.post('/api/volunteers', requireAuth('citizen'), (req, res) => {
    const vols = readJSONArray(VOLUNTEERS_FILE);
    vols.push(req.body);
    writeJSON(VOLUNTEERS_FILE, vols);
    res.json({ success: true });
});

app.get('/api/volunteers', requireAuth('admin'), (req, res) => {
    res.json(readJSONArray(VOLUNTEERS_FILE));
});

// Statik site (tek komutla arayüz + API)
app.use(
    express.static(ROOT, {
        index: 'index.html',
        dotfiles: 'deny',
        setHeaders(res) {
            res.setHeader('X-Content-Type-Options', 'nosniff');
        }
    })
);

app.listen(PORT, () => {
    console.log(`TR-GOZU güvenli backend http://localhost:${PORT}`);
});
