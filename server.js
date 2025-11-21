const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const DOMAIN = 'zelfa.nethacker.cloud';

// --- SECURITY CONFIG ---
// 使用固定 Key 確保重啟後 Login Session 不失效
const ENCRYPTION_KEY = Buffer.from("d7f8a9e2b1c4d3f5a6e8c0b7d9f2a1c5e8b4d3a6f9c0e7b2d5a8f1c4e3b6d9a2", 'hex');
const IV_LENGTH = 16;
const ADMIN_PASSWORD = process.env.ADMIN;

const API_KEYS = {
    CAW: process.env.CAWAPI,
    GAS: process.env.GASAPI,
    OA: process.env.OAAPI
};

// --- STRICT MODEL & PROVIDER MAPPING ---
// 這裡定義了唯一的真理：哪個模型屬於哪個供應商，絕對不能改
const MODEL_PROVIDER_MAP = {
    'gpt-5-mini': 'ChatAnyWhere',
    'deepseek-v3': 'ChatAnyWhere',
    'gemini-2.0-flash': 'Google',
    'gpt-5-nano': 'OpenAI',
    'gpt-5.1-codex-mini': 'OpenAI'
};

// 產生白名單 Keys
const ALLOWED_MODELS = Object.keys(MODEL_PROVIDER_MAP);

// --- MIDDLEWARE ---
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Security Headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    if (req.path.startsWith('/api')) {
        const origin = req.get('origin');
        const referer = req.get('referer');
        if (origin !== `https://${DOMAIN}` && (!referer || !referer.includes(DOMAIN))) {
             if(req.hostname !== 'localhost') return res.status(403).json({ error: 'Origin Denied' });
        }
        res.setHeader('Access-Control-Allow-Origin', `https://${DOMAIN}`);
    }
    next();
});

// --- CRYPTO HELPERS ---
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) { return null; }
}

// --- FILE IO ---
const USERS_FILE = path.join(__dirname, 'users.json');
const HISTORY_FILE = path.join(__dirname, 'history.json');

async function readJson(file) {
    try { return JSON.parse(await fs.readFile(file, 'utf8')); } catch (e) { return {}; }
}
async function writeJson(file, data) {
    await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// --- AUTH MIDDLEWARE ---
async function requireUserAuth(req, res, next) {
    const cookie = req.cookies['session_token'];
    if (!cookie) return res.redirect('/login');

    const decrypted = decrypt(cookie);
    if (!decrypted) {
        res.clearCookie('session_token');
        return res.redirect('/login');
    }

    const session = JSON.parse(decrypted);
    if (Date.now() - session.ts > 86400000) { // 24h
        res.clearCookie('session_token');
        return res.redirect('/login');
    }

    const users = await readJson(USERS_FILE);
    if(!users[session.username]) {
        res.clearCookie('session_token');
        return res.redirect('/login');
    }

    req.user = session.username;
    next();
}

async function requireAdminAuth(req, res, next) {
    const cookie = req.cookies['admin_token'];
    if (!cookie) {
        if(req.path.startsWith('/api')) return res.status(403).json({error: "Admin Auth Required"});
        return next(); 
    }
    const decrypted = decrypt(cookie);
    if (!decrypted) {
        res.clearCookie('admin_token');
        return req.path.startsWith('/api') ? res.status(403).json({error: "Invalid Token"}) : next();
    }
    const session = JSON.parse(decrypted);
    if (session.role !== 'admin') {
        return req.path.startsWith('/api') ? res.status(403).json({error: "Role Mismatch"}) : next();
    }
    req.isAdmin = true;
    next();
}

// --- RATE LIMIT ---
async function checkRateLimit(username, model) {
    const users = await readJson(USERS_FILE);
    const user = users[username];
    if (!user) return false;

    const today = new Date().toISOString().split('T')[0];
    if (user.usage.date !== today) {
        user.usage = { date: today, counts: {} };
    }

    const limit = user.limits[model] || 0;
    const current = user.usage.counts[model] || 0;

    if (current >= limit) return false;

    user.usage.counts[model] = current + 1;
    await writeJson(USERS_FILE, users);
    return true;
}

// --- ROUTES: PAGES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'pages/index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'pages/login.html')));
app.get('/create', (req, res) => res.sendFile(path.join(__dirname, 'pages/create.html')));
app.get('/chat', requireUserAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages/chat.html')));
app.get('/chat/:id', requireUserAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages/chat.html')));
app.get('/account', requireUserAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages/account.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'pages/admin.html')));

// --- ROUTES: API ---

// Admin Logic
app.post('/api/admin/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        const token = encrypt(JSON.stringify({ role: 'admin', ts: Date.now() }));
        res.cookie('admin_token', token, { httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 86400000 });
        res.json({ success: true });
    } else {
        res.status(403).json({ error: 'Invalid Password' });
    }
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true });
});

app.post('/api/admin/users', requireAdminAuth, async (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ error: 'Admin Only' });
    const { action, username, password, limits } = req.body;
    const users = await readJson(USERS_FILE);

    if (action === 'list') {
        const list = Object.keys(users).map(u => ({
            username: u, limits: users[u].limits, usage: users[u].usage
        }));
        return res.json({ users: list });
    }
    if (action === 'create') {
        if (users[username]) return res.status(400).json({ error: 'User exists' });
        users[username] = {
            password: await bcrypt.hash(password, 10),
            limits: limits || { "gpt-5-mini": 50, "deepseek-v3": 50, "gemini-2.0-flash": 50, "gpt-5-nano": 50, "gpt-5.1-codex-mini": 50 },
            usage: { date: new Date().toISOString().split('T')[0], counts: {} }
        };
        await writeJson(USERS_FILE, users);
        return res.json({ success: true });
    }
    if (action === 'delete') {
        delete users[username];
        await writeJson(USERS_FILE, users);
        return res.json({ success: true });
    }
    if (action === 'update_limit') {
        if (users[username]) {
            users[username].limits = { ...users[username].limits, ...limits };
            await writeJson(USERS_FILE, users);
            return res.json({ success: true });
        }
    }
    res.status(400).json({ error: 'Action Failed' });
});

// User Logic
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = await readJson(USERS_FILE);
    if (!users[username]) return res.status(401).json({ error: 'Not Found' });

    if (await bcrypt.compare(password, users[username].password)) {
        const token = encrypt(JSON.stringify({ username, ts: Date.now() }));
        res.cookie('session_token', token, { httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 86400000 });
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Bad Creds' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('session_token');
    res.json({ success: true });
});

app.post('/api/account', requireUserAuth, async (req, res) => {
    const users = await readJson(USERS_FILE);
    const user = users[req.user];
    const remaining = {};
    const today = new Date().toISOString().split('T')[0];
    const counts = (user.usage.date === today) ? user.usage.counts : {};
    for (const [model, limit] of Object.entries(user.limits)) {
        remaining[model] = Math.max(0, limit - (counts[model] || 0));
    }
    res.json({ username: req.user, remaining });
});

// Chat Data Logic
app.post('/api/chat/load', requireUserAuth, async (req, res) => {
    const history = await readJson(HISTORY_FILE);
    const { chatId } = req.body;
    if (chatId) {
        const chat = history[chatId];
        if (!chat || chat.owner !== req.user) return res.status(403).json({ error: 'Denied' });
        return res.json({ chat });
    }
    const list = Object.entries(history)
        .filter(([_, d]) => d.owner === req.user)
        .map(([id, d]) => ({ id, title: d.title }));
    res.json({ list });
});

app.post('/api/chat/action', requireUserAuth, async (req, res) => {
    const { action, chatId, newTitle } = req.body;
    const history = await readJson(HISTORY_FILE);
    if (!history[chatId] || history[chatId].owner !== req.user) return res.status(403).json({ error: 'Denied' });

    if (action === 'rename') history[chatId].title = newTitle;
    if (action === 'delete') delete history[chatId];
    await writeJson(HISTORY_FILE, history);
    res.json({ success: true });
});

// --- CORE MODEL INFERENCE LOGIC (STRICT MAPPING) ---
app.post('/api/models', requireUserAuth, async (req, res) => {
    const { model, prompt, chatId, messages } = req.body;
    
    // 1. Strict Model Validation (Must exist in Map)
    const targetProvider = MODEL_PROVIDER_MAP[model];
    if (!targetProvider) {
        return res.status(400).json({ error: `ILLEGAL MODEL: '${model}' is not in the secure registry.` });
    }

    // 2. Rate Limit Check
    if (!(await checkRateLimit(req.user, model))) {
        return res.status(429).json({ error: 'Daily Rate Limit Exceeded' });
    }

    // 3. Prepare Input
    const historyStr = (messages && messages.length) 
        ? " (History: " + messages.map(m => `${m.role}: ${m.content}`).join(" | ") + ")"
        : "";
    const finalInput = `${prompt}${historyStr}`;

    let reply = "";
    const fetch = (await import('node-fetch')).default;

    try {
        // 4. Strict Routing based on Provider Mapping
        if (targetProvider === 'ChatAnyWhere') {
            // 只處理 gpt-5-mini 和 deepseek-v3
            const apiRes = await fetch("https://api.chatanywhere.tech/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.CAW}`
                },
                body: JSON.stringify({
                    model: model, // CAW 接受這兩個 ID
                    messages: [
                        { role: "system", content: "You are a helpful AI." },
                        { role: "user", content: finalInput }
                    ],
                    temperature: 1, top_p: 1
                })
            });
            if (apiRes.status === 429) throw new Error("ChatAnyWhere Rate Limit");
            const data = await apiRes.json();
            reply = data?.choices?.[0]?.message?.content || "[CAW Error: No Content]";

        } else if (targetProvider === 'Google') {
            // 只處理 gemini-2.0-flash
            const apiRes = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${API_KEYS.GAS}`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ contents: [{ parts: [{ text: finalInput }] }] })
                }
            );
            const data = await apiRes.json();
            reply = data?.candidates?.[0]?.content?.parts?.[0]?.text || "[Google Error: No Content]";

        } else if (targetProvider === 'OpenAI') {
            // 只處理 gpt-5-nano 和 gpt-5.1-codex-mini
            const apiRes = await fetch("https://api.openai.com/v1/responses", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OA}`
                },
                body: JSON.stringify({ 
                    model: model, 
                    input: finalInput 
                })
            });
            const data = await apiRes.json();
            reply = data?.choices?.[0]?.text || data?.output || JSON.stringify(data);
        } else {
            throw new Error("System Error: Provider Mapping Invalid");
        }

        // 5. Save to History
        const history = await readJson(HISTORY_FILE);
        let activeId = chatId;
        if (!activeId || !history[activeId]) {
            activeId = uuidv4();
            history[activeId] = {
                owner: req.user,
                title: prompt.substring(0, 20) || "New Chat",
                messages: []
            };
        }
        history[activeId].messages.push({ role: 'user', content: prompt });
        history[activeId].messages.push({ role: 'ai', content: reply });
        await writeJson(HISTORY_FILE, history);

        res.json({ reply, chatId: activeId });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.listen(PORT, () => console.log(`Zelfa Core Online: ${PORT}`));
