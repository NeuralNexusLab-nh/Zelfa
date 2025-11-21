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
const ENCRYPTION_KEY = Buffer.from("d7f8a9e2b1c4d3f5a6e8c0b7d9f2a1c5e8b4d3a6f9c0e7b2d5a8f1c4e3b6d9a2", 'hex');
const IV_LENGTH = 16;
const ADMIN_PASSWORD = process.env.ADMIN ? process.env.ADMIN.trim() : null;

if(!ADMIN_PASSWORD) console.error("⚠️ WARNING: process.env.ADMIN is not set!");

const API_KEYS = {
    CAW: process.env.CAWAPI,
    GAS: process.env.GASAPI,
    OA: process.env.OAAPI
};

// --- MODEL REGISTRY (Configuration) ---
const MODEL_REGISTRY = {
    // ChatAnyWhere (OpenAI Compatible)
    'gpt-5-mini':       { provider: 'ChatAnyWhere', maxTokens: 3000 }, 
    'deepseek-v3':      { provider: 'ChatAnyWhere', maxTokens: 3000 },
    'gpt-3.5-turbo':      { provider: 'ChatAnyWhere', maxTokens: 3000 },
    'deepseek-r1':      { provider: 'ChatAnyWhere', maxTokens: 3000 },
    'gpt-4o-mini':      { provider: 'ChatAnyWhere', maxTokens: 3000 },

    // Google (Gemini)
    'gemini-2.0-flash': { provider: 'Google', maxTokens: 2000 },

    // OpenAI (Custom)
    'gpt-5-nano':         { provider: 'OpenAI', maxTokens: 200},
    'gpt-4o-mini-search-preview':         { provider: 'OpenAI', maxTokens: 300},
    'o1-mini':         { provider: 'OpenAI', maxTokens: 350},
    'o3-mini':         { provider: 'OpenAI', maxTokens: 350},
    'gpt-5.1-codex-mini': { provider: 'OpenAI', maxTokens: 2300} 
};

// --- MIDDLEWARE ---
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
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

// --- CRYPTO ---
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}
function decrypt(text) {
    try {
        const parts = text.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let dec = decipher.update(Buffer.from(parts.join(':'), 'hex'));
        dec = Buffer.concat([dec, decipher.final()]);
        return dec.toString();
    } catch (e) { return null; }
}

// --- FILE OPS ---
const USERS_FILE = path.join(__dirname, 'users.json');
const HISTORY_FILE = path.join(__dirname, 'history.json');
async function readJson(file) { try { return JSON.parse(await fs.readFile(file, 'utf8')); } catch { return {}; } }
async function writeJson(file, data) { await fs.writeFile(file, JSON.stringify(data, null, 2)); }

// --- AUTH ---
async function requireUserAuth(req, res, next) {
    const c = req.cookies['session_token'];
    if (!c) return res.redirect('/login');
    const d = decrypt(c);
    if (!d) { res.clearCookie('session_token'); return res.redirect('/login'); }
    const s = JSON.parse(d);
    if (Date.now() - s.ts > 86400000) { res.clearCookie('session_token'); return res.redirect('/login'); }
    const users = await readJson(USERS_FILE);
    if(!users[s.username]) { res.clearCookie('session_token'); return res.redirect('/login'); }
    req.user = s.username;
    next();
}

async function requireAdminAuth(req, res, next) {
    const c = req.cookies['admin_token'];
    if (!c) {
        if(req.path.startsWith('/api')) return res.status(403).json({error: "Admin Auth Required"});
        return next();
    }
    const d = decrypt(c);
    if (!d || JSON.parse(d).role !== 'admin') {
        res.clearCookie('admin_token');
        return req.path.startsWith('/api') ? res.status(403).json({error: "Invalid Token"}) : next();
    }
    req.isAdmin = true;
    next();
}

// --- LIMITS ---
async function checkRateLimit(username, model) {
    const users = await readJson(USERS_FILE);
    const user = users[username];
    if (!user) return false;
    const today = new Date().toISOString().split('T')[0];
    if (user.usage.date !== today) user.usage = { date: today, counts: {} };
    const limit = user.limits[model] || 0;
    const current = user.usage.counts[model] || 0;
    if (current >= limit) return false;
    user.usage.counts[model] = current + 1;
    await writeJson(USERS_FILE, users);
    return true;
}

// --- ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'pages/index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'pages/login.html')));
app.get('/create', (req, res) => res.sendFile(path.join(__dirname, 'pages/create.html')));
app.get('/chat', requireUserAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages/chat.html')));
app.get('/chat/:id', requireUserAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages/chat.html')));
app.get('/account', requireUserAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages/account.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'pages/admin.html')));

// --- API ---
app.post('/api/admin/login', (req, res) => {
    if (!ADMIN_PASSWORD) return res.status(500).json({error:'Server Config Error'});
    if (req.body.password && req.body.password.trim() === ADMIN_PASSWORD) {
        res.cookie('admin_token', encrypt(JSON.stringify({role:'admin', ts:Date.now()})), {httpOnly:true, secure:true, sameSite:'Lax'});
        res.json({success:true});
    } else res.status(403).json({error:'Invalid Password'});
});
app.post('/api/admin/logout', (req, res) => { res.clearCookie('admin_token'); res.json({success:true}); });

app.post('/api/admin/users', requireAdminAuth, async (req, res) => {
    if(!req.isAdmin) return res.status(403).json({error:'Admin Only'});
    const {action, username, password, limits} = req.body;
    const users = await readJson(USERS_FILE);
    
    if(action === 'list') return res.json({users: Object.keys(users).map(u=>({username:u, limits:users[u].limits, usage:users[u].usage}))});
    if(action === 'create') {
        if(users[username]) return res.status(400).json({error:'Exists'});
        users[username] = {
            password: await bcrypt.hash(password, 10),
            limits: limits || { 
                "gpt-5-mini":50, 
                "gpt-4o-mini":50, 
                "gpt-3.5-turbo":50 ,
                "deepseek-v3":13, 
                "deepseek-r1":13, 
                "gemini-2.0-flash":75, 
                "gpt-5-nano":20,
                "gpt-4o-mini-search-preview": 20,
                "o1-mini": 3,
                "o3-mini": 3,
                "gpt-5.1-codex-mini":3 
            },
            usage: { date: new Date().toISOString().split('T')[0], counts: {} }
        };
        await writeJson(USERS_FILE, users);
        return res.json({success:true});
    }
    if(action === 'delete') { delete users[username]; await writeJson(USERS_FILE, users); return res.json({success:true}); }
    if(action === 'update_limit') {
        if(users[username]) { users[username].limits = {...users[username].limits, ...limits}; await writeJson(USERS_FILE, users); return res.json({success:true}); }
    }
    res.status(400).json({error:'Failed'});
});

app.post('/api/login', async (req, res) => {
    const {username, password} = req.body;
    const users = await readJson(USERS_FILE);
    if(!users[username]) return res.status(401).json({error:'Not Found'});
    if(await bcrypt.compare(password, users[username].password)) {
        res.cookie('session_token', encrypt(JSON.stringify({username, ts:Date.now()})), {httpOnly:true, secure:true, sameSite:'Lax'});
        res.json({success:true});
    } else res.status(401).json({error:'Bad Creds'});
});
app.post('/api/logout', (req, res) => { res.clearCookie('session_token'); res.json({success:true}); });

app.post('/api/account', requireUserAuth, async (req, res) => {
    const users = await readJson(USERS_FILE);
    const user = users[req.user];
    const remaining = {};
    const counts = (user.usage.date === new Date().toISOString().split('T')[0]) ? user.usage.counts : {};
    for(const [m, l] of Object.entries(user.limits)) remaining[m] = Math.max(0, l - (counts[m]||0));
    res.json({username: req.user, remaining});
});

app.post('/api/chat/load', requireUserAuth, async (req, res) => {
    const h = await readJson(HISTORY_FILE);
    if(req.body.chatId) {
        const c = h[req.body.chatId];
        if(!c || c.owner !== req.user) return res.status(403).json({error:'Denied'});
        return res.json({chat: c});
    }
    res.json({list: Object.entries(h).filter(([_,d])=>d.owner===req.user).map(([id,d])=>({id, title:d.title}))});
});

app.post('/api/chat/action', requireUserAuth, async (req, res) => {
    const h = await readJson(HISTORY_FILE);
    if(!h[req.body.chatId] || h[req.body.chatId].owner !== req.user) return res.status(403).json({error:'Denied'});
    if(req.body.action === 'rename') h[req.body.chatId].title = req.body.newTitle;
    if(req.body.action === 'delete') delete h[req.body.chatId];
    await writeJson(HISTORY_FILE, h);
    res.json({success:true});
});

// --- INFERENCE ---
app.post('/api/models', requireUserAuth, async (req, res) => {
    const { model, prompt, chatId, messages } = req.body;

    // 1. Validate Config
    const config = MODEL_REGISTRY[model];
    if (!config) return res.status(400).json({ error: `Invalid Model: ${model}` });

    // 2. Rate Limit
    if (!(await checkRateLimit(req.user, model))) return res.status(429).json({ error: 'Daily Limit Exceeded' });

    // 3. Context
    const historyStr = (messages && messages.length) ? " (History: " + messages.map(m => `${m.role}: ${m.content}`).join(" | ") + ")" : "";
    const finalInput = `${prompt}${historyStr}`;
    const fetch = (await import('node-fetch')).default;

    try {
        let reply = "";

        if (config.provider === 'ChatAnyWhere') {
            const apiRes = await fetch("https://api.chatanywhere.tech/v1/chat/completions", {
                method: "POST",
                headers: { "Content-Type": "application/json", "Authorization": `Bearer ${API_KEYS.CAW}` },
                body: JSON.stringify({
                    model: model,
                    messages: [{ role: "user", content: finalInput }],
                    temperature: 1, top_p: 1,
                    max_tokens: config.maxTokens
                })
            });
            if (apiRes.status === 429) throw new Error("Provider Rate Limit");
            const data = await apiRes.json();
            reply = data?.choices?.[0]?.message?.content || "[No Content]";

        } else if (config.provider === 'Google') {
            const apiRes = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${API_KEYS.GAS}`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        contents: [{ parts: [{ text: finalInput }] }],
                        generationConfig: { maxOutputTokens: config.maxTokens }
                    })
                }
            );
            const data = await apiRes.json();
            reply = data?.candidates?.[0]?.content?.parts?.[0]?.text || "[No Content]";

        } else if (config.provider === 'OpenAI') {
            const apiRes = await fetch("https://api.openai.com/v1/responses", {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OA}`
                },
                body: JSON.stringify({
                    model: model,
                    input: finalInput,
                    max_tokens: config.maxTokens ?? 512
                })
            });
            const data = await apiRes.json();

            // 🔑 統一解析 OpenAI Responses API
            if (data.output_text) {
                reply = data.output_text;
            } else if (Array.isArray(data.output) && data.output[0]?.text) {
                reply = data.output[0].text;
            } else if (Array.isArray(data) &&
                       data[0]?.content &&
                       data[0].content[0]?.text) {
                reply = data[0].content[0].text;
            } else if (data.error) {
                throw new Error(data.error.message);
            } else {
                reply = "[No Content]";
            }
        }

        // 4. Save chat history
        const h = await readJson(HISTORY_FILE);
        const activeId = chatId || uuidv4();
        if (!h[activeId]) h[activeId] = { owner: req.user, title: prompt.substring(0, 20) || "New Chat", messages: [] };
        h[activeId].messages.push({ role: 'user', content: prompt });
        h[activeId].messages.push({ role: 'ai', content: reply });
        await writeJson(HISTORY_FILE, h);

        // 5. Return to frontend
        res.json({ reply, chatId: activeId });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});


app.listen(PORT, () => console.log(`Zelfa Core Online: ${PORT}`));
