// --- MODULE IMPORTS ---
const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs'); // sync 用
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.set('trust proxy', true);

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const DOMAIN = 'zelfa.nethacker.cloud';

const ENCRYPTION_KEY = Buffer.from(process.env.KEY || "", 'hex');
const IV_LENGTH = 16;
const ADMIN_PASSWORD = process.env.ADMIN ? process.env.ADMIN.trim() : null;

if (!ADMIN_PASSWORD) console.error("⚠️ WARNING: process.env.ADMIN is not set!");
if (!process.env.KEY) console.error("⚠️ WARNING: process.env.KEY is not set!");

const API_KEYS = {
    GAS: process.env.GASAPI,
    OA: process.env.OAAPI,
    OLM: process.env.OLMAPI
};

// --- MODEL REGISTRY ---
const MODEL_REGISTRY = {
    'cogito-2.1:671b': { provider: 'Ollama' },
    'glm-4.6': { provider: 'Ollama' },
    'kimi-k2:1t': { provider: 'Ollama' },
    'kimi-k2-thinking': { provider: 'Ollama' },
    'qwen3-coder:480b': { provider: 'Ollama' },
    'deepseek-v3.1:671b': { provider: 'Ollama' },
    'gpt-oss:120b': { provider: 'Ollama' },
    'gemini-2.0-flash': { provider: 'Google' },
    'gpt-5-nano': { provider: 'OpenAI' },
    'o3-mini': { provider: 'OpenAI' },
    'gpt-5.1-codex-mini': { provider: 'OpenAI' }
};

// --- MIDDLEWARE ---
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    if (req.path.startsWith('/api')) {
        const origin = req.get('origin');
        const referer = req.get('referer');

        if (
            origin !== `https://${DOMAIN}` &&
            origin !== `https://zelfa.onrender.com` &&
            (!referer || !referer.includes(DOMAIN))
        ) {
            if (req.hostname !== 'localhost') return res.status(403).json({ error: 'Origin Denied' });
        }

        res.setHeader('Access-Control-Allow-Origin', `https://${DOMAIN}`);
    }
    next();
});

// Ban system
app.use((req, res, next) => {
    const ban = JSON.parse(fsSync.readFileSync("./ban.json", "utf8"));
    if (ban.includes(req.ip)) {
        if (req.path.includes("admin")) return next();
        return res.status(403).send("Your IP has been banned!");
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
    } catch {
        return null;
    }
}

// --- FILE OPS ---
const USERS_FILE = path.join(__dirname, 'users.json');
const HISTORY_FILE = path.join(__dirname, 'history.json');

async function readJson(file) {
    try {
        return JSON.parse(await fs.readFile(file, 'utf8'));
    } catch {
        return {};
    }
}

async function writeJson(file, data) {
    await fs.writeFile(file, JSON.stringify(data, null, 2));
}

// --- AUTH ---
async function requireUserAuth(req, res, next) {
    const c = req.cookies['session_token'];
    if (!c) return res.redirect('/login');
    const d = decrypt(c);
    if (!d) {
        res.clearCookie('session_token');
        return res.redirect('/login');
    }
    const s = JSON.parse(d);
    if (Date.now() - s.ts > 86400000) {
        res.clearCookie('session_token');
        return res.redirect('/login');
    }
    const users = await readJson(USERS_FILE);
    if (!users[s.username]) {
        res.clearCookie('session_token');
        return res.redirect('/login');
    }
    req.user = s.username;
    next();
}

async function requireAdminAuth(req, res, next) {
    const c = req.cookies['admin_token'];
    if (!c) {
        if (req.path.startsWith('/api')) return res.status(403).json({ error: "Admin Auth Required" });
        return next();
    }
    const d = decrypt(c);
    if (!d || JSON.parse(d).role !== 'admin') {
        res.clearCookie('admin_token');
        return req.path.startsWith('/api') ? res.status(403).json({ error: "Invalid Token" }) : next();
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

// --- ADMIN API ---
app.get("/admin/ban", (req, res) => {
    if (req.query.pswd !== process.env.ADMIN) return res.status(403).send("ACCESS DENIED");

    const ban = JSON.parse(fsSync.readFileSync("./ban.json", "utf8"));
    ban.push(req.query.ip);

    fsSync.writeFileSync("./ban.json", JSON.stringify(ban, null, 2));
    res.send("SUCCESS");
});

app.get("/admin/logs", (req, res) => {
    if (req.query.pswd !== process.env.ADMIN) return res.status(403).send("ACCESS DENIED");

    const logs = JSON.parse(fsSync.readFileSync("./logs.json", "utf8"));
    res.json(logs);
});

app.get("/admin/clear", (req, res) => {
    if (req.query.pswd !== process.env.ADMIN) return res.status(403).send("ACCESS DENIED");

    fsSync.writeFileSync("./ban.json", "[]");
    res.send("SUCCESS");
});

// --- LOGIN API ---
app.post('/api/admin/login', (req, res) => {
    if (!ADMIN_PASSWORD) return res.status(500).json({ error: 'Server Config Error' });

    if (req.body.password && req.body.password.trim() === ADMIN_PASSWORD) {
        res.cookie('admin_token', encrypt(JSON.stringify({ role: 'admin', ts: Date.now() })), {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax'
        });
        return res.json({ success: true });
    }
    res.status(403).json({ error: 'Invalid Password' });
});

app.post('/api/admin/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.json({ success: true });
});

// --- USER MANAGEMENT ---
app.post('/api/admin/users', requireAdminAuth, async (req, res) => {
    if (!req.isAdmin) return res.status(403).json({ error: "Admin Only" });

    const { action, username, password, limits } = req.body;
    const users = await readJson(USERS_FILE);

    if (action === "list") {
        return res.json({
            users: Object.keys(users).map(u => ({
                username: u,
                limits: users[u].limits,
                usage: users[u].usage
            }))
        });
    }

    if (action === "create") {
        if (users[username]) return res.status(400).json({ error: "Exists" });

        const defaultOllamaLimits = {
            "gpt-oss:120b": 25,
            "deepseek-v3.1:671b": 25,
            "qwen3-coder:480b": 25,
            "kimi-k2:1t": 25,
            "kimi-k2-thinking": 25,
            "cogito-2.1:671b": 25,
            "glm-4.6": 25
        };

        const adminOllamaLimits = {
            "gpt-oss:120b": 10000,
            "deepseek-v3.1:671b": 10000,
            "qwen3-coder:480b": 10000,
            "kimi-k2:1t": 10000,
            "kimi-k2-thinking": 10000,
            "cogito-2.1:671b": 10000,
            "glm-4.6": 10000
        };

        const isAdminUser = username === "NeuralNexusLab" || username === "admin";

        users[username] = {
            password: await bcrypt.hash(password, 10),
            limits: isAdminUser ? {
                ...adminOllamaLimits,
                "gemini-2.0-flash": 10000,
                "gpt-5-nano": 10000,
                "o3-mini": 10000,
                "gpt-5.1-codex-mini": 10000
            } : {
                ...defaultOllamaLimits,
                "gemini-2.0-flash": 50,
                "o3-mini": 0,
                "gpt-5.1-codex-mini": 1
            },
            usage: { date: new Date().toISOString().split('T')[0], counts: {} }
        };

        await writeJson(USERS_FILE, users);
        return res.json({ success: true });
    }

    if (action === "delete") {
        delete users[username];
        await writeJson(USERS_FILE, users);
        return res.json({ success: true });
    }

    if (action === "update_limit") {
        if (users[username]) {
            users[username].limits = { ...users[username].limits, ...limits };
            await writeJson(USERS_FILE, users);
            return res.json({ success: true });
        }
    }

    res.status(400).json({ error: "Failed" });
});

// --- USER LOGIN ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = await readJson(USERS_FILE);

    if (!users[username]) return res.status(401).json({ error: "Not Found" });

    if (await bcrypt.compare(password, users[username].password)) {
        res.cookie('session_token', encrypt(JSON.stringify({ username, ts: Date.now() })), {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax'
        });
        return res.json({ success: true });
    }

    res.status(401).json({ error: "Bad Creds" });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('session_token');
    res.json({ success: true });
});

// --- ACCOUNT ---
app.post('/api/account', requireUserAuth, async (req, res) => {
    const users = await readJson(USERS_FILE);
    const user = users[req.user];

    const today = new Date().toISOString().split('T')[0];
    const counts = user.usage.date === today ? user.usage.counts : {};

    const remaining = {};
    for (const [m, limit] of Object.entries(user.limits)) {
        remaining[m] = Math.max(0, limit - (counts[m] || 0));
    }

    res.json({ username: req.user, remaining });
});

// --- CHAT LOAD ---
app.post('/api/chat/load', requireUserAuth, async (req, res) => {
    const h = await readJson(HISTORY_FILE);

    if (req.body.chatId) {
        const c = h[req.body.chatId];
        if (!c || c.owner !== req.user) return res.status(403).json({ error: "Denied" });
        return res.json({ chat: c });
    }

    const list = Object.entries(h)
        .filter(([_, d]) => d.owner === req.user)
        .map(([id, d]) => ({ id, title: d.title }));

    res.json({ list });
});

// --- CHAT ACTION ---
app.post('/api/chat/action', requireUserAuth, async (req, res) => {
    const h = await readJson(HISTORY_FILE);

    if (!h[req.body.chatId] || h[req.body.chatId].owner !== req.user) {
        return res.status(403).json({ error: "Denied" });
    }

    if (req.body.action === 'rename') h[req.body.chatId].title = req.body.newTitle;
    if (req.body.action === 'delete') delete h[req.body.chatId];

    await writeJson(HISTORY_FILE, h);
    res.json({ success: true });
});

// --- INFERENCE ---
app.post('/api/models', requireUserAuth, async (req, res) => {
    const { model, prompt, chatId, messages } = req.body;

    // --- Logs ---
    let logs = JSON.parse(fsSync.readFileSync("./logs.json", "utf8"));
    logs.push({ [req.ip]: `model: ${model} prompt: ${prompt}` });
    fsSync.writeFileSync("./logs.json", JSON.stringify(logs, null, 2));

    // 1. Validate Model
    const config = MODEL_REGISTRY[model];
    if (!config) return res.status(400).json({ error: `Invalid Model: ${model}` });

    // 2. Rate Limit
    if (!(await checkRateLimit(req.user, model))) {
        return res.status(429).json({ error: "Daily Limit Exceeded" });
    }

    // 3. Build Input
    const historyStr = (messages && messages.length)
        ? " (History: " + messages.map(m => `${m.role}: ${m.content}`).join(" | ") + ")"
        : "";

    const finalInput = `${prompt}${historyStr}`;
    const fetch = (await import("node-fetch")).default;

    try {
        let reply = "";

        // Ollama
        if (config.provider === "Ollama") {
            const apiRes = await fetch("https://ollama.com/api/generate", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OLM}`
                },
                body: JSON.stringify({
                    model,
                    prompt: finalInput + ` (Your a AI model named ${model}, your here to help user.)`,
                    stream: false
                })
            });

            const data = await apiRes.json();
            reply = data.response || "[No Content]";
        }

        // Google
        else if (config.provider === "Google") {
            const apiRes = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${API_KEYS.GAS}`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        contents: [{ parts: [{ text: finalInput }] }]
                    })
                }
            );

            const data = await apiRes.json();
            reply = data?.candidates?.[0]?.content?.parts?.[0]?.text || "[No Content]";
        }

        else if (config.provider === "OpenAI") {
            const apiRes = await fetch("https://api.openai.com/v1/responses", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OA}`
                },
                body: JSON.stringify({
                    model,
                    input: finalInput,
                    reasoning: {"effort": "low"}
                })
            });
            const data = await apiRes.json();
            reply = data?.output?.[1]?.content?.[0]?.text || "[No Content]";
            console.log("OpenAI Raw Res: " + JSON.stringify(data));
        }

        // Save Chat
        const h = await readJson(HISTORY_FILE);
        const id = chatId || uuidv4();

        if (!h[id]) {
            h[id] = {
                owner: req.user,
                title: prompt.substring(0, 20) || "New Chat",
                messages: []
            };
        }

        h[id].messages.push({ role: "user", content: prompt });
        h[id].messages.push({ role: "ai", content: reply });

        await writeJson(HISTORY_FILE, h);

        res.json({ reply, chatId: id });

    } catch (e) {
        console.error("Model Error:", e);
        res.status(500).json({ error: e.message });
    }
});

// --- START SERVER ---
app.listen(PORT, () => console.log(`Zelfa Core Online: ${PORT}`));
