// --- MODULE IMPORTS ---
const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');

const app = express();
app.set('trust proxy', true);

// --- CONFIG ---
const PORT = process.env.PORT || 3000;

const RLD_FILE = path.join(__dirname, 'rld.json');
const SAVED_DIR = path.join(__dirname, 'saved');
const SAVED_CHATS_FILE = path.join(SAVED_DIR, 'chats.json');

const API_KEYS = {
    OA: process.env.OAAPI || "",
    OLM: process.env.OLMAPI || ""
};

// --- MODEL REGISTRY ---
const MODEL_REGISTRY = {

    // Ollama
    'gpt-oss:120b': { provider: 'Ollama' },
    'devstral-2:123b': { provider: 'Ollama' },
    'rnj-1:8b': { provider: 'Ollama' },
    'cogito-2.1:671b': { provider: 'Ollama' },
    'glm-5': { provider: 'Ollama' },
    'kimi-k2.5': { provider: 'Ollama' },
    'qwen3-vl:235b': { provider: 'Ollama' },
    'qwen3-coder:480b': { provider: 'Ollama' },
    'deepseek-v3.2': { provider: 'Ollama' },
    'gemma3:27b': { provider: 'Ollama' },
    'ministral-3:14b': { provider: 'Ollama' },
    'minimax-m2.5': { provider: 'Ollama' },
    'qwen3-coder-next': { provider: 'Ollama' },
    'gemini-3-flash-preview': { provider: 'Ollama' },
    'nemotron-3-nano:30b': { provider: 'Ollama' },
    'qwen3-next:80b': { provider: 'Ollama' },
    'qwen3.5:397b': { provider: 'Ollama' },
    'gemma4:31b': { provider: 'Ollama' },

    // OpenAI
    'gpt-4o': { provider: 'OpenAI', flex: true },
    'gpt-4.1': { provider: 'OpenAI', flex: true },
    'gpt-5-nano': { provider: 'OpenAI', flex: true },
    'gpt-4o-mini': { provider: 'OpenAI' },
    'gpt-4.1-nano': { provider: 'OpenAI' },
    'gpt-5-mini': { provider: 'OpenAI', flex: true },
    'gpt-3.5-turbo': { provider: 'OpenAI' },
    'gpt-5': { provider: 'OpenAI', flex: true },
    'gpt-5.1': { provider: 'OpenAI', flex: true },
    'gpt-5.2': { provider: 'OpenAI', flex: true },
    'o4-mini': { provider: 'OpenAI', flex: true },
    'gpt-5.4': { provider: 'OpenAI', flex: true },
    'gpt-5.4-nano': { provider: 'OpenAI', flex: true },
    'gpt-5.4-mini': { provider: 'OpenAI', flex: true }

};

// --- FILE INIT ---
if (!fs.existsSync(RLD_FILE)) {
    fs.writeFileSync(RLD_FILE, JSON.stringify({}));
}

if (!fs.existsSync(SAVED_DIR)) {
    fs.mkdirSync(SAVED_DIR);
}

if (!fs.existsSync(SAVED_CHATS_FILE)) {
    fs.writeFileSync(SAVED_CHATS_FILE, JSON.stringify({}));
}

// --- MIDDLEWARE ---
app.use(bodyParser.json({ limit: "1mb" }));

app.use(express.static(path.join(__dirname, 'public')));

// --- DEBUG LOG ---
app.use((req, res, next) => {
    try {
        console.log(
            "PATH:", req.path,
            "UA:", req.headers["user-agent"],
            "BODY:", JSON.stringify(req.body || {})
        );
    } catch {}
    next();
});

// --- SECURITY HEADERS ---
app.use((req, res, next) => {

    res.setHeader('Access-Control-Allow-Origin', 'https://zelfa.zone.id');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }

    next();
});

// --- RATE LIMIT GROUP ---
const getModelGroup = (model) => {

    if (['gpt-5', 'gpt-5.1', 'gpt-5.2', 'gpt-5.4', 'gpt-4.1', 'gpt-4o'].includes(model)) {
        return { group: 'D', limit: 30 };
    }

    if (model === 'gpt-3.5-turbo') {
        return { group: 'C', limit: 120 };
    }

    if ([
        'o4-mini',
        'gpt-5-mini',
        'gpt-4.1-nano',
        'gpt-4o-mini',
        'gpt-5.4-nano',
        'gpt-5.4-mini'
    ].includes(model)) {
        return { group: 'B', limit: 230 };
    }

    return { group: 'A', limit: 200 };
};

// --- DAILY LIMIT STORAGE ---
let rlQueue = Promise.resolve();

function todayKey() {
    return new Date().toISOString().slice(0, 10);
}

async function checkDailyLimit(model) {

    return new Promise((resolve) => {

        rlQueue = rlQueue.then(() => {

            let data = {};

            try {
                data = JSON.parse(fs.readFileSync(RLD_FILE));
            } catch {
                data = {};
            }

            const today = todayKey();
            const { group, limit } = getModelGroup(model);

            if (!data[today]) data[today] = {};
            if (!data[today][group]) data[today][group] = 0;

            if (data[today][group] >= limit) {
                resolve(false);
                return;
            }

            data[today][group]++;

            fs.writeFileSync(RLD_FILE, JSON.stringify(data));

            resolve(true);

        });

    });

}

// --- GLOBAL COOLDOWN ---
let lastRequestTime = 0;

// --- ROUTES ---

app.get('/', (req, res) => {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- MAIN API ---
app.post('/api/models', async (req, res) => {

    try {

        const now = Date.now();
        const model = req.body.model || "none";

        // --- GLOBAL COOLDOWN ---
        if (now - lastRequestTime < 5000 && model !== 'gpt-5-nano') {
            return res
                .status(403)
                .type("text")
                .send("ERROR 403 Access Denied: Cooldown.");
        }

        if (model !== 'gpt-5-nano') {
            lastRequestTime = now;
        }

        const { messages } = req.body || {};
        const config = MODEL_REGISTRY[model];

        if (!config) {
            return res.status(400).json({ error: "Invalid model" });
        }

        // --- DAILY LIMIT ---
        const allowed = await checkDailyLimit(model);

        if (!allowed) {
            return res.status(429).send("Daily model group limit reached.");
        }

        const recentMessages = (messages || [])
            .slice(-6)
            .map(m => ({
                role: m.role === 'ai' ? 'assistant' : m.role,
                content: m.content
            }));

        // --- FETCH MODEL ---
        let apiRes;

        if (config.provider === "Ollama") {

            apiRes = await fetch("https://ollama.com/api/chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OLM}`
                },
                body: JSON.stringify({
                    model,
                    messages: recentMessages,
                    stream: true
                })
            });

        } else {

            const isFlex = config.flex === true;

            apiRes = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OA}`
                },
                body: JSON.stringify({
                    model,
                    messages: recentMessages,
                    stream: true,
                    service_tier: isFlex ? "flex" : "default",
                    max_completion_tokens: 8000
                })
            });

        }

        if (!apiRes.ok) {
            const text = await apiRes.text();
            return res.status(apiRes.status).send(text);
        }

        // --- STREAM RESPONSE ---
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Transfer-Encoding', 'chunked');

        let buffer = "";

        for await (const chunk of apiRes.body) {

            const lines = (buffer + chunk.toString()).split('\n');
            buffer = lines.pop();

            for (const line of lines) {

                const trimmed = line.trim();
                if (!trimmed) continue;

                try {

                    let text = "";

                    if (config.provider === "Ollama") {

                        const json = JSON.parse(trimmed);

                        if (json.message?.content) {
                            text = json.message.content;
                        }

                    } else {

                        if (trimmed.startsWith('data: ')) {

                            const dataStr = trimmed.replace('data: ', '');

                            if (dataStr !== '[DONE]') {

                                const json = JSON.parse(dataStr);
                                text = json.choices[0]?.delta?.content || "";

                            }
                        }

                    }

                    if (text) res.write(text);

                } catch {}

            }

        }

        return res.end();

    } catch (err) {

        console.error("Stream Error:", err);

        if (!res.headersSent) {
            return res.status(500).send("Internal server error");
        }

        res.write("\n[System Error: Connection interrupted]");
        return res.end();

    }

});

// --- ROBOTS ---
app.get(['/robots.txt','/Robots.txt','/robot.txt'], (req,res)=>{
    return res.sendFile(path.join(__dirname,"public","robots.txt"));
});

// --- FALLBACK ---
app.all("*", (req, res) => {
    return res.redirect("https://zelfa.zone.id/");
});

// --- START ---
app.listen(PORT, () => {
    console.log(`Zelfa Hacker Edition Online: ${PORT}`);
});
