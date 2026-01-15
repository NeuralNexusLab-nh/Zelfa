// --- MODULE IMPORTS ---
const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');

const app = express();
app.set('trust proxy', true);

// Debug Log
app.use((req, res, next) => {
    console.log("Req from " + req.ip + ", path is " + req.path);
    next();
});

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const RLD_FILE = path.join(__dirname, 'rld.json');

const API_KEYS = {
    OA: process.env.OAAPI || "",
    OLM: process.env.OLMAPI || ""
};

// --- MODEL REGISTRY ---
const MODEL_REGISTRY = {
    'gpt-oss:120b': { provider: 'Ollama' },
    'devstral-2:123b': { provider: 'Ollama' },
    'rnj-1:8b': { provider: 'Ollama' },
    'cogito-2.1:671b': { provider: 'Ollama' },
    'glm-4.7': { provider: 'Ollama' },
    'kimi-k2:1t': { provider: 'Ollama' },
    'qwen3-vl:235b': { provider: 'Ollama' },
    'qwen3-coder:480b': { provider: 'Ollama' },
    'deepseek-v3.2': { provider: 'Ollama' },
    'gemma3:27b': { provider: 'Ollama' },
    'ministral-3:14b': { provider: 'Ollama' },
    'minimax-m2.1': { provider: 'Ollama' },
    'gemini-3-flash-preview': { provider: 'Ollama' },
    'nemotron-3-nano:30b': { provider: 'Ollama' },
    'qwen3-next:80b': { provider: 'Ollama' },
    'gpt-5-nano': { provider: 'OpenAI', flex: true },
    'gpt-4o-mini': { provider: 'OpenAI' },
    'gpt-4.1-nano': { provider: 'OpenAI' },
    'gpt-5-mini': { provider: 'OpenAI', flex: true },
    'gpt-5': { provider: 'OpenAI', flex: true },
    'gpt-5.1': { provider: 'OpenAI', flex: true },
    'gpt-5.2': { provider: 'OpenAI', flex: true },
    'gpt-3.5-turbo': { provider: 'OpenAI' },
    'o4-mini': { provider: 'OpenAI', flex: true }
};

// --- FILE INITIALIZATION ---
if (!fs.existsSync(RLD_FILE)) {
    fs.writeFileSync(RLD_FILE, JSON.stringify({}));
}
const SAVED_DIR = path.join(__dirname, 'saved');
const SAVED_CHATS_FILE = path.join(SAVED_DIR, 'chats.json');
if (!fs.existsSync(SAVED_DIR)) fs.mkdirSync(SAVED_DIR);
if (!fs.existsSync(SAVED_CHATS_FILE)) fs.writeFileSync(SAVED_CHATS_FILE, JSON.stringify({}));

// --- RATE LIMIT QUEUE SYSTEM ---
let rlQueue = Promise.resolve();

const getModelGroup = (model) => {
    if (model === 'gpt-5.2') return { group: 'D', limit: 5 };
    if (model === 'gpt-5' || model === 'gpt-5.1') return { group: 'C', limit: 10 };
    if (model === 'o4-mini' || model === 'gpt-5-mini' || model === 'gpt-3.5-turbo') return { group: 'B', limit: 20 };
    return { group: 'A', limit: 40 }; // Ollama + Nano/Mini models
};

// --- MIDDLEWARE ---
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); 
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// --- ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// --- STREAMING INFERENCE API ---
app.post('/api/models', async (req, res) => {
    const { model, messages } = req.body;
    const config = MODEL_REGISTRY[model];
    if (!config) return res.status(400).json({ error: `Invalid Model` });

    const ip = req.ip || "unknown";
    const today = new Date().toISOString().split('T')[0];
    const groupInfo = getModelGroup(model);

    // --- 佇列鎖定：確保 RateLimit 存取順序 ---
    let release;
    const waitPromise = new Promise(resolve => release = resolve);
    const previousQueue = rlQueue;
    rlQueue = previousQueue.then(() => waitPromise);

    await previousQueue;

    try {
        let rld = JSON.parse(fs.readFileSync(RLD_FILE, 'utf8'));
        if (!rld[ip] || rld[ip].date !== today) {
            rld[ip] = { date: today, A: 0, B: 0, C: 0 };
        }

        const currentCount = rld[ip][groupInfo.group];
        if (currentCount >= groupInfo.limit) {
            release(); // 釋放鎖定
            return res.status(429).json({ error: `Rate limit exceeded for Group ${groupInfo.group} (${groupInfo.limit}/day).` });
        }

        // 更新計數並存檔
        rld[ip][groupInfo.group]++;
        fs.writeFileSync(RLD_FILE, JSON.stringify(rld, null, 2));

        // --- 準備 API 請求 ---
        const recentMessages = messages.slice(-15).map(m => ({
            role: m.role === 'ai' ? 'assistant' : m.role,
            content: m.content
        }));

        let fetchPromise;
        if (config.provider === "Ollama") {
            fetchPromise = fetch("https://ollama.com/api/chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OLM}`
                },
                body: JSON.stringify({ model: model, messages: recentMessages, stream: true })
            });
        } else {
            // OpenAI 邏輯 (包含 Flex 判定)
            const isFlex = config.flex === true;
            fetchPromise = fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OA}`
                },
                body: JSON.stringify({
                    model: model,
                    messages: recentMessages,
                    stream: true,
                    service_tier: isFlex ? "flex" : "default"
                })
            });
        }

        // --- 關鍵步驟：發出請求後立刻釋放鎖定，不等待串流完成 ---
        const apiRes = await fetchPromise;
        release(); 

        // --- 處理串流回應 ---
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
                        if (json.message && json.message.content) text = json.message.content;
                    } else {
                        if (trimmed.startsWith('data: ')) {
                            const dataStr = trimmed.replace('data: ', '').trim();
                            if (dataStr !== '[DONE]') {
                                const json = JSON.parse(dataStr);
                                text = json.choices[0]?.delta?.content || "";
                            }
                        }
                    }
                    if (text) res.write(text);
                } catch (e) {}
            }
        }
        res.end();

    } catch (e) {
        release(); // 發生錯誤也要記得釋放鎖定
        console.error("Stream Error:", e);
        if (!res.headersSent) res.status(500);
        res.write("\n[System Error: Connection interrupted]");
        res.end();
    }
});

// --- STATIC ROUTES & ROBOTS ---
app.get("/robots.txt", (req, res) => res.sendFile(path.join(__dirname, "public", "robots.txt")));
app.get("/Robots.txt", (req, res) => res.sendFile(path.join(__dirname, "public", "robots.txt")));
app.get("/robot.txt", (req, res) => res.sendFile(path.join(__dirname, "public", "robots.txt")));

app.all("*", (req, res) => {
    res.redirect("https://zelfaz.nethacker.cloud");
});

app.listen(PORT, () => console.log(`Zelfa Hacker Edition Online: ${PORT}`));
