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

const API_KEYS = {
    GAS: process.env.GASAPI || "",
    OA: process.env.OAAPI || "",
    OLM: process.env.OLMAPI || ""
};

// --- MODEL REGISTRY ---
const MODEL_REGISTRY = {
    'cogito-2.1:671b': { provider: 'Ollama' },
    'glm-4.6': { provider: 'Ollama' },
    'kimi-k2:1t': { provider: 'Ollama' },
    'qwen3-coder:480b': { provider: 'Ollama' },
    'deepseek-v3.2': { provider: 'Ollama' },
    'gemma3:27b': { provider: 'Ollama' },
    'gemini-3-pro-preview': { provider: 'Ollama' },
    'ministral-3:14b': { provider: 'Ollama' },
    'minimax-m2': { provider: 'Ollama' },
    'gemini-2.0-flash': { provider: 'Google' },
    'gpt-5-nano': { provider: 'OpenAI' },
    'gpt-4o-mini': { provider: 'OpenAI' },
    'gpt-4.1-nano': { provider: 'OpenAI' }
};

// --- FILE OPS (BUG FIXED HERE) ---
const SAVED_DIR = path.join(__dirname, 'saved'); // 定義資料夾路徑
const SAVED_CHATS_FILE = path.join(SAVED_DIR, 'chats.json'); // 定義檔案路徑

// 1. 先檢查資料夾是否存在，不存在就建立
if (!fs.existsSync(SAVED_DIR)) {
    fs.mkdirSync(SAVED_DIR);
}

// 2. 再檢查檔案是否存在，不存在就建立
if (!fs.existsSync(SAVED_CHATS_FILE)) {
    fs.writeFileSync(SAVED_CHATS_FILE, JSON.stringify({}));
}

// --- MIDDLEWARE ---
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Security & CORS Headers
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); 
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// --- RATE LIMITER ---
const ipLimits = new Map();
const checkRateLimit = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const today = new Date().toISOString().split('T')[0];
    let record = ipLimits.get(ip);
    
    if (!record || record.date !== today) {
        record = { date: today, count: 0 };
    }
    
    if (record.count >= 50) {
        return res.status(429).json({ error: "Rate limit exceeded (50/day)." });
    }
    
    record.count++;
    ipLimits.set(ip, record);
    next();
};

// --- ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.get('/chat/:id', (req, res) => {
    const savedData = JSON.parse(fs.readFileSync(SAVED_CHATS_FILE));
    if (!savedData[req.params.id]) {
        return res.status(404).send("404 // LOG NOT FOUND");
    }
    res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

app.get('/api/saved/:id', (req, res) => {
    const savedData = JSON.parse(fs.readFileSync(SAVED_CHATS_FILE));
    const chat = savedData[req.params.id];
    if (chat) res.json(chat);
    else res.status(404).json({ error: "Not found" });
});

app.post('/api/save', async (req, res) => {
    const { history, model } = req.body;
    if (!history || history.length < 2) {
        return res.status(400).json({ error: "Insufficient data to save." });
    }
    
    const chatId = uuidv4();
    const savedData = JSON.parse(fs.readFileSync(SAVED_CHATS_FILE));
    
    savedData[chatId] = {
        timestamp: new Date().toISOString(),
        model: model,
        history: history
    };
    
    fs.writeFileSync(SAVED_CHATS_FILE, JSON.stringify(savedData, null, 2));

    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.get('host');
    const dynamicLink = `${protocol}://${host}/chat/${chatId}`;

    res.json({ link: dynamicLink, id: chatId });
});

// --- STREAMING INFERENCE API ---
app.post('/api/models', checkRateLimit, async (req, res) => {
    var { model, messages } = req.body;
    const config = MODEL_REGISTRY[model];
    
    if (!config) return res.status(400).json({ error: `Invalid Model` });

    const recentMessages = messages.slice(-15).map(m => ({
        role: m.role === 'ai' ? 'assistant' : m.role,
        content: m.content
    }));

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Transfer-Encoding', 'chunked');

    try {
        let apiRes;
        
        // --- OLLAMA ---
        if (config.provider === "Ollama") {
            apiRes = await fetch("https://ollama.com/api/chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OLM}`
                },
                body: JSON.stringify({
                    model: model,
                    messages: recentMessages,
                    stream: true 
                })
            });
        }

        // --- OPENAI ---
        else if (config.provider === "OpenAI") {
            apiRes = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OA}`
                },
                body: JSON.stringify({
                    model: model,
                    messages: recentMessages,
                    stream: true 
                })
            });
        }

        // --- GOOGLE ---
        else if (config.provider === "Google") {
            const googleContents = recentMessages.map(m => ({
                role: m.role === 'user' ? 'user' : 'model',
                parts: [{ text: m.content }]
            }));

            apiRes = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${API_KEYS.GAS}`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ contents: googleContents })
                }
            );
        }

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
                        if (json.message && json.message.content) {
                            text = json.message.content;
                        }
                    } 
                    else if (config.provider === "OpenAI") {
                        if (trimmed.startsWith('data: ')) {
                            const dataStr = trimmed.replace('data: ', '').trim();
                            if (dataStr !== '[DONE]') {
                                const json = JSON.parse(dataStr);
                                text = json.choices[0]?.delta?.content || "";
                            }
                        }
                    }
                    else if (config.provider === "Google") {
                        if (trimmed.startsWith('data: ')) {
                            const json = JSON.parse(trimmed.replace('data: ', '').trim());
                            text = json.candidates?.[0]?.content?.parts?.[0]?.text || "";
                        }
                    }

                    if (text) res.write(text);

                } catch (e) { 
                }
            }
        }
        
        res.end();

    } catch (e) {
        console.error("Stream Error:", e);
        res.write("\n[System Error: Connection interrupted]");
        res.end();
    }
});

app.listen(PORT, () => console.log(`Zelfa Hacker Edition Online: ${PORT}`));
