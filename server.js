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
    // console.log("Req from " + req.ip + ", path is " + req.path);
    next();
});

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const DOMAIN = 'zelfa.nethacker.cloud';

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
    'kimi-k2-thinking': { provider: 'Ollama' },
    'qwen3-coder:480b': { provider: 'Ollama' },
    'deepseek-v3.1:671b': { provider: 'Ollama' },
    'gpt-oss:120b': { provider: 'Ollama' },
    'gemini-2.0-flash': { provider: 'Google' },
    'gpt-5-nano': { provider: 'OpenAI' },
    'o3-mini': { provider: 'OpenAI' },
    'gpt-5.1-codex-mini': { provider: 'OpenAI' }
};

// --- FILE OPS ---
const SAVED_CHATS_FILE = path.join(__dirname, 'saved_chats.json');

if (!fs.existsSync(SAVED_CHATS_FILE)) {
    fs.writeFileSync(SAVED_CHATS_FILE, JSON.stringify({}));
}

// --- MIDDLEWARE ---
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
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
    
    if (record.count >= 135) {
        return res.status(429).json({ error: "Rate limit exceeded (135/day)." });
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

app.all("/healthz", (req, res) => {
    res.status(200).send("true");
});

app.post('/api/save', async (req, res) => {
    const { history, model } = req.body;
    if (!history || history.length < 10) {
        return res.status(400).json({ error: "Insufficient data. Need at least 5 interaction cycles." });
    }
    const chatId = uuidv4();
    const savedData = JSON.parse(fs.readFileSync(SAVED_CHATS_FILE));
    savedData[chatId] = {
        timestamp: new Date().toISOString(),
        model: model,
        history: history
    };
    fs.writeFileSync(SAVED_CHATS_FILE, JSON.stringify(savedData, null, 2));
    res.json({ link: `https://${DOMAIN}/chat/${chatId}`, id: chatId });
});

// --- STREAMING INFERENCE API ---
app.post('/api/models', checkRateLimit, async (req, res) => {
    const { model, messages } = req.body;
    const config = MODEL_REGISTRY[model];
    
    if (!config) return res.status(400).json({ error: `Invalid Model` });

    // Memory protection: Keep last 15 messages
    const recentMessages = messages.slice(-15).map(m => ({
        role: m.role === 'ai' ? 'assistant' : m.role,
        content: m.content
    }));

    // Setup Server-Sent Events / Stream Header
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Transfer-Encoding', 'chunked');

    try {
        
        // --- OLLAMA STREAMING ---
        if (config.provider === "Ollama") {
            const apiRes = await fetch("https://ollama.com/api/chat", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OLM}`
                },
                body: JSON.stringify({
                    model: model,
                    messages: recentMessages,
                    stream: true // Enable Streaming
                })
            });

            // Ollama sends JSON objects one per line
            for await (const chunk of apiRes.body) {
                const lines = chunk.toString().split('\n');
                for (const line of lines) {
                    if (!line.trim()) continue;
                    try {
                        const json = JSON.parse(line);
                        if (json.message && json.message.content) {
                            res.write(json.message.content);
                        }
                    } catch (e) { /* ignore parse errors for partial chunks */ }
                }
            }
        }

        // --- OPENAI STREAMING ---
        else if (config.provider === "OpenAI") {
            const apiRes = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OA}`
                },
                body: JSON.stringify({
                    model: model,
                    messages: recentMessages,
                    stream: true // Enable Streaming
                })
            });

            // OpenAI sends "data: {JSON}"
            for await (const chunk of apiRes.body) {
                const lines = chunk.toString().split('\n');
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const jsonStr = line.replace('data: ', '').trim();
                        if (jsonStr === '[DONE]') continue;
                        try {
                            const json = JSON.parse(jsonStr);
                            const text = json.choices[0]?.delta?.content || '';
                            if (text) res.write(text);
                        } catch (e) { }
                    }
                }
            }
        }

        // --- GOOGLE STREAMING (SSE Mode) ---
        else if (config.provider === "Google") {
            const googleContents = recentMessages.map(m => ({
                role: m.role === 'user' ? 'user' : 'model',
                parts: [{ text: m.content }]
            }));

            // Use streamGenerateContent with alt=sse for easier parsing
            const apiRes = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${API_KEYS.GAS}`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ contents: googleContents })
                }
            );

            for await (const chunk of apiRes.body) {
                const lines = chunk.toString().split('\n');
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        try {
                            const json = JSON.parse(line.replace('data: ', '').trim());
                            const text = json.candidates?.[0]?.content?.parts?.[0]?.text || '';
                            if (text) res.write(text);
                        } catch (e) { }
                    }
                }
            }
        }

        res.end(); // Finish stream

    } catch (e) {
        console.error("Stream Error:", e);
        res.write("\n[System Error: Connection interrupted]");
        res.end();
    }
});

app.listen(PORT, () => console.log(`Zelfa Hacker Edition Online: ${PORT}`));
