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
    'gpt-5-nano': { provider: 'OpenAI' },
    'gpt-4o-mini': { provider: 'OpenAI' },
    'gpt-4.1-nano': { provider: 'OpenAI' },
    'gpt-5-mini': { provider: 'OpenAI' }
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
    const ip = req.ip || "";
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
            var st;
            if (model == "gpt-5-mini" || model == "gpt-5-nano") {
                st = "flex";
            } else {
                st = "default";
            }
            
            apiRes = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${API_KEYS.OA}`
                },
                body: JSON.stringify({
                    model: model,
                    messages: recentMessages,
                    stream: true,
                    service_tier: st,
                    ...(model.includes("search") && {
                        web_search_options: {}
                    })
                })
            });
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
                    else if (config.provider === "OpenAI" || config.provider === "Zelfa") {
                        if (trimmed.startsWith('data: ')) {
                            const dataStr = trimmed.replace('data: ', '').trim();
                            if (dataStr !== '[DONE]') {
                                const json = JSON.parse(dataStr);
                                text = json.choices[0]?.delta?.content || "";
                            }
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

app.get("/robots.txt", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "robots.txt"));
});

app.get("/Robots.txt", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "robots.txt"));
});

app.get("/robot.txt", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "robots.txt"));
});

app.all("*", (req, res) => {
    res.redirect("https://zelfaz.nethacker.cloud");
});

app.listen(PORT, () => console.log(`Zelfa Hacker Edition Online: ${PORT}`));
