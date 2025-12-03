// --- MODULE IMPORTS ---
const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch'); // 使用 v2 版本

const app = express();
app.set('trust proxy', true);

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const DOMAIN = 'zelfa.nethacker.cloud'; // 你的域名

// API Keys (請確保環境變數已設定)
const API_KEYS = {
    GAS: process.env.GASAPI || "",
    OA: process.env.OAAPI || "",
    OLM: process.env.OLMAPI || ""
};

// --- MODEL REGISTRY (保持原樣) ---
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

// 初始化儲存檔案
if (!fs.existsSync(SAVED_CHATS_FILE)) {
    fs.writeFileSync(SAVED_CHATS_FILE, JSON.stringify({}));
}

// --- MIDDLEWARE ---
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

// --- RATE LIMITER (In-Memory) ---
const ipLimits = new Map(); // Key: IP, Value: { date: 'YYYY-MM-DD', count: 0 }

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

// 1. 首頁 (Chat Interface)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 2. 查看公開對話頁面
app.get('/chat/:id', (req, res) => {
    // 簡單檢查 ID 是否存在，若存在回傳 view 頁面，具體資料由前端 fetch
    const savedData = JSON.parse(fs.readFileSync(SAVED_CHATS_FILE));
    if (!savedData[req.params.id]) {
        return res.status(404).send("404 // LOG NOT FOUND OR DELETED");
    }
    res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

// 3. 獲取已儲存對話的 API (給 view.html 用)
app.get('/api/saved/:id', (req, res) => {
    const savedData = JSON.parse(fs.readFileSync(SAVED_CHATS_FILE));
    const chat = savedData[req.params.id];
    if (chat) {
        res.json(chat);
    } else {
        res.status(404).json({ error: "Not found" });
    }
});

// 4. 儲存對話 API
app.post('/api/save', async (req, res) => {
    const { history, model } = req.body;

    // 限制：至少 5 次對話 (User + AI = 2，所以 5 次對話約等於 10 條訊息)
    // 這裡我們寬鬆判定，只要陣列長度 >= 10 即可
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

// 5. 模型推理 API (核心邏輯)
app.post('/api/models', checkRateLimit, async (req, res) => {
    const { model, prompt, messages } = req.body; // messages 是前端傳來的完整歷史

    // 1. Validate Model
    const config = MODEL_REGISTRY[model];
    if (!config) return res.status(400).json({ error: `Invalid Model: ${model}` });

    // 2. Construct Input (保持原本邏輯)
    // 原本邏輯是 "prompt (History: ...)"，我們這邊把前端傳來的 messages 轉成字串
    // 過濾掉最後一條 (因為那是當前的 prompt)，避免重複
    const historyContext = messages.slice(0, -1); 
    
    const historyStr = (historyContext && historyContext.length)
        ? " (History: " + historyContext.map(m => `${m.role}: ${m.content}`).join(" | ") + ")"
        : "";

    const finalInput = `${prompt}${historyStr}`;

    try {
        let reply = "";

        // --- Original API Logic ---
        
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

        // OpenAI (Custom Endpoint from original code)
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
            // console.log("OpenAI Raw Res: " + JSON.stringify(data));
        }

        res.json({ reply });

    } catch (e) {
        console.error("Model Error:", e);
        res.status(500).json({ error: "Inference Failed" });
    }
});

// --- START SERVER ---
app.listen(PORT, () => console.log(`Zelfa Hacker Edition Online: ${PORT}`));
