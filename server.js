// --- MODULE IMPORTS ---
const express = require('express');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');

const app = express();
app.set('trust proxy', true);

// --- DEBUG LOG ---
app.use((req, res, next) => {
    console.log("Req from " + req.ip + ", path is " + req.path);
    next();
});

// --- CONFIG ---
const PORT = process.env.PORT || 3000;

const API_KEYS = {
    OA: process.env.OAAPI || "",
    OLM: process.env.OLMAPI || "",
    GH: process.env.GHAPI || ""
};

// --- MODEL REGISTRY ---
const MODEL_REGISTRY = {
    // --- OLLAMA ---
    'gpt-oss:120b': { provider: 'Ollama' },
    'devstral-2:123b': { provider: 'Ollama' },
    'rnj-1:8b': { provider: 'Ollama' },
    'cogito-2.1:671b': { provider: 'Ollama' },
    'glm-4.6': { provider: 'Ollama' },
    'kimi-k2:1t': { provider: 'Ollama' },
    'qwen3-vl:235b': { provider: 'Ollama' },
    'qwen3-coder:480b': { provider: 'Ollama' },
    'deepseek-v3.2': { provider: 'Ollama' },
    'gemma3:27b': { provider: 'Ollama' },
    'gemini-3-pro-preview': { provider: 'Ollama' },
    'ministral-3:14b': { provider: 'Ollama' },
    'minimax-m2': { provider: 'Ollama' },

    // --- OPENAI ---
    'gpt-5-nano': { provider: 'OpenAI' },
    'gpt-5-mini': { provider: 'OpenAI' },
    'gpt-4o-mini': { provider: 'OpenAI' },
    'gpt-4.1-nano': { provider: 'OpenAI' },
    'gpt-4o-mini-search-preview': { provider: 'OpenAI' },

    // --- GITHUB MODELS ---
    'microsoft/Phi-4': { provider: 'GitHub' },
    'microsoft/Phi-4-reasoning': { provider: 'GitHub' },
    'openai/gpt-4o-mini': { provider: 'GitHub' },
    'meta/Meta-Llama-3.1-8B-Instruct': { provider: 'GitHub' }
};

// --- FILE OPS ---
const SAVED_DIR = path.join(__dirname, 'saved');
const SAVED_CHATS_FILE = path.join(SAVED_DIR, 'chats.json');

if (!fs.existsSync(SAVED_DIR)) fs.mkdirSync(SAVED_DIR);
if (!fs.existsSync(SAVED_CHATS_FILE)) fs.writeFileSync(SAVED_CHATS_FILE, JSON.stringify({}));

// --- MIDDLEWARE ---
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- SECURITY HEADERS ---
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// --- RATE LIMIT ---
const ipLimits = new Map();
const checkRateLimit = (req, res, next) => {
    const ip = req.ip || "";
    const today = new Date().toISOString().split('T')[0];
    let record = ipLimits.get(ip);

    if (!record || record.date !== today) {
        record = { date: today, count: 0 };
    }

    if (record.count >= 30) {
        return res.status(429).json({ error: "Rate limit exceeded (30/day)." });
    }

    record.count++;
    ipLimits.set(ip, record);
    next();
};

// --- ROUTES ---
app.get('/', (req, res) =>
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

// --- STREAMING INFERENCE ---
app.post('/api/models', checkRateLimit, async (req, res) => {
    const { model, messages } = req.body;
    const config = MODEL_REGISTRY[model];

    if (!config) return res.status(400).json({ error: "Invalid model" });

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
                    model,
                    messages: recentMessages,
                    stream: true
                })
            });
        }

        // --- OPENAI ---
        else if (config.provider === "OpenAI") {
            let st;
            if (model === "gpt-5-mini" || model === "gpt-5-nano") {
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


        // --- GITHUB MODELS ---
        else if (config.provider === "GitHub") {
            apiRes = await fetch(
                "https://models.github.ai/inference/chat/completions",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${API_KEYS.GH}`
                    },
                    body: JSON.stringify({
                        model,
                        messages: recentMessages,
                        stream: true
                    })
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

                let text = "";

                // --- OLLAMA ---
                if (config.provider === "Ollama") {
                    const json = JSON.parse(trimmed);
                    text = json?.message?.content || "";
                }

                // --- OPENAI & GITHUB (SAME FORMAT) ---
                else {
                    if (trimmed.startsWith("data: ")) {
                        const data = trimmed.replace("data: ", "").trim();
                        if (data !== "[DONE]") {
                            const json = JSON.parse(data);
                            text = json.choices?.[0]?.delta?.content || "";
                        }
                    }
                }

                if (text) res.write(text);
            }
        }

        res.end();

    } catch (e) {
        console.error("Stream error:", e);
        res.write("\n[System Error]");
        res.end();
    }
});

// --- FALLBACK ---
app.all("*", (req, res) => {
    res.redirect("https://zelfaz.nethacker.cloud");
});

app.listen(PORT, () =>
    console.log(`Zelfa Hacker Edition Online: ${PORT}`)
);
