require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const AI_MODEL = "meta-llama/llama-3.1-8b-instruct:free";
const APP_URL = process.env.APP_URL || "https://taya-ai-api.onrender.com";

const systemPrompt = `Tu es TAYA IA V13, l'assistante de Maruce à Conakry, Guinée. Tu es chaleureuse, utile, tu parles en français simple. Tu aides pour la vie quotidienne, les études, le business.`;

app.get('/', (req, res) => {
  res.json({ status: 'TAYA IA V13 est Live !', model: AI_MODEL });
});

app.post('/api/chat', async (req, res) => {
  try {
    const { messages, message } = req.body;
    
    let cleanMessages = [];
    if (messages && Array.isArray(messages)) {
      cleanMessages = messages;
    } else if (message) {
      cleanMessages = [{ role: "user", content: message }];
    } else {
      return res.status(400).json({ error: "Message manquant" });
    }

    if (!OPENROUTER_API_KEY) {
      return res.status(500).json({ error: "OPENROUTER_API_KEY manquant sur Render" });
    }

    // On garde seulement les 6 derniers pour économiser les crédits
    const limitedMessages = cleanMessages.slice(-6);

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": APP_URL,
          "X-Title": "TAYA IA V13"
        },
        body: JSON.stringify({
          model: AI_MODEL,
          messages: [
            {
              role: "system",
              content: systemPrompt
            },
            ...limitedMessages
          ],
          temperature: 0.7,
          max_tokens: 1000
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("OpenRouter Error:", result);
      return res.status(502).json({
        error: "Le service IA est temporairement indisponible.",
        details: result?.error?.message || JSON.stringify(result)
      });
    }

    const answer = result.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        error: "L'IA n'a pas renvoyé de réponse."
      });
    }

    res.json({ 
      reply: answer,
      answer: answer,
      response: answer
    });

  } catch (err) {
    console.error("Server Error:", err);
    res.status(500).json({ error: "Erreur serveur: " + err.message });
  }
});

// Compatibilité avec d'autres routes que ton frontend peut utiliser
app.post('/chat', async (req, res) => {
  req.url = '/api/chat';
  app.handle(req, res);
});

app.listen(PORT, () => {
  console.log(`TAYA IA V13 lancée sur le port ${PORT} avec modèle ${AI_MODEL}`);
});
