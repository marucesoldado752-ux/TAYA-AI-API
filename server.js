require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

app.use(helmet());

app.use(cors({
  origin: [
    "https://marucesoldado752-ux.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
  ]
}));

app.use(express.json({ limit: "10mb" }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  message: {
    error: "Trop de demandes. Réessaie dans quelques minutes."
  }
}));

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.OPENROUTER_API_KEY;
const MODEL = process.env.AI_MODEL || "openrouter/auto";

app.get("/", (req, res) => {
  res.json({
    name: "TAYA AI",
    version: "2.0.0",
    status: "online",
    creator: "Maruce",
    country: "Guinée"
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "OK" });
});

app.post("/api/chat", async (req, res) => {
  try {
    if (!API_KEY) {
      return res.status(500).json({
        error: "La clé OpenRouter n'est pas configurée sur le serveur."
      });
    }

    const messages = req.body.messages;

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        error: "Aucun message reçu."
      });
    }

    if (messages.length > 30) {
      return res.status(400).json({
        error: "Conversation trop longue."
      });
    }

    const safeMessages = messages
      .filter(m =>
        m &&
        ["user", "assistant"].includes(m.role) &&
        (typeof m.content === "string" ||
         Array.isArray(m.content))
      )
      .map(m => ({
        role: m.role,
        content: m.content
      }));

    if (!safeMessages.length ||
        safeMessages[safeMessages.length - 1].role !== "user") {
      return res.status(400).json({
        error: "Le dernier message doit venir de l'utilisateur."
      });
    }

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${API_KEY}`,
          "Content-Type": "application/json",
          "X-OpenRouter-Title": "TAYA AI"
        },
        body: JSON.stringify({
          model: MODEL,
          messages: [
            {
              role: "system",
              content: `Tu es TAYA AI, un assistant intelligent créé par Maruce en Guinée.

Tu réponds en français par défaut.
Tu comprends plusieurs langues.
Tu es rapide, précis, naturel et respectueux.
Tu réponds directement à la question.
Tu expliques clairement les sujets difficiles.
Tu aides avec les études, les sciences, la technologie, le développement web, les mathématiques, la rédaction et la créativité.
Tu ne prétends jamais avoir effectué une action que tu n'as pas réalisée.
Si tu ne connais pas une information, tu le dis honnêtement.
Tu ne fabriques pas de faits.
Ton identité est TAYA AI.`
            },
            ...safeMessages
          ],
          temperature: 0.7,
          max_tokens: 2000
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("OpenRouter error:", data);

      return res.status(502).json({
        error: "Le moteur IA rencontre un problème. Réessaie."
      });
    }

    const answer = data.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        error: "L'intelligence artificielle n'a pas retourné de réponse."
      });
    }

    res.json({
      success: true,
      reply: answer,
      model: data.model || MODEL
    });

  } catch (error) {
    console.error("Server error:", error);

    res.status(500).json({
      error: "Erreur interne du serveur TAYA AI."
    });
  }
});

app.listen(PORT, () => {
  console.log(`TAYA AI fonctionne sur le port ${PORT}`);
});
