require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

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

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

let supabase = null;

if (SUPABASE_URL && SUPABASE_SECRET_KEY) {
  supabase = createClient(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
  );

  console.log("Supabase connecté");
} else {
  console.warn("Supabase non configuré");
}

const SYSTEM_PROMPT = `
Tu es TAYA IA, un assistant intelligent créé par Maruce en Guinée.

Tu réponds en français par défaut.
Tu comprends plusieurs langues.
Tu es rapide, précis, naturel et respectueux.

Tu réponds directement aux questions.
Tu expliques clairement les sujets difficiles.
Tu aides avec les études, les sciences, la technologie,
le développement web, les mathématiques, la rédaction
et la créativité.

Tu ne prétends jamais avoir effectué une action que tu n'as pas réalisée.
Tu ne fabriques pas de faits.
Si tu ne connais pas une information, tu le dis honnêtement.

Tu possèdes une mémoire conversationnelle.
Utilise les informations mémorisées pour mieux comprendre
les demandes de l'utilisateur.
Ne prétends pas te souvenir d'informations qui ne figurent pas
dans la conversation ou dans la mémoire fournie.

Ton identité est TAYA IA 🇬🇳.
`;

app.get("/", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: "3.0.0",
    status: "online",
    creator: "Maruce",
    country: "Guinée",
    memory: Boolean(supabase)
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    memory: Boolean(supabase)
  });
});

// Récupérer la mémoire d'un utilisateur
async function getMemory(userId) {
  if (!supabase || !userId) return "";

  const { data, error } = await supabase
    .from("taya_memories")
    .select("memory")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    console.error("Erreur mémoire:", error.message);
    return "";
  }

  return data?.memory || "";
}

// Enregistrer la mémoire
async function saveMemory(userId, memory) {
  if (!supabase || !userId) return;

  const { error } = await supabase
    .from("taya_memories")
    .upsert({
      user_id: userId,
      memory: memory.slice(-12000),
      updated_at: new Date().toISOString()
    }, {
      onConflict: "user_id"
    });

  if (error) {
    console.error("Sauvegarde mémoire:", error.message);
  }
}

app.post("/api/chat", async (req, res) => {
  try {
    if (!API_KEY) {
      return res.status(500).json({
        error: "La clé OpenRouter n'est pas configurée."
      });
    }

    const messages = req.body.messages;
    const userId = typeof req.body.userId === "string"
      ? req.body.userId.trim().slice(0, 100)
      : null;

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
        (
          typeof m.content === "string" ||
          Array.isArray(m.content)
        )
      )
      .map(m => ({
        role: m.role,
        content: m.content
      }));

    if (
      !safeMessages.length ||
      safeMessages[safeMessages.length - 1].role !== "user"
    ) {
      return res.status(400).json({
        error: "Le dernier message doit venir de l'utilisateur."
      });
    }

    // Charger la mémoire existante
    const memory = await getMemory(userId);

    const systemMessages = [
      {
        role: "system",
        content: SYSTEM_PROMPT
      }
    ];

    if (memory) {
      systemMessages.push({
        role: "system",
        content: `
Voici les informations des conversations précédentes
de cet utilisateur.

Utilise-les uniquement lorsqu'elles sont utiles.

MEMOIRE :
${memory}
`
      });
    }

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${API_KEY}`,
          "Content-Type": "application/json",
          "X-OpenRouter-Title": "TAYA IA"
        },
        body: JSON.stringify({
          model: MODEL,
          messages: [
            ...systemMessages,
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

    // Sauvegarder les échanges dans Supabase
    if (userId && supabase) {
      const conversation = safeMessages
        .slice(-10)
        .map(m => {
          const content = typeof m.content === "string"
            ? m.content
            : "[Contenu multimodal]";

          return `${m.role}: ${content}`;
        })
        .join("\n");

      const updatedMemory = [
        memory,
        conversation,
        `assistant: ${answer}`
      ]
        .filter(Boolean)
        .join("\n")
        .slice(-12000);

      await saveMemory(userId, updatedMemory);
    }

    return res.json({
      success: true,
      reply: answer,
      model: data.model || MODEL,
      memoryEnabled: Boolean(userId && supabase)
    });

  } catch (error) {
    console.error("Server error:", error);

    return res.status(500).json({
      error: "Erreur interne du serveur TAYA IA."
    });
  }
});

app.listen(PORT, () => {
  console.log(`TAYA IA fonctionne sur le port ${PORT}`);
});
