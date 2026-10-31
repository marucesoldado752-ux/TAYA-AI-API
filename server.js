require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const VERSION = "11.0.0";

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const AI_MODEL = process.env.AI_MODEL || "openai/gpt-4o-mini";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY =
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY;

let supabase = null;

if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  });
}

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: [
    "https://marucesoldado752-ux.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));

app.use(express.json({ limit: "12mb" }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "Trop de demandes. Réessaie dans une minute."
  }
});

app.use("/api/", limiter);

// PAGE DE SANTÉ

app.get("/", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online"
  });
});

app.get("/health", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online",
    aiConfigured: !!OPENROUTER_API_KEY,
    intelligentMemory: !!supabase,
    model: AI_MODEL
  });
});

// VÉRIFICATION DES IDENTIFIANTS

function validUserId(value) {
  return typeof value === "string" &&
    value.length >= 5 &&
    value.length <= 40;
}

// RÉCUPÉRER LA MÉMOIRE

app.get("/api/memory", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(503).json({
        error: "La mémoire Supabase n'est pas configurée."
      });
    }

    const userId = req.query.userId;

    if (!validUserId(userId)) {
      return res.status(400).json({
        error: "Identifiant utilisateur invalide."
      });
    }

    const { data, error } = await supabase
      .from("taya_memories")
      .select("memory")
      .eq("user_id", userId)
      .maybeSingle();

    if (error) throw error;

    res.json({
      memory: data?.memory || ""
    });

  } catch (error) {
    console.error("MEMORY GET:", error.message);

    res.status(500).json({
      error: "Impossible de charger la mémoire."
    });
  }
});

// ENREGISTRER LA MÉMOIRE

app.put("/api/memory", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(503).json({
        error: "La mémoire Supabase n'est pas configurée."
      });
    }

    const { userId, memory } = req.body;

    if (!validUserId(userId)) {
      return res.status(400).json({
        error: "Identifiant utilisateur invalide."
      });
    }

    if (typeof memory !== "string" || memory.length > 20000) {
      return res.status(400).json({
        error: "Mémoire invalide ou trop longue."
      });
    }

    const { data: existing, error: findError } = await supabase
      .from("taya_memories")
      .select("user_id")
      .eq("user_id", userId)
      .maybeSingle();

    if (findError) throw findError;

    let result;

    if (existing) {
      result = await supabase
        .from("taya_memories")
        .update({
          memory,
          updated_at: new Date().toISOString()
        })
        .eq("user_id", userId);
    } else {
      result = await supabase
        .from("taya_memories")
        .insert({
          user_id: userId,
          memory,
          updated_at: new Date().toISOString()
        });
    }

    if (result.error) throw result.error;

    res.json({
      success: true,
      message: "Mémoire enregistrée."
    });

  } catch (error) {
    console.error("MEMORY PUT:", error.message);

    res.status(500).json({
      error: "Impossible d'enregistrer la mémoire."
    });
  }
});

// SUPPRIMER LA MÉMOIRE

app.delete("/api/memory", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(503).json({
        error: "La mémoire Supabase n'est pas configurée."
      });
    }

    const { userId } = req.body;

    if (!validUserId(userId)) {
      return res.status(400).json({
        error: "Identifiant utilisateur invalide."
      });
    }

    const { error } = await supabase
      .from("taya_memories")
      .delete()
      .eq("user_id", userId);

    if (error) throw error;

    res.json({
      success: true,
      message: "Mémoire supprimée."
    });

  } catch (error) {
    console.error("MEMORY DELETE:", error.message);

    res.status(500).json({
      error: "Impossible de supprimer la mémoire."
    });
  }
});

// INTELLIGENCE ARTIFICIELLE

app.post("/api/chat", async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return res.status(503).json({
        error: "La clé OpenRouter n'est pas configurée sur Render."
      });
    }

    const { messages, userId } = req.body;

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

    let memory = "";

    if (supabase && validUserId(userId)) {
      const { data, error } = await supabase
        .from("taya_memories")
        .select("memory")
        .eq("user_id", userId)
        .maybeSingle();

      if (error) {
        console.error("MEMORY READ:", error.message);
      } else {
        memory = data?.memory || "";
      }
    }

    const systemPrompt = `
Tu es TAYA IA, un assistant intelligent créé par Maruce en Guinée 🇬🇳.

Tu dois :
- Répondre en français si l'utilisateur parle français.
- Comprendre les questions et donner des réponses précises.
- Répondre directement sans ajouter de phrases inutiles.
- Expliquer clairement les sujets difficiles.
- Aider à programmer en HTML, CSS, JavaScript et autres langages.
- Corriger les erreurs de code.
- Traduire et rédiger des textes.
- Analyser les images et les documents lorsqu'ils sont fournis.
- Ne jamais inventer une information lorsque tu ne la connais pas.

Tu es un assistant généraliste utile, naturel et rapide.

${memory ? "INFORMATIONS MÉMORISÉES SUR L'UTILISATEUR :\n" + memory : ""}
`;

    const cleanMessages = messages.map(message => {
      if (!message || !["user", "assistant"].includes(message.role)) {
        throw new Error("Message invalide.");
      }

      let content = message.content;

      if (typeof content === "string") {
        content = content.slice(0, 30000);
      } else if (Array.isArray(content)) {
        content = content.slice(0, 10).map(part => {
          if (part.type === "text") {
            return {
              type: "text",
              text: String(part.text || "").slice(0, 25000)
            };
          }

          if (part.type === "image_url" && part.image_url?.url) {
            return {
              type: "image_url",
              image_url: {
                url: part.image_url.url
              }
            };
          }

          throw new Error("Type de contenu non accepté.");
        });
      } else {
        throw new Error("Contenu invalide.");
      }

      return {
        role: message.role,
        content
      };
    });

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + OPENROUTER_API_KEY,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://marucesoldado752-ux.github.io/",
          "X-Title": "TAYA IA"
        },
        body: JSON.stringify({
          model: AI_MODEL,
          messages: [
            {
              role: "system",
              content: systemPrompt
            },
            ...cleanMessages
          ],
          temperature: 0.7,
          max_tokens: 4000
        }),
        signal: AbortSignal.timeout(110000)
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("OPENROUTER:", data);

      return res.status(502).json({
        error: data.error?.message || "Le fournisseur IA a rencontré une erreur."
      });
    }

    const reply = data.choices?.[0]?.message?.content;

    if (!reply) {
      return res.status(502).json({
        error: "L'intelligence artificielle n'a envoyé aucune réponse."
      });
    }

    res.json({
      reply,
      memoryEnabled: !!supabase,
      model: AI_MODEL
    });

  } catch (error) {
    console.error("CHAT ERROR:", error);

    res.status(error.name === "TimeoutError" ? 504 : 500).json({
      error: error.name === "TimeoutError"
        ? "Le délai de réponse est dépassé. Réessaie."
        : error.message || "Erreur interne du serveur."
    });
  }
});

// ERREURS GÉNÉRALES

app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err.message);

  res.status(500).json({
    error: "Une erreur interne est survenue."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("================================");
  console.log("🤖 TAYA IA V" + VERSION);
  console.log("🚀 Serveur démarré sur le port " + PORT);
  console.log("🧠 Supabase :", !!supabase);
  console.log("✨ OpenRouter :", !!OPENROUTER_API_KEY);
  console.log("================================");
});
