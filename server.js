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

// IDENTITÉ DE TAYA IA

const SYSTEM_PROMPT = `
Tu es TAYA IA 🇬🇳, un assistant intelligent créé par Maruce en Guinée.

Tu réponds en français par défaut.
Tu comprends plusieurs langues.

TON COMPORTEMENT :

- Réponds directement aux questions.
- Sois précis, naturel et rapide.
- Explique clairement les sujets difficiles.
- Aide avec les études, les sciences, la technologie,
  le développement web, les mathématiques et la rédaction.
- Ne fabrique jamais des informations.
- Ne prétends jamais avoir effectué une action que tu n'as pas réalisée.

RECHERCHE INTERNET :

Tu disposes d'un outil de recherche Internet en temps réel.

Utilise-le lorsque l'utilisateur demande :
- Des informations récentes.
- L'actualité.
- Des résultats sportifs.
- Des prix actuels.
- Des informations sur une entreprise.
- Des informations susceptibles d'avoir changé.
- Une vérification d'information.
- Des recherches sur Internet.

Lorsque tu effectues une recherche :
- Consulte les résultats pertinents.
- Compare les informations lorsque nécessaire.
- Privilégie les sources fiables.
- Cite les sources utilisées.
- N'invente jamais de liens.
- Distingue les faits vérifiés des incertitudes.

MÉMOIRE :

Tu possèdes une mémoire conversationnelle.

Utilise les informations mémorisées pour mieux comprendre
les demandes de l'utilisateur.

Ne prétends pas te souvenir d'informations qui ne figurent
pas dans la conversation ou dans la mémoire fournie.

IDENTITÉ :

Ton nom est TAYA IA.
Ton créateur est Maruce.
Tu représentes la Guinée 🇬🇳.
`;

// PAGE PRINCIPALE

app.get("/", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: "4.0.0",
    status: "online",
    creator: "Maruce",
    country: "Guinée",
    memory: Boolean(supabase),
    webSearch: true
  });
});

// ÉTAT DU SERVEUR

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    memory: Boolean(supabase),
    webSearch: true
  });
});

// RÉCUPÉRER LA MÉMOIRE

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

// ENREGISTRER LA MÉMOIRE

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

// RECHERCHE ET DISCUSSION IA

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

    // Vérification des messages

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

    // CHARGER LA MÉMOIRE

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

    // APPEL OPENROUTER AVEC RECHERCHE INTERNET

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

          // OUTIL DE RECHERCHE INTERNET

          tools: [
            {
              type: "openrouter:web_search",

              parameters: {
                engine: "auto",
                max_results: 5,
                max_total_results: 10,
                max_uses: 2
              }
            }
          ],

          temperature: 0.7,
          max_tokens: 2500

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

    const message = data.choices?.[0]?.message;

    let answer = message?.content;

    if (Array.isArray(answer)) {
      answer = answer
        .filter(item => item.type === "text")
        .map(item => item.text)
        .join("\n");
    }

    if (typeof answer !== "string" || !answer.trim()) {
      return res.status(502).json({
        error: "L'intelligence artificielle n'a pas retourné de réponse."
      });
    }

    // RÉCUPÉRER LES SOURCES INTERNET

    const annotations = message?.annotations || [];

    const sources = annotations
      .filter(a =>
        a.type === "url_citation" &&
        a.url_citation?.url
      )
      .map(a => ({
        title: a.url_citation.title || "Source Internet",
        url: a.url_citation.url
      }))
      .filter(s => {
        try {
          return new URL(s.url).protocol === "https:";
        } catch {
          return false;
        }
      })
      .filter((s, i, arr) =>
        arr.findIndex(x => x.url === s.url) === i
      )
      .slice(0, 10);

    // AJOUTER LES SOURCES À LA RÉPONSE

    if (sources.length > 0) {

      const sourceList = sources
        .map(s => `- [${s.title.replace(/[$begin:math:display$$end:math:display$]/g, "")}](${s.url})`)
        .join("\n");

      answer += "\n\n### Sources consultées\n\n" + sourceList;
    }

    // SAUVEGARDER LA MÉMOIRE

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

    // RÉPONSE FINALE

    return res.json({

      success: true,

      reply: answer,

      model: data.model || MODEL,

      memoryEnabled: Boolean(userId && supabase),

      webSearchEnabled: true,

      sources: sources

    });

  } catch (error) {

    console.error("Server error:", error);

    return res.status(500).json({
      error: "Erreur interne du serveur TAYA IA."
    });

  }
});

// DÉMARRAGE

app.listen(PORT, () => {

  console.log("--------------------------------");
  console.log("TAYA IA V4");
  console.log("Serveur : ONLINE");
  console.log("Recherche Internet : ACTIVÉE");
  console.log("Mémoire Supabase :", Boolean(supabase));
  console.log("Créateur : Maruce 🇬🇳");
  console.log("--------------------------------");

});
