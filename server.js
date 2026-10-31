require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// CONFIGURATION

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

// SUPABASE

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

DATE ACTUELLE : ${new Date().toISOString()}

IDENTITÉ :

- Ton nom est TAYA IA.
- Ton créateur est Maruce.
- Tu représentes la Guinée 🇬🇳.
- Tu réponds en français par défaut.
- Tu comprends plusieurs langues.

COMPORTEMENT :

- Réponds directement à la question.
- Sois précis, naturel et rapide.
- Ne donne pas d'informations inutiles.
- Explique clairement les sujets difficiles.
- Aide en sciences, technologie, études et développement.
- Ne fabrique jamais des faits.
- Ne prétends jamais avoir réalisé une action non effectuée.

RECHERCHE INTERNET :

Tu disposes d'un outil de recherche Internet en temps réel.

Utilise-le pour :
- Les actualités.
- Les événements récents.
- Les résultats sportifs.
- Les prix actuels.
- Les entreprises.
- Les informations susceptibles d'avoir changé.
- Les vérifications de faits.
- Les recherches demandées par l'utilisateur.

RÈGLES DE RECHERCHE :

1. Recherche les informations pertinentes.
2. Privilégie les sources fiables et originales.
3. Compare plusieurs sources lorsque c'est nécessaire.
4. Vérifie les dates de publication.
5. Ne présente jamais une rumeur comme un fait confirmé.
6. Ne fabrique aucun chiffre.
7. Ne fabrique aucun lien.
8. Indique clairement les incertitudes.
9. Cite les sources réellement consultées.

PRÉSENTATION DES SOURCES :

- Ne crée pas une longue liste de sources dans ta réponse.
- Les sources seront ajoutées automatiquement par le serveur.
- Ne répète pas les sources.
- Ne cite pas un média si tu ne l'as pas réellement consulté.

MÉMOIRE :

Tu possèdes une mémoire conversationnelle.

Utilise les informations mémorisées lorsqu'elles sont utiles.
Ne prétends jamais te souvenir d'informations absentes de ta mémoire.

OBJECTIF :

Fournir des réponses utiles, fiables, naturelles et intelligentes.
`;

// FONCTION DE NETTOYAGE DES SOURCES

function extractSources(annotations) {

  if (!Array.isArray(annotations)) {
    return [];
  }

  return annotations
    .filter(a =>
      a &&
      a.type === "url_citation" &&
      a.url_citation &&
      a.url_citation.url
    )
    .map(a => {

      const item = a.url_citation;

      try {

        const parsed = new URL(item.url);

        if (parsed.protocol !== "https:") {
          return null;
        }

        return {
          title: String(
            item.title || parsed.hostname
          )
            .replace(/[\r\n\t]/g, " ")
            .replace(/[<>]/g, "")
            .trim()
            .slice(0, 180),

          url: parsed.toString()

        };

      } catch {
        return null;
      }

    })
    .filter(Boolean)
    .filter((source, index, array) =>
      array.findIndex(
        item => item.url === source.url
      ) === index
    )
    .slice(0, 10);
}

// NETTOYAGE DES SOURCES EN DOUBLE

function cleanAnswer(answer) {

  return answer

    .replace(
      /\n{0,2}#{1,3}\s*(sources consultées|sources utilisées|sources)\b[\s\S]*$/i,
      ""
    )

    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// FORMATER LES SOURCES

function formatSources(sources) {

  if (!sources.length) {
    return "";
  }

  const list = sources.map(source => {

    const title = source.title
      .replace(/\\/g, "")
      .replace(/\[/g, "\\[")
      .replace(/\]/g, "\\]");

    const safeUrl = source.url.replace(/\)/g, "%29");

    return `- [${title}](${safeUrl})`;

  }).join("\n");

  return "\n\n### Sources consultées\n\n" + list;
}

// PAGE PRINCIPALE

app.get("/", (req, res) => {

  res.json({
    name: "TAYA IA",
    version: "5.0.0",
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
    version: "5.0.0",
    memory: Boolean(supabase),
    webSearch: true
  });

});

// RÉCUPÉRER LA MÉMOIRE

async function getMemory(userId) {

  if (!supabase || !userId) {
    return "";
  }

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

  if (!supabase || !userId) {
    return;
  }

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

// EXTRAIRE LE TEXTE D'UN MESSAGE

function getMessageText(content) {

  if (typeof content === "string") {
    return content;
  }

  if (Array.isArray(content)) {

    return content.map(item => {

      if (item.type === "text") {
        return item.text || "";
      }

      return "[Contenu multimodal]";

    }).join("\n");

  }

  return "";

}

// DISCUSSION IA

app.post("/api/chat", async (req, res) => {

  try {

    if (!API_KEY) {

      return res.status(500).json({
        error: "La clé OpenRouter n'est pas configurée."
      });

    }

    const messages = req.body.messages;

    const userId =
      typeof req.body.userId === "string"
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

    // VALIDATION DES MESSAGES

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
Voici les informations mémorisées sur les conversations précédentes.

Utilise-les uniquement lorsqu'elles sont utiles.

MÉMOIRE :

${memory}
`
      });

    }

    // APPEL OPENROUTER

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {

        method: "POST",

        headers: {
          "Authorization": `Bearer ${API_KEY}`,
          "Content-Type": "application/json",
          "X-OpenRouter-Title": "TAYA IA V5"
        },

        body: JSON.stringify({

          model: MODEL,

          messages: [
            ...systemMessages,
            ...safeMessages
          ],

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
          max_tokens: 3000

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

        .map(item => item.text || "")

        .join("\n");

    }

    if (typeof answer !== "string" || !answer.trim()) {

      return res.status(502).json({
        error: "TAYA IA n'a pas retourné de réponse."
      });

    }

    // RÉCUPÉRER LES SOURCES

    const sources = extractSources(
      message?.annotations
    );

    // NETTOYER LA RÉPONSE

    answer = cleanAnswer(answer);

    // AJOUTER LES SOURCES UNE SEULE FOIS

    answer += formatSources(sources);

    // SAUVEGARDE MÉMOIRE

    if (userId && supabase) {

      const lastUserMessage = safeMessages
        .filter(m => m.role === "user")
        .slice(-1)[0];

      const userText = lastUserMessage
        ? getMessageText(lastUserMessage.content)
        : "";

      const updatedMemory = [
        memory,
        `Utilisateur: ${userText}`,
        `TAYA IA: ${answer}`
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

      sources: sources,

      version: "5.0.0"

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
  console.log("TAYA IA V5 🇬🇳");
  console.log("Serveur : ONLINE");
  console.log("Recherche Internet : ACTIVÉE");
  console.log("Sources : NETTOYÉES");
  console.log("Mémoire Supabase :", Boolean(supabase));
  console.log("Créateur : Maruce");
  console.log("--------------------------------");

});
