/**
 * TAYA IA — API V21.0.3
 * Backend officiel by Maruce Soldado 🇬🇳
 * Express + Supabase + OpenRouter + Tavily
 *
 * Table utilisateurs :
 * taya_v13_users
 *
 * Colonnes :
 * id, phone, name, password, password_hash,
 * email, avatar_url, created_at, updated_at,
 * recovery_code_hash, role, must_reset_password,
 * last_seen_at
 */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { promisify } = require("util");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 3000;
const VERSION = "21.0.3";

const scryptAsync = promisify(crypto.scrypt);

const {
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET,
  OPENROUTER_API_KEY,
  OPENROUTER_MODEL,
  OPENROUTER_VISION_MODEL,
  OPENROUTER_PDF_MODEL,
  TAVILY_API_KEY,
  ALLOWED_ORIGIN
} = process.env;

// -------------------- SUPABASE --------------------

const SUPABASE_KEY =
  SUPABASE_SECRET_KEY ||
  SUPABASE_SERVICE_ROLE_KEY;

const supabase =
  SUPABASE_URL && SUPABASE_KEY
    ? createClient(
        SUPABASE_URL,
        SUPABASE_KEY,
        {
          auth: {
            autoRefreshToken: false,
            persistSession: false
          }
        }
      )
    : null;

// -------------------- ADMINISTRATEURS --------------------

const ADMIN_PHONES = new Set([
  "+224663401157",
  "+224612768878"
]);

// -------------------- SÉCURITÉ --------------------

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

const allowedOrigins = (
  ALLOWED_ORIGIN ||
  "https://marucesoldado752-ux.github.io"
)
  .split(",")
  .map(origin =>
    origin.trim().replace(/\/+$/, "")
  )
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (
        !origin ||
        allowedOrigins.includes(
          origin.replace(/\/+$/, "")
        )
      ) {
        return callback(null, true);
      }

      return callback(
        new Error("Origine non autorisée")
      );
    },

    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);

app.use(
  express.json({
    limit: "25mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "25mb"
  })
);

// -------------------- LIMITATION DES REQUÊTES --------------------

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use("/api/", generalLimiter);

// -------------------- FONCTIONS GÉNÉRALES --------------------

function ok(res, data = {}, status = 200) {
  return res.status(status).json({
    success: true,
    ...data
  });
}

function fail(res, message, status = 400) {
  return res.status(status).json({
    success: false,
    error: message
  });
}

function cleanText(value, max = 12000) {
  return String(
    value == null ? "" : value
  )
    .trim()
    .slice(0, max);
}

// -------------------- NORMALISATION TÉLÉPHONE --------------------

function normalizePhone(value) {
  let digits = String(value || "")
    .replace(/\D/g, "");

  if (!digits) return "";

  // Numéro guinéen local
  if (digits.length === 9) {
    digits = "224" + digits;
  }

  return "+" + digits;
}

function phoneVariants(value) {
  const canonical = normalizePhone(value);

  if (!canonical) return [];

  const digits = canonical.slice(1);

  const variants = new Set([
    canonical,
    digits
  ]);

  // Compatibilité avec les anciens numéros guinéens
  if (
    digits.startsWith("224") &&
    digits.length === 12
  ) {
    variants.add(digits.slice(3));
    variants.add("+" + digits.slice(3));
  }

  return [...variants];
}

// -------------------- ADMIN --------------------

function isAdmin(user) {
  return ADMIN_PHONES.has(
    normalizePhone(user?.phone)
  );
}

// -------------------- DONNÉES PUBLIQUES UTILISATEUR --------------------

function publicUser(user) {
  if (!user) return null;

  const name =
    user.name ||
    user.full_name ||
    "";

  return {
    id: user.id,
    p: user.id,

    name,
    full_name: name,

    phone: normalizePhone(user.phone),

    email: user.email || "",

    avatar_url:
      user.avatar_url || "",

    role: isAdmin(user)
      ? "admin"
      : "user",

    created_at:
      user.created_at || null,

    last_seen_at:
      user.last_seen_at || null,

    must_reset_password:
      !!user.must_reset_password
  };
}

// -------------------- VÉRIFICATION SERVICES --------------------

function requireServices(req, res, next) {
  if (!supabase) {
    return fail(
      res,
      "Supabase n'est pas configuré sur le serveur",
      503
    );
  }

  if (!JWT_SECRET) {
    return fail(
      res,
      "JWT_SECRET n'est pas configuré",
      503
    );
  }

  next();
}

// -------------------- TOKEN JWT --------------------

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      phone: user.phone
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

// -------------------- VÉRIFICATION MOT DE PASSE --------------------

async function verifyStoredHash(
  storedValue,
  supplied
) {
  const stored = String(
    storedValue || ""
  );

  if (!stored) return false;

  // BCRYPT
  if (stored.startsWith("$2")) {
    try {
      return await bcrypt.compare(
        supplied,
        stored
      );
    } catch (_) {
      return false;
    }
  }

  // SCRYPT
  if (stored.startsWith("scrypt$")) {
    try {
      const parts = stored.split("$");

      if (parts.length !== 3) {
        return false;
      }

      const salt = parts[1];
      const expectedHex = parts[2];

      if (
        !salt ||
        !/^[a-f0-9]+$/i.test(expectedHex) ||
        expectedHex.length % 2
      ) {
        return false;
      }

      const expected = Buffer.from(
        expectedHex,
        "hex"
      );

      const actual = await scryptAsync(
        supplied,
        salt,
        expected.length
      );

      return (
        actual.length === expected.length &&
        crypto.timingSafeEqual(
          actual,
          expected
        )
      );

    } catch (error) {
      console.error(
        "Erreur SCRYPT:",
        error.message
      );

      return false;
    }
  }

  // SHA256
  if (/^[a-f0-9]{64}$/i.test(stored)) {
    const digest = crypto
      .createHash("sha256")
      .update(supplied)
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(digest, "hex"),
      Buffer.from(stored.toLowerCase(), "hex")
    );
  }

  // Ancien mot de passe en clair
  return stored === supplied;
}

async function makePasswordHash(password) {
  return bcrypt.hash(
    String(password),
    12
  );
}

async function verifyPassword(
  user,
  password
) {
  if (
    user.password_hash &&
    await verifyStoredHash(
      user.password_hash,
      password
    )
  ) {
    return true;
  }

  if (
    user.password &&
    await verifyStoredHash(
      user.password,
      password
    )
  ) {
    return true;
  }

  return false;
}

// -------------------- MISE À JOUR MOT DE PASSE --------------------

async function upgradePassword(
  user,
  password
) {
  const password_hash =
    await makePasswordHash(password);

  const { error } = await supabase
    .from("taya_v13_users")
    .update({
      password_hash,
      password: null,
      must_reset_password: false,
      updated_at: new Date().toISOString()
    })
    .eq("id", user.id);

  if (error) {
    console.error(
      "Mise à jour mot de passe:",
      error.message
    );
  }
}

// -------------------- AUTHENTIFICATION --------------------

async function authenticate(
  req,
  res,
  next
) {
  try {
    const header =
      req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return fail(
        res,
        "Connexion requise",
        401
      );
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    const { data: user, error } =
      await supabase
        .from("taya_v13_users")
        .select("*")
        .eq("id", decoded.id)
        .maybeSingle();

    if (error || !user) {
      return fail(
        res,
        "Session invalide",
        401
      );
    }

    req.user = user;

    next();

  } catch (error) {
    return fail(
      res,
      "Session invalide ou expirée",
      401
    );
  }
}

// -------------------- PROTECTION ADMIN --------------------

function requireAdmin(req, res, next) {
  if (!isAdmin(req.user)) {
    return fail(
      res,
      "Accès administrateur refusé",
      403
    );
  }

  next();
}

// ============================================================
// PARTIE 2/3 À AJOUTER À LA SUITE
// ============================================================// ============================================================
// TAYA IA V21.0.3
// PARTIE 2/3
// IA + HISTORIQUE + MÉMOIRE + RECHERCHE WEB
// ============================================================

// -------------------- OPENROUTER --------------------

const OPENROUTER_URL =
  "https://openrouter.ai/api/v1/chat/completions";

function extractText(content) {
  if (typeof content === "string") {
    return content;
  }

  if (Array.isArray(content)) {
    return content.map(part =>
      typeof part === "string"
        ? part
        : (part && (part.text || part.content)) || ""
    ).join("\n");
  }

  return "";
}

async function callAI({
  messages,
  model,
  temperature = 0.7,
  max_tokens = 3000
}) {
  if (!OPENROUTER_API_KEY) {
    throw new Error(
      "OPENROUTER_API_KEY n'est pas configurée"
    );
  }

  const response = await fetch(
    OPENROUTER_URL,
    {
      method: "POST",

      headers: {
        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer":
          "https://marucesoldado752-ux.github.io",
        "X-Title": "TAYA IA by Maruce"
      },

      body: JSON.stringify({
        model:
          model ||
          OPENROUTER_MODEL ||
          "openai/gpt-4o-mini",

        messages,
        temperature,
        max_tokens
      })
    }
  );

  const result = await response
    .json()
    .catch(() => ({}));

  if (!response.ok) {
    console.error(
      "Erreur OpenRouter:",
      result
    );

    throw new Error(
      result.error?.message ||
      "Erreur du service IA"
    );
  }

  const answer =
    result.choices?.[0]?.message?.content;

  if (!answer) {
    throw new Error("Réponse IA vide");
  }

  return extractText(answer);
}

// -------------------- RECHERCHE WEB TAVILY --------------------

async function searchWeb(query) {
  if (!TAVILY_API_KEY) {
    return {
      available: false,
      answer: "",
      results: []
    };
  }

  const response = await fetch(
    "https://api.tavily.com/search",
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        api_key: TAVILY_API_KEY,
        query: cleanText(query, 1000),
        search_depth: "advanced",
        max_results: 5,
        include_answer: true
      })
    }
  );

  const data = await response
    .json()
    .catch(() => ({}));

  if (!response.ok) {
    console.error(
      "Erreur Tavily:",
      data
    );

    throw new Error(
      "Erreur de recherche Web"
    );
  }

  return {
    available: true,

    answer: data.answer || "",

    results: (data.results || []).map(item => ({
      title: item.title || "",
      url: item.url || "",
      content: item.content || ""
    }))
  };
}

function shouldSearch(message, requested) {
  if (requested === true) {
    return true;
  }

  const text = String(message || "")
    .toLowerCase();

  const keywords = [
    "actualité",
    "actualités",
    "aujourd'hui",
    "maintenant",
    "en ce moment",
    "dernières nouvelles",
    "prix actuel",
    "cours actuel",
    "météo",
    "résultat du match",
    "qui est actuellement",
    "recherche sur internet",
    "cherche sur internet",
    "sur google",
    "information récente"
  ];

  return keywords.some(word =>
    text.includes(word)
  );
}

// -------------------- HISTORIQUE --------------------

function normalizeHistory(history) {
  if (!Array.isArray(history)) {
    return [];
  }

  return history
    .slice(-20)
    .map(item => ({
      role:
        item.role === "assistant"
          ? "assistant"
          : "user",

      content: cleanText(
        item.content || item.message || "",
        12000
      )
    }))
    .filter(item => item.content);
}

async function saveConversation(
  userId,
  role,
  message
) {
  const { error } = await supabase
    .from("taya_v12_messages")
    .insert({
      user_id: userId,
      role,
      message: cleanText(message, 20000)
    });

  if (error) {
    console.error(
      "Sauvegarde conversation:",
      error.message
    );
  }
}

app.get(
  "/api/history",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v12_messages")
        .select("*")
        .eq("user_id", req.user.id)
        .limit(200);

      if (error) {
        throw error;
      }

      return ok(res, {
        messages: data || [],
        history: data || []
      });

    } catch (error) {
      console.error(
        "Historique:",
        error
      );

      return fail(
        res,
        "Impossible de charger l'historique",
        500
      );
    }
  }
);

// -------------------- MÉMOIRE UTILISATEUR --------------------

async function getUserMemory(userId) {
  const { data, error } = await supabase
    .from("taya_v12_memories")
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    console.error(
      "Lecture mémoire:",
      error.message
    );

    return "";
  }

  return data?.memory || "";
}

async function saveUserMemory(
  userId,
  memory
) {
  const value = cleanText(
    memory,
    12000
  );

  const { data, error: readError } =
    await supabase
      .from("taya_v12_memories")
      .select("*")
      .eq("user_id", userId)
      .maybeSingle();

  if (readError) {
    throw readError;
  }

  if (data) {
    const { error } = await supabase
      .from("taya_v12_memories")
      .update({
        memory: value,
        updated_at: new Date().toISOString()
      })
      .eq("user_id", userId);

    if (error) {
      throw error;
    }

  } else {
    const { error } = await supabase
      .from("taya_v12_memories")
      .insert({
        user_id: userId,
        memory: value
      });

    if (error) {
      throw error;
    }
  }

  return value;
}

app.get(
  "/api/memory",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const memory = await getUserMemory(
        req.user.id
      );

      return ok(res, {
        memory
      });

    } catch (error) {
      console.error(
        "Mémoire:",
        error
      );

      return fail(
        res,
        "Impossible de récupérer la mémoire",
        500
      );
    }
  }
);

app.put(
  "/api/memory",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const memory = await saveUserMemory(
        req.user.id,
        req.body.memory || ""
      );

      return ok(res, {
        memory,
        message: "Mémoire enregistrée"
      });

    } catch (error) {
      console.error(
        "Enregistrement mémoire:",
        error
      );

      return fail(
        res,
        "Impossible d'enregistrer la mémoire",
        500
      );
    }
  }
);

// -------------------- STATUT API --------------------

app.get("/", (req, res) => {
  return ok(res, {
    name: "TAYA IA",
    version: VERSION,
    server: "online",
    message: "Bienvenue sur TAYA IA by Maruce"
  });
});

app.get("/api", (req, res) => {
  return ok(res, {
    name: "TAYA IA API",
    version: VERSION
  });
});

app.get("/api/health", (req, res) => {
  return ok(res, {
    version: VERSION,
    server: "online",
    supabase: !!supabase,
    ai: !!OPENROUTER_API_KEY,
    web_search: !!TAVILY_API_KEY
  });
});

// -------------------- CHAT INTELLIGENT --------------------

app.post(
  "/api/chat",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const message = cleanText(
        req.body.message,
        12000
      );

      if (!message) {
        return fail(
          res,
          "Message vide"
        );
      }

      const history = normalizeHistory(
        req.body.history ||
        req.body.messages
      );

      const memory = await getUserMemory(
        req.user.id
      );

      let webContext = "";
      let searchResults = [];

      const searchRequested = shouldSearch(
        message,
        req.body.web_search
      );

      // Recherche automatique si nécessaire
      if (
        searchRequested &&
        TAVILY_API_KEY
      ) {
        try {
          const search = await searchWeb(
            message
          );

          if (search.available) {
            webContext = [
              search.answer,

              ...(search.results || []).map(item =>
                `${item.title}\n${item.content}\n${item.url}`
              )

            ]
              .filter(Boolean)
              .join("\n\n");

            searchResults =
              search.results || [];
          }

        } catch (searchError) {
          console.error(
            "Recherche Web:",
            searchError.message
          );
        }
      }

      const systemPrompt = `
Tu es TAYA IA, une intelligence artificielle
moderne, rapide, précise et utile,
créée par Maruce Soldado 🇬🇳.

RÈGLES :

1. Réponds dans la langue de l'utilisateur.
2. Donne une réponse directe et claire.
3. Évite les longues introductions.
4. Ne prétends jamais avoir effectué une action
   que tu n'as pas faite.
5. Pour les calculs, donne le résultat exact.
6. Pour le code, fournis un code complet
   lorsque l'utilisateur le demande.
7. Si tu ne connais pas une information,
   dis-le clairement.
8. Respecte la sécurité et la confidentialité.
9. Utilise les informations Web disponibles.
10. Ne présente pas une information non vérifiée
    comme un fait.

MÉMOIRE UTILISATEUR :

${memory || "Aucune mémoire enregistrée."}

INFORMATIONS DE RECHERCHE WEB :

${webContext || "Aucune recherche Web effectuée."}
`;

      const answer = await callAI({
        messages: [
          {
            role: "system",
            content: systemPrompt
          },

          ...history,

          {
            role: "user",
            content: message
          }
        ],

        temperature: 0.7,
        max_tokens: 4000
      });

      // Sauvegarde du message utilisateur
      await saveConversation(
        req.user.id,
        "user",
        message
      );

      // Sauvegarde de la réponse IA
      await saveConversation(
        req.user.id,
        "assistant",
        answer
      );

      return ok(res, {
        answer,
        message: answer,
        web_search: searchRequested,
        sources: searchResults
      });

    } catch (error) {
      console.error(
        "Chat IA:",
        error
      );

      return fail(
        res,
        error.message ||
        "Erreur du service IA",
        500
      );
    }
  }
);

// ============================================================
// FIN PARTIE 2/3
// ============================================================// ============================================================
// TAYA IA V21.0.3
// PARTIE 3/3
// IMAGES + PDF + CONTACTS + SUPPORT + ADMIN
// ============================================================

// -------------------- ANALYSE DES IMAGES --------------------

app.post(
  "/api/chat/image",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const imageValue =
        req.body.image_base64 ||
        req.body.image ||
        req.body.data_url ||
        "";

      const question = cleanText(
        req.body.message ||
        "Décris et analyse cette image.",
        5000
      );

      if (!imageValue) {
        return fail(res, "Image manquante");
      }

      let imageUrl = String(imageValue);

      if (!imageUrl.startsWith("data:image/")) {
        const mime = String(
          req.body.mime_type || "image/jpeg"
        );

        if (!mime.startsWith("image/")) {
          return fail(
            res,
            "Format d'image non valide"
          );
        }

        imageUrl = `data:${mime};base64,${imageUrl}`;
      }

      if (
        !/^data:image\/(jpeg|jpg|png|webp|gif);base64,/i.test(
          imageUrl
        )
      ) {
        return fail(
          res,
          "Format d'image non pris en charge"
        );
      }

      const answer = await callAI({
        model:
          OPENROUTER_VISION_MODEL ||
          OPENROUTER_MODEL ||
          "openai/gpt-4o-mini",

        messages: [
          {
            role: "system",
            content:
              "Tu es TAYA IA. Analyse les images avec précision. Décris uniquement ce qui est visible et réponds à la question de l'utilisateur."
          },
          {
            role: "user",
            content: [
              {
                type: "text",
                text: question
              },
              {
                type: "image_url",
                image_url: {
                  url: imageUrl
                }
              }
            ]
          }
        ],

        max_tokens: 3000
      });

      return ok(res, {
        answer,
        message: answer
      });

    } catch (error) {
      console.error(
        "Analyse image:",
        error
      );

      return fail(
        res,
        error.message ||
        "Analyse de l'image impossible",
        500
      );
    }
  }
);

// -------------------- LECTURE DES PDF --------------------

app.post(
  "/api/chat/pdf",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const pdfBase64 = String(
        req.body.pdf_base64 ||
        req.body.file_base64 ||
        req.body.file ||
        ""
      );

      const question = cleanText(
        req.body.message ||
        "Résume ce document.",
        5000
      );

      if (!pdfBase64) {
        return fail(
          res,
          "Fichier PDF manquant"
        );
      }

      const pdfParse = require("pdf-parse");

      const cleanBase64 = pdfBase64
        .replace(
          /^data:application\/pdf;base64,/,
          ""
        )
        .replace(/\s/g, "");

      const buffer = Buffer.from(
        cleanBase64,
        "base64"
      );

      if (!buffer.length) {
        return fail(
          res,
          "PDF vide ou invalide"
        );
      }

      if (
        buffer.length >
        15 * 1024 * 1024
      ) {
        return fail(
          res,
          "Le PDF dépasse la limite de 15 Mo"
        );
      }

      // Vérification de la signature PDF
      if (
        buffer.subarray(0, 5).toString() !== "%PDF-"
      ) {
        return fail(
          res,
          "Le fichier envoyé n'est pas un PDF valide"
        );
      }

      const parsed = await pdfParse(buffer);

      const documentText = cleanText(
        parsed.text,
        45000
      );

      if (!documentText) {
        return fail(
          res,
          "Aucun texte lisible trouvé dans ce PDF. Le document est peut-être scanné."
        );
      }

      const answer = await callAI({
        model:
          OPENROUTER_PDF_MODEL ||
          OPENROUTER_MODEL ||
          "openai/gpt-4o-mini",

        messages: [
          {
            role: "system",
            content:
              "Tu es TAYA IA. Analyse les documents fournis et réponds précisément à la demande en utilisant le contenu du document."
          },
          {
            role: "user",
            content:
              `QUESTION : ${question}\n\n` +
              `CONTENU DU PDF :\n${documentText}`
          }
        ],

        max_tokens: 4000
      });

      return ok(res, {
        answer,
        message: answer,
        pages: parsed.numpages || null
      });

    } catch (error) {
      console.error(
        "Analyse PDF:",
        error
      );

      return fail(
        res,
        "Impossible de lire ce PDF",
        500
      );
    }
  }
);

// -------------------- CONTACT : ÉCRIRE À MARUCE --------------------

async function createContact(req, res) {
  try {
    const message = cleanText(
      req.body.message,
      10000
    );

    if (!message) {
      return fail(
        res,
        "Message vide"
      );
    }

    const subject = cleanText(
      req.body.subject ||
      "Message utilisateur",
      150
    );

    const { data, error } = await supabase
      .from("taya_v12_contacts")
      .insert({
        user_id: req.user.id,
        message: `${subject}\n\n${message}`
      })
      .select("*")
      .single();

    if (error) {
      throw error;
    }

    return ok(
      res,
      {
        contact: data,
        message: "Message envoyé à Maruce"
      },
      201
    );

  } catch (error) {
    console.error(
      "Contact:",
      error
    );

    return fail(
      res,
      "Impossible d'envoyer le message",
      500
    );
  }
}

app.post(
  "/api/contact",
  requireServices,
  authenticate,
  createContact
);

app.post(
  "/api/contacts",
  requireServices,
  authenticate,
  createContact
);

// -------------------- SUPPORT --------------------

app.post(
  "/api/support",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const message = cleanText(
        req.body.message,
        10000
      );

      if (!message) {
        return fail(
          res,
          "Message vide"
        );
      }

      const { data, error } = await supabase
        .from("taya_v19_support_messages")
        .insert({
          user_id: req.user.id,
          sender_id: req.user.id,
          sender_role: isAdmin(req.user)
            ? "admin"
            : "user",
          message
        })
        .select("*")
        .single();

      if (error) {
        throw error;
      }

      return ok(
        res,
        {
          message: data,
          status: "sent"
        },
        201
      );

    } catch (error) {
      console.error(
        "Support:",
        error
      );

      return fail(
        res,
        "Envoi du message impossible",
        500
      );
    }
  }
);

// -------------------- ADMIN : UTILISATEURS --------------------

app.get(
  "/api/admin/users",
  requireServices,
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v13_users")
        .select("*")
        .limit(1000);

      if (error) {
        throw error;
      }

      const users = (data || []).map(
        publicUser
      );

      return ok(res, {
        users,
        total: users.length
      });

    } catch (error) {
      console.error(
        "Admin utilisateurs:",
        error
      );

      return fail(
        res,
        "Impossible de charger les utilisateurs",
        500
      );
    }
  }
);

// -------------------- ADMIN : MESSAGES --------------------

app.get(
  "/api/admin/messages",
  requireServices,
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const [
        supportResult,
        contactsResult
      ] = await Promise.all([
        supabase
          .from("taya_v19_support_messages")
          .select("*")
          .limit(500),

        supabase
          .from("taya_v12_contacts")
          .select("*")
          .limit(500)
      ]);

      if (supportResult.error) {
        throw supportResult.error;
      }

      if (contactsResult.error) {
        throw contactsResult.error;
      }

      const messages = [
        ...(supportResult.data || []).map(
          item => ({
            ...item,
            type: "support"
          })
        ),

        ...(contactsResult.data || []).map(
          item => ({
            ...item,
            type: "contact"
          })
        )
      ];

      return ok(res, {
        messages,
        total: messages.length
      });

    } catch (error) {
      console.error(
        "Admin messages:",
        error
      );

      return fail(
        res,
        "Impossible de charger les messages",
        500
      );
    }
  }
);

// -------------------- PRÉSENCE --------------------

app.post(
  "/api/presence/heartbeat",
  requireServices,
  authenticate,
  (req, res) => {
    return ok(res, {
      online: true,
      user_id: req.user.id
    });
  }
);

// -------------------- AUDIO --------------------

app.post(
  "/api/audio/transcriptions",
  requireServices,
  authenticate,
  (req, res) => {
    return res.status(501).json({
      success: false,
      error:
        "La transcription audio par API n'est pas activée. Utilise la reconnaissance vocale du navigateur."
    });
  }
);

app.post(
  "/api/audio/speech",
  requireServices,
  authenticate,
  (req, res) => {
    return res.status(501).json({
      success: false,
      error:
        "La génération audio par API n'est pas activée. Utilise la synthèse vocale du navigateur."
    });
  }
);

// -------------------- ROUTE INCONNUE --------------------

app.use(
  "/api",
  (req, res) => {
    return fail(
      res,
      "Route API introuvable",
      404
    );
  }
);

// -------------------- GESTION DES ERREURS --------------------

app.use(
  (error, req, res, next) => {
    console.error(
      "Erreur serveur:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    return res.status(500).json({
      success: false,
      error: "Une erreur interne est survenue"
    });
  }
);

// -------------------- DÉMARRAGE SERVEUR --------------------

app.listen(PORT, () => {
  console.log("--------------------------------");
  console.log("TAYA IA API");
  console.log("Version :", VERSION);
  console.log("Port :", PORT);
  console.log("Supabase :", !!supabase);
  console.log("OpenRouter :", !!OPENROUTER_API_KEY);
  console.log("Tavily :", !!TAVILY_API_KEY);
  console.log("--------------------------------");
});
