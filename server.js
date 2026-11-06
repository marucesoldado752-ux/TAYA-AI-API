/**
 * TAYA IA — API V21.0.1
 * Backend Express + Supabase + OpenRouter + Tavily
 *
 * Clé primaire de taya_v13_users : p
 * Nom utilisateur : name
 * Les anciennes données V12/V19 sont conservées.
 */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const VERSION = "21.0.1";

const OPENROUTER_URL =
  "https://openrouter.ai/api/v1/chat/completions";

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

const SUPABASE_KEY =
  SUPABASE_SECRET_KEY || SUPABASE_SERVICE_ROLE_KEY;

const supabase =
  SUPABASE_URL && SUPABASE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_KEY, {
        auth: {
          autoRefreshToken: false,
          persistSession: false
        }
      })
    : null;

const ADMIN_PHONES = new Set([
  "+224663401157",
  "+224612768878"
]);

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
  .map(origin => origin.trim().replace(/\/+$/, ""))
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (
        !origin ||
        allowedOrigins.includes(origin.replace(/\/+$/, ""))
      ) {
        return callback(null, true);
      }

      return callback(
        new Error("Origine non autorisée par CORS")
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
    ],
    credentials: false
  })
);

app.use(express.json({ limit: "25mb" }));

app.use(
  express.urlencoded({
    extended: true,
    limit: "25mb"
  })
);

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

// Réponses standard
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

// Normalisation du téléphone
function normalizePhone(value) {
  let phone = String(value || "")
    .trim()
    .replace(/[^\d+]/g, "");

  if (phone && !phone.startsWith("+")) {
    phone = "+" + phone;
  }

  return phone;
}

// Vérification administrateur
function isAdmin(user) {
  return ADMIN_PHONES.has(
    normalizePhone(user && user.phone)
  );
}

// Informations publiques du compte
function publicUser(user) {
  if (!user) return null;

  return {
    id: user.p,
    p: user.p,
    name: user.name || user.full_name || "",
    full_name: user.name || user.full_name || "",
    phone: user.phone || "",
    email: user.email || "",
    avatar_url: user.avatar_url || "",
    role: isAdmin(user) ? "admin" : "user",
    created_at: user.created_at || null,
    last_seen_at: user.last_seen_at || null,
    must_reset_password: !!user.must_reset_password
  };
}

// Vérification des services
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

// Création du jeton de connexion
function signToken(user) {
  return jwt.sign(
    {
      id: user.p,
      phone: user.phone
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

// Sécurité du code de récupération
function hashRecoveryCode(code) {
  return crypto
    .createHash("sha256")
    .update(String(code))
    .digest("hex");
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));

  return (
    aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb)
  );
}

// Mot de passe sécurisé
async function makePasswordHash(password) {
  return bcrypt.hash(String(password), 12);
}

async function verifyPassword(user, password) {
  const supplied = String(password || "");

  if (user.password_hash) {
    const stored = String(user.password_hash);

    if (stored.startsWith("$2")) {
      return bcrypt.compare(supplied, stored);
    }

    if (/^[a-f0-9]{64}$/i.test(stored)) {
      return safeEqual(
        crypto
          .createHash("sha256")
          .update(supplied)
          .digest("hex"),
        stored.toLowerCase()
      );
    }

    return safeEqual(stored, supplied);
  }

  if (
    user.password !== undefined &&
    user.password !== null
  ) {
    return safeEqual(user.password, supplied);
  }

  return false;
}

async function upgradePassword(user, password) {
  const password_hash =
    await makePasswordHash(password);

  const { error } = await supabase
    .from("taya_v13_users")
    .update({
      password_hash,
      password: null,
      updated_at: new Date().toISOString()
    })
    .eq("p", user.p);

  if (error) {
    console.error(
      "Password upgrade:",
      error.message
    );
  }
}

// Vérification de la session
async function authenticate(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return fail(res, "Connexion requise", 401);
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("p", decoded.id)
      .maybeSingle();

    if (error || !user) {
      return fail(res, "Session invalide", 401);
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

// Protection administrateur
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

// Nettoyage des textes
function cleanText(value, max = 12000) {
  return String(value || "")
    .trim()
    .slice(0, max);
}

// Extraction du texte renvoyé par l'IA
function extractText(content) {
  if (typeof content === "string") {
    return content;
  }

  if (Array.isArray(content)) {
    return content.map(part => {
      if (typeof part === "string") {
        return part;
      }

      return (
        part && (part.text || part.content)
      ) || "";
    }).join("\n");
  }

  return "";
}// Connexion à OpenRouter
async function openRouter(messages, model) {
  if (!OPENROUTER_API_KEY) {
    throw new Error("OPENROUTER_API_KEY n'est pas configuré");
  }

  const response = await fetch(OPENROUTER_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "https://marucesoldado752-ux.github.io/",
      "X-Title": "TAYA IA"
    },
    body: JSON.stringify({
      model: model || OPENROUTER_MODEL,
      messages,
      temperature: 0.7
    })
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.error?.message || `Erreur IA (${response.status})`
    );
  }

  return extractText(
    data.choices?.[0]?.message?.content
  );
}

// Sauvegarde des messages
async function saveChatMessage(userId, role, message) {
  const { error } = await supabase
    .from("taya_v12_messages")
    .insert({
      user_id: userId,
      role,
      message
    });

  if (error) {
    console.error("Sauvegarde message:", error.message);
  }
}

// Lecture de la mémoire
async function getUserMemory(userId) {
  const { data, error } = await supabase
    .from("taya_v12_memories")
    .select("memory")
    .eq("user_id", userId)
    .maybeSingle();

  if (error && error.code !== "PGRST116") {
    throw error;
  }

  return data?.memory || "";
}

// Enregistrement de la mémoire
async function saveUserMemory(userId, memory) {
  const { data: existing, error: readError } =
    await supabase
      .from("taya_v12_memories")
      .select("user_id")
      .eq("user_id", userId)
      .maybeSingle();

  if (readError && readError.code !== "PGRST116") {
    throw readError;
  }

  if (existing) {
    const { error } = await supabase
      .from("taya_v12_memories")
      .update({
        memory,
        updated_at: new Date().toISOString()
      })
      .eq("user_id", userId);

    if (error) throw error;
  } else {
    const { error } = await supabase
      .from("taya_v12_memories")
      .insert({
        user_id: userId,
        memory,
        updated_at: new Date().toISOString()
      });

    if (error) throw error;
  }
}

// Recherche Web avec Tavily
async function webSearch(query) {
  if (!TAVILY_API_KEY) {
    throw new Error("Recherche Web non configurée");
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
        query,
        search_depth: "basic",
        max_results: 5,
        include_answer: true
      })
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.message || "Échec de la recherche Web"
    );
  }

  return data;
}

// Page d'accueil et état du serveur
app.get("/", (req, res) => {
  return ok(res, {
    name: "TAYA IA API",
    version: VERSION,
    status: "online"
  });
});

app.get("/api/status", (req, res) => {
  return ok(res, {
    version: VERSION,
    server: "online",
    supabase: !!supabase,
    ai: !!OPENROUTER_API_KEY,
    web_search: !!TAVILY_API_KEY,
    image_analysis: !!(
      OPENROUTER_API_KEY &&
      (OPENROUTER_VISION_MODEL || OPENROUTER_MODEL)
    ),
    pdf_analysis: !!(
      OPENROUTER_API_KEY &&
      (OPENROUTER_PDF_MODEL || OPENROUTER_MODEL)
    )
  });
});

// INSCRIPTION
app.post(
  "/api/auth/register",
  authLimiter,
  requireServices,
  async (req, res) => {
    try {
      const name = cleanText(
        req.body.name || req.body.full_name,
        100
      );

      const phone = normalizePhone(req.body.phone);
      const password = String(req.body.password || "");

      if (!name || !phone || password.length < 6) {
        return fail(
          res,
          "Nom, téléphone et mot de passe (6 caractères minimum) requis"
        );
      }

      const { data: found, error: findError } =
        await supabase
          .from("taya_v13_users")
          .select("p")
          .eq("phone", phone)
          .maybeSingle();

      if (findError) throw findError;

      if (found) {
        return fail(
          res,
          "Ce numéro est déjà inscrit",
          409
        );
      }

      const password_hash =
        await makePasswordHash(password);

      const recoveryCode = crypto
        .randomBytes(4)
        .toString("hex")
        .toUpperCase();

      const { data: user, error } = await supabase
        .from("taya_v13_users")
        .insert({
          name,
          phone,
          password_hash,
          recovery_code_hash: hashRecoveryCode(recoveryCode),
          role: ADMIN_PHONES.has(phone) ? "admin" : "user",
          must_reset_password: false
        })
        .select("*")
        .single();

      if (error) throw error;

      return ok(
        res,
        {
          token: signToken(user),
          user: publicUser(user),
          recovery_code: recoveryCode,
          message: "Compte créé avec succès. Conservez votre code de récupération."
        },
        201
      );

    } catch (error) {
      console.error("Register:", error.message);

      return fail(
        res,
        error.message || "Impossible de créer le compte",
        500
      );
    }
  }
);

// CONNEXION
app.post(
  "/api/auth/login",
  authLimiter,
  requireServices,
  async (req, res) => {
    try {
      const phone = normalizePhone(req.body.phone);
      const password = String(req.body.password || "");

      if (!phone || !password) {
        return fail(
          res,
          "Téléphone et mot de passe requis"
        );
      }

      const { data: user, error } = await supabase
        .from("taya_v13_users")
        .select("*")
        .eq("phone", phone)
        .maybeSingle();

      if (error) throw error;

      if (!user || !(await verifyPassword(user, password))) {
        return fail(
          res,
          "Numéro ou mot de passe incorrect",
          401
        );
      }

      if (
        !user.password_hash ||
        !String(user.password_hash).startsWith("$2")
      ) {
        await upgradePassword(user, password);
      }

      return ok(res, {
        token: signToken(user),
        user: publicUser(user)
      });

    } catch (error) {
      console.error("Login:", error.message);

      return fail(
        res,
        "Erreur pendant la connexion",
        500
      );
    }
  }
);

// RÉCUPÉRATION DU COMPTE
app.post(
  "/api/auth/recover",
  authLimiter,
  requireServices,
  async (req, res) => {
    try {
      const phone = normalizePhone(req.body.phone);

      const code = cleanText(
        req.body.recovery_code,
        100
      ).toUpperCase();

      const newPassword = String(
        req.body.new_password || ""
      );

      if (!phone || !code || newPassword.length < 6) {
        return fail(
          res,
          "Téléphone, code et nouveau mot de passe requis"
        );
      }

      const { data: user, error } = await supabase
        .from("taya_v13_users")
        .select("*")
        .eq("phone", phone)
        .maybeSingle();

      if (error) throw error;

      if (
        !user ||
        !user.recovery_code_hash ||
        !safeEqual(
          user.recovery_code_hash,
          hashRecoveryCode(code)
        )
      ) {
        return fail(
          res,
          "Code de récupération incorrect",
          401
        );
      }

      const password_hash =
        await makePasswordHash(newPassword);

      const { error: updateError } = await supabase
        .from("taya_v13_users")
        .update({
          password_hash,
          password: null,
          recovery_code_hash: null,
          must_reset_password: false,
          updated_at: new Date().toISOString()
        })
        .eq("p", user.p);

      if (updateError) throw updateError;

      return ok(res, {
        message: "Mot de passe modifié. Vous pouvez vous connecter."
      });

    } catch (error) {
      console.error("Recover:", error.message);

      return fail(
        res,
        "Impossible de récupérer le compte",
        500
      );
    }
  }
);

// COMPTE CONNECTÉ
app.get(
  "/api/auth/me",
  requireServices,
  authenticate,
  (req, res) => {
    return ok(res, {
      user: publicUser(req.user)
    });
  }
);

// HISTORIQUE
app.get(
  "/api/history",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const limit = Math.min(
        Math.max(Number(req.query.limit) || 100, 1),
        500
      );

      const { data, error } = await supabase
        .from("taya_v12_messages")
        .select("id,user_id,role,message")
        .eq("user_id", req.user.p)
        .limit(limit);

      if (error) throw error;

      return ok(res, {
        messages: data || []
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible de charger l'historique",
        500
      );
    }
  }
);

// SUPPRESSION DE L'HISTORIQUE
app.delete(
  "/api/history",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const { error } = await supabase
        .from("taya_v12_messages")
        .delete()
        .eq("user_id", req.user.p);

      if (error) throw error;

      return ok(res, {
        message: "Historique supprimé"
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible de supprimer l'historique",
        500
      );
    }
  }
);

// MÉMOIRE — LECTURE
app.get(
  "/api/memory",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const memory = await getUserMemory(req.user.p);

      return ok(res, { memory });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible de lire la mémoire",
        500
      );
    }
  }
);

// MÉMOIRE — ENREGISTREMENT
app.put(
  "/api/memory",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      await saveUserMemory(
        req.user.p,
        cleanText(req.body.memory, 20000)
      );

      return ok(res, {
        message: "Mémoire enregistrée"
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible d'enregistrer la mémoire",
        500
      );
    }
  }
);

// RECHERCHE WEB
app.post(
  "/api/search",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const query = cleanText(req.body.query, 1000);

      if (!query) {
        return fail(res, "Recherche manquante");
      }

      const result = await webSearch(query);

      return ok(res, { result });

    } catch (error) {
      return fail(
        res,
        error.message || "Recherche Web impossible",
        502
      );
    }
  }
);

// DISCUSSION AVEC TAYA IA
app.post(
  "/api/chat",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const message = cleanText(
        req.body.message || req.body.prompt,
        12000
      );

      if (!message) {
        return fail(res, "Message vide");
      }

      const memory = await getUserMemory(
        req.user.p
      ).catch(() => "");

      let searchContext = "";

      if (
        req.body.web_search === true &&
        TAVILY_API_KEY
      ) {
        const search = await webSearch(message);

        searchContext =
          "\n\nRésultats de recherche Web :\n" +
          JSON.stringify(search.results || [])
            .slice(0, 12000);
      }

      const history = Array.isArray(req.body.history)
        ? req.body.history
            .slice(-12)
            .map(item => ({
              role:
                item.role === "assistant"
                  ? "assistant"
                  : "user",
              content: cleanText(
                item.content || item.message,
                4000
              )
            }))
            .filter(item => item.content)
        : [];

      const system = [
        "Tu es TAYA IA, un assistant intelligent, précis et rapide créé par Maruce Soldado.",
        "Réponds dans la langue de l'utilisateur.",
        "Va directement à la réponse, sans introduction inutile.",
        "Sois honnête si tu ne connais pas une information. N'invente jamais de faits.",
        memory
          ? "Mémoire utile de l'utilisateur : " + memory
          : "",
        searchContext
      ]
        .filter(Boolean)
        .join("\n\n");

      const answer = await openRouter(
        [
          {
            role: "system",
            content: system
          },
          ...history,
          {
            role: "user",
            content: message
          }
        ]
      );

      await saveChatMessage(
        req.user.p,
        "user",
        message
      );

      await saveChatMessage(
        req.user.p,
        "assistant",
        answer
      );

      return ok(res, {
        answer,
        response: answer
      });

    } catch (error) {
      console.error("Chat:", error.message);

      return fail(
        res,
        error.message || "L'IA n'a pas pu répondre",
        502
      );
    }
  }
);// ======================================================
// ANALYSE DES IMAGES
// ======================================================

app.post(
  "/api/chat/image",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const image = String(
        req.body.image || req.body.data_url || ""
      );

      const message = cleanText(
        req.body.message || "Décris et analyse cette image.",
        4000
      );

      if (
        !/^data:image\/(png|jpe?g|webp|gif);base64,/i.test(image)
      ) {
        return fail(
          res,
          "Image invalide. Envoie une image PNG, JPG, WEBP ou GIF."
        );
      }

      const model =
        OPENROUTER_VISION_MODEL || OPENROUTER_MODEL;

      if (!model) {
        return fail(
          res,
          "Modèle d'analyse d'image non configuré",
          503
        );
      }

      const answer = await openRouter(
        [
          {
            role: "user",
            content: [
              {
                type: "text",
                text: message
              },
              {
                type: "image_url",
                image_url: {
                  url: image
                }
              }
            ]
          }
        ],
        model
      );

      return ok(res, {
        answer,
        response: answer
      });

    } catch (error) {
      console.error("Image:", error.message);

      return fail(
        res,
        error.message || "Analyse de l'image impossible",
        502
      );
    }
  }
);


// ======================================================
// LECTURE DES PDF
// ======================================================

app.post(
  "/api/chat/pdf",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const file = String(
        req.body.file || req.body.data || ""
      );

      const question = cleanText(
        req.body.message || "Résume et explique ce document.",
        4000
      );

      const base64 = file.replace(
        /^data:application\/pdf;base64,/i,
        ""
      );

      if (
        !base64 ||
        base64.length > 18 * 1024 * 1024
      ) {
        return fail(
          res,
          "PDF manquant ou trop volumineux."
        );
      }

      const buffer = Buffer.from(base64, "base64");

      if (buffer.subarray(0, 5).toString() !== "%PDF-") {
        return fail(res, "Fichier PDF invalide.");
      }

      let pdfParse;

      try {
        pdfParse = require("pdf-parse");
      } catch (_) {
        return fail(
          res,
          "Le module pdf-parse manque. Ajoute pdf-parse aux dépendances.",
          503
        );
      }

      const parsed = await pdfParse(buffer);

      const documentText = cleanText(
        parsed.text,
        50000
      );

      if (!documentText) {
        return fail(
          res,
          "Aucun texte lisible trouvé dans ce PDF."
        );
      }

      const answer = await openRouter(
        [
          {
            role: "system",
            content:
              "Tu es TAYA IA. Analyse le contenu du document et réponds précisément. N'invente rien."
          },
          {
            role: "user",
            content:
              `Question : ${question}\n\n` +
              `Contenu du PDF :\n${documentText}`
          }
        ],
        OPENROUTER_PDF_MODEL || OPENROUTER_MODEL
      );

      return ok(res, {
        answer,
        response: answer,
        pages: parsed.numpages || null
      });

    } catch (error) {
      console.error("PDF:", error.message);

      return fail(
        res,
        error.message || "Lecture du PDF impossible",
        502
      );
    }
  }
);


// ======================================================
// MESSAGES ENVOYÉS À MARUCE
// ======================================================

app.post(
  "/api/contacts",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const message = cleanText(
        req.body.message,
        5000
      );

      if (!message) {
        return fail(res, "Message vide");
      }

      const { data, error } = await supabase
        .from("taya_v12_contacts")
        .insert({
          user_id: req.user.p,
          message
        })
        .select("*")
        .single();

      if (error) throw error;

      return ok(
        res,
        {
          contact: data,
          message: "Message envoyé"
        },
        201
      );

    } catch (error) {
      console.error("Contact:", error.message);

      return fail(
        res,
        error.message || "Envoi impossible",
        500
      );
    }
  }
);


app.get(
  "/api/contacts",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v12_contacts")
        .select("*")
        .eq("user_id", req.user.p);

      if (error) throw error;

      return ok(res, {
        contacts: data || []
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible de charger les messages",
        500
      );
    }
  }
);


// ======================================================
// MESSAGES DE SUPPORT
// ======================================================

app.post(
  "/api/support/messages",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const message = cleanText(
        req.body.message,
        5000
      );

      if (!message) {
        return fail(res, "Message vide");
      }

      const { data, error } = await supabase
        .from("taya_v19_support_messages")
        .insert({
          user_id: req.user.p,
          sender_id: req.user.p,
          sender_role: isAdmin(req.user)
            ? "admin"
            : "user",
          message
        })
        .select("*")
        .single();

      if (error) throw error;

      return ok(
        res,
        {
          message: data
        },
        201
      );

    } catch (error) {
      console.error("Support:", error.message);

      return fail(
        res,
        error.message || "Envoi du message impossible",
        500
      );
    }
  }
);


app.get(
  "/api/support/messages",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      let query = supabase
        .from("taya_v19_support_messages")
        .select("*");

      if (!isAdmin(req.user)) {
        query = query.eq("user_id", req.user.p);
      }

      const { data, error } = await query;

      if (error) throw error;

      return ok(res, {
        messages: data || []
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible de charger les messages",
        500
      );
    }
  }
);


// ======================================================
// ADMINISTRATION — UTILISATEURS INSCRITS
// ======================================================

app.get(
  "/api/admin/users",
  requireServices,
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v13_users")
        .select(
          "p,name,phone,email,role,created_at,last_seen_at"
        )
        .order("created_at", {
          ascending: false
        })
        .limit(1000);

      if (error) throw error;

      return ok(res, {
        users: (data || []).map(publicUser)
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible de charger les inscrits",
        500
      );
    }
  }
);


// ======================================================
// ADMINISTRATION — MESSAGES
// ======================================================

app.get(
  "/api/admin/messages",
  requireServices,
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const [support, contacts] = await Promise.all([
        supabase
          .from("taya_v19_support_messages")
          .select("*")
          .limit(1000),

        supabase
          .from("taya_v12_contacts")
          .select("*")
          .limit(1000)
      ]);

      if (support.error) throw support.error;
      if (contacts.error) throw contacts.error;

      return ok(res, {
        support_messages: support.data || [],
        contact_messages: contacts.data || []
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible de charger les messages admin",
        500
      );
    }
  }
);


// ======================================================
// ADMINISTRATION — PRÉSENCE
// ======================================================

app.get(
  "/api/admin/presence",
  requireServices,
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v13_users")
        .select("p,name,phone,last_seen_at")
        .order("last_seen_at", {
          ascending: false
        })
        .limit(500);

      if (error) throw error;

      return ok(res, {
        users: data || []
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Impossible de charger les présences",
        500
      );
    }
  }
);


// ======================================================
// MISE À JOUR DE LA PRÉSENCE
// ======================================================

app.post(
  "/api/presence/heartbeat",
  requireServices,
  authenticate,
  async (req, res) => {
    try {
      const { error } = await supabase
        .from("taya_v13_users")
        .update({
          last_seen_at: new Date().toISOString()
        })
        .eq("p", req.user.p);

      if (error) throw error;

      return ok(res, {
        online: true
      });

    } catch (error) {
      return fail(
        res,
        error.message || "Mise à jour de présence impossible",
        500
      );
    }
  }
);


// ======================================================
// ROUTE INCONNUE
// ======================================================

app.use((req, res) => {
  return fail(
    res,
    "Route introuvable",
    404
  );
});


// ======================================================
// GESTION GÉNÉRALE DES ERREURS
// ======================================================

app.use((error, req, res, next) => {
  console.error(
    "Erreur serveur:",
    error && error.stack || error
  );

  if (res.headersSent) {
    return next(error);
  }

  return fail(
    res,
    error.message || "Erreur interne du serveur",
    500
  );
});


// ======================================================
// DÉMARRAGE DU SERVEUR — INDISPENSABLE POUR RENDER
// ======================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `TAYA IA API V${VERSION} démarrée sur le port ${PORT}`
  );
});
