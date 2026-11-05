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
const PORT = process.env.PORT || 3000;
const VERSION = "18.3.0";
const OPENROUTER_URL = "https://openrouter.ai/api/v1";

const {
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET,
  OPENROUTER_API_KEY,
  OPENROUTER_MODEL,
  OPENROUTER_STT_MODEL,
  OPENROUTER_TTS_MODEL,
  TAVILY_API_KEY
} = process.env;

const SUPABASE_KEY = SUPABASE_SECRET_KEY || SUPABASE_SERVICE_ROLE_KEY;

const FRONTEND_ORIGINS = (
  process.env.ALLOWED_ORIGIN || "https://marucesoldado752-ux.github.io"
)
  .split(",")
  .map(origin => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

if (!SUPABASE_URL || !SUPABASE_KEY) console.error("Configuration Supabase manquante.");
if (!JWT_SECRET) console.error("JWT_SECRET manquant.");
if (!OPENROUTER_API_KEY) console.error("OPENROUTER_API_KEY manquante.");

const supabase = SUPABASE_URL && SUPABASE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false }
    })
  : null;

app.disable("x-powered-by");

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);

    const normalized = origin.replace(/\/$/, "");

    if (FRONTEND_ORIGINS.includes(normalized)) {
      return callback(null, true);
    }

    return callback(new Error("Origine non autorisée"));
  },
  methods: ["GET", "POST", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false
}));

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use("/api/", apiLimiter);

const audioLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    error: "Trop de requêtes audio. Réessaie plus tard."
  }
});

/* ========================= OUTILS ========================= */

function success(res, data = {}) {
  return res.json({ success: true, ...data });
}

function failure(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message
  });
}

function normalizePhone(phone) {
  return String(phone || "").replace(/[^\d+]/g, "");
}

function isAdmin(phone) {
  return [
    "+224663401157",
    "+224612768878"
  ].includes(normalizePhone(phone));
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    role: isAdmin(user.phone) ? "admin" : "user",
    created_at: user.created_at
  };
}

function createToken(user) {
  if (!JWT_SECRET) throw new Error("JWT_SECRET manquant");

  return jwt.sign(
    { id: user.id, phone: user.phone },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function generateRecoveryCode() {
  return crypto.randomBytes(5).toString("hex").toUpperCase();
}

function hashRecoveryCode(code) {
  return crypto
    .createHash("sha256")
    .update(String(code).toUpperCase())
    .digest("hex");
}

function safeEqualText(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function requireServices(req, res, next) {
  if (!supabase) {
    return failure(res, 503, "Base de données non configurée.");
  }

  if (!JWT_SECRET) {
    return failure(res, 503, "Authentification non configurée.");
  }

  next();
}

app.use("/api/", (req, res, next) => {
  if (req.path === "/status") return next();
  return requireServices(req, res, next);
});

/* ========================= MOT DE PASSE ========================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `scrypt$${salt}$${hash}`;
}

async function verifyPassword(password, storedPassword) {
  if (!storedPassword) return false;

  const stored = String(storedPassword);

  if (/^\$2[aby]\$/.test(stored)) {
    return bcrypt.compare(password, stored);
  }

  if (stored.startsWith("scrypt$")) {
    const parts = stored.split("$");

    if (parts.length !== 3) return false;

    const original = Buffer.from(parts[2], "hex");

    const calculated = crypto.scryptSync(
      password,
      parts[1],
      original.length
    );

    return original.length === calculated.length &&
      crypto.timingSafeEqual(original, calculated);
  }

  return safeEqualText(stored, password);
}

async function savePassword(userId, password) {
  const { error } = await supabase
    .from("taya_v13_users")
    .update({
      password_hash: hashPassword(password),
      password: null,
      must_reset_password: false,
      updated_at: new Date().toISOString()
    })
    .eq("id", userId);

  if (error) throw error;
}

/* ========================= AUTHENTIFICATION ========================= */

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : null;

    if (!token) {
      return failure(res, 401, "Connexion requise.");
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("id", decoded.id)
      .maybeSingle();

    if (error || !user) {
      return failure(res, 401, "Compte introuvable.");
    }

    req.user = user;
    next();

  } catch (error) {
    return failure(res, 401, "Session expirée. Reconnecte-toi.");
  }
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req.user.phone)) {
    return failure(res, 403, "Accès administrateur refusé.");
  }

  next();
}

function openRouterHeaders() {
  return {
    Authorization: `Bearer ${OPENROUTER_API_KEY}`,
    "Content-Type": "application/json",
    "HTTP-Referer": "https://marucesoldado752-ux.github.io",
    "X-Title": "TAYA IA"
  };
}

function extractText(content) {
  if (typeof content === "string") return content;

  if (!Array.isArray(content)) return "";

  return content
    .filter(part =>
      part &&
      part.type === "text" &&
      typeof part.text === "string"
    )
    .map(part => part.text)
    .join("\n");
}

function isAllowedDataUrl(value, prefixes, maxChars = 20 * 1024 * 1024) {
  return typeof value === "string" &&
    value.length <= maxChars &&
    prefixes.some(prefix => value.startsWith(prefix));
}

/* ========================= ROUTES PUBLIQUES ========================= */

app.get("/", (req, res) => res.json({
  success: true,
  application: "TAYA IA",
  version: VERSION,
  creator: "MARUCE SOLDADO",
  country: "Guinée",
  server: "online"
}));

app.get("/api/status", (req, res) => success(res, {
  version: VERSION,
  server: "online",
  supabase: supabase ? "configured" : "not_configured",
  ai: OPENROUTER_API_KEY ? "configured" : "not_configured",
  web_search: TAVILY_API_KEY ? "configured" : "not_configured",
  image_analysis: OPENROUTER_API_KEY ? "available_if_model_supports_vision" : "not_configured",
  pdf_analysis: OPENROUTER_API_KEY ? "available" : "not_configured",
  voice_transcription: OPENROUTER_API_KEY ? "available" : "not_configured",
  voice_speech: OPENROUTER_API_KEY ? "available" : "not_configured"
}));

/* ========================= AUTH ========================= */

app.post("/api/auth/access", (req, res) => failure(
  res,
  403,
  "Cette méthode de connexion est désactivée. Utilise ton mot de passe."
));

app.post("/api/auth/legacy-reset", (req, res) => failure(
  res,
  403,
  "Réinitialisation non autorisée sans vérification du compte."
));/* =========================
   INSCRIPTION
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!name || !phone || password.length < 6) {
      return failure(
        res,
        400,
        "Nom, téléphone et mot de passe d'au moins 6 caractères obligatoires."
      );
    }

    const { data: existing, error: searchError } = await supabase
      .from("taya_v13_users")
      .select("id")
      .eq("phone", phone)
      .maybeSingle();

    if (searchError) {
      return failure(res, 500, "Erreur de vérification du compte.");
    }

    if (existing) {
      return failure(res, 409, "Ce numéro possède déjà un compte.");
    }

    const recoveryCode = generateRecoveryCode();

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .insert({
        name,
        phone,
        password_hash: hashPassword(password),
        password: null,
        recovery_code_hash: hashRecoveryCode(recoveryCode),
        role: isAdmin(phone) ? "admin" : "user",
        must_reset_password: false
      })
      .select("*")
      .single();

    if (error) {
      console.error("Register:", error.message);
      return failure(res, 500, "Impossible de créer le compte.");
    }

    return success(res, {
      message: "Compte créé avec succès.",
      token: createToken(user),
      user: publicUser(user),
      recovery_code: recoveryCode
    });

  } catch (error) {
    console.error("Register:", error.message);
    return failure(res, 500, "Erreur lors de l'inscription.");
  }
});

/* =========================
   CONNEXION
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!phone || !password) {
      return failure(res, 400, "Téléphone et mot de passe obligatoires.");
    }

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (error || !user) {
      return failure(res, 401, "Numéro ou mot de passe incorrect.");
    }

    const storedPassword = user.password_hash || user.password;
    const valid = await verifyPassword(password, storedPassword);

    if (!valid) {
      return failure(res, 401, "Numéro ou mot de passe incorrect.");
    }

    if (user.must_reset_password && !isAdmin(user.phone)) {
      return failure(
        res,
        403,
        "Ce compte doit être réactivé par une procédure de récupération vérifiée."
      );
    }

    if (user.must_reset_password && isAdmin(user.phone)) {
      await supabase
        .from("taya_v13_users")
        .update({
          must_reset_password: false,
          updated_at: new Date().toISOString()
        })
        .eq("id", user.id);
    }

    if (
      !user.password_hash ||
      !String(user.password_hash).startsWith("scrypt$")
    ) {
      await savePassword(user.id, password);
    }

    return success(res, {
      message: "Connexion réussie.",
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("Login:", error.message);
    return failure(res, 500, "Erreur lors de la connexion.");
  }
});

/* =========================
   RÉCUPÉRATION DU COMPTE
========================= */

app.post("/api/auth/recover", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const code = String(req.body.recovery_code || "");
    const newPassword = String(req.body.new_password || "");

    if (!phone || !code || newPassword.length < 6) {
      return failure(res, 400, "Informations de récupération invalides.");
    }

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (error || !user || !user.recovery_code_hash) {
      return failure(res, 400, "Code de récupération incorrect.");
    }

    if (!safeEqualText(
      hashRecoveryCode(code),
      user.recovery_code_hash
    )) {
      return failure(res, 400, "Code de récupération incorrect.");
    }

    const newCode = generateRecoveryCode();

    const { error: updateError } = await supabase
      .from("taya_v13_users")
      .update({
        password_hash: hashPassword(newPassword),
        password: null,
        recovery_code_hash: hashRecoveryCode(newCode),
        must_reset_password: false,
        updated_at: new Date().toISOString()
      })
      .eq("id", user.id);

    if (updateError) {
      return failure(res, 500, "Impossible de modifier le mot de passe.");
    }

    return success(res, {
      message: "Mot de passe modifié.",
      recovery_code: newCode
    });

  } catch (error) {
    console.error("Recover:", error.message);
    return failure(res, 500, "Erreur de récupération.");
  }
});

/* =========================
   UTILISATEUR CONNECTÉ
========================= */

app.get("/api/auth/me", authenticate, (req, res) => {
  success(res, {
    user: publicUser(req.user)
  });
});

/* =========================
   HISTORIQUE
========================= */

app.get("/api/history", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_v12_messages")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });

    if (error) {
      console.error("History:", error.message);
      return failure(res, 500, "Impossible de charger l'historique.");
    }

    success(res, {
      messages: data || []
    });

  } catch (error) {
    return failure(res, 500, "Erreur de chargement de l'historique.");
  }
});

/* =========================
   MÉMOIRE
========================= */

app.get("/api/memory", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_v12_memories")
      .select("*")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) {
      return failure(res, 500, "Impossible de charger la mémoire.");
    }

    success(res, {
      memory: data ? data.memory : ""
    });

  } catch (error) {
    return failure(res, 500, "Erreur de mémoire.");
  }
});

app.put("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = String(req.body.memory || "");

    if (memory.length > 20000) {
      return failure(res, 400, "La mémoire est trop longue.");
    }

    const { data: existing, error: searchError } = await supabase
      .from("taya_v12_memories")
      .select("user_id")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (searchError) {
      return failure(res, 500, "Erreur de mémoire.");
    }

    let result;

    if (existing) {
      result = await supabase
        .from("taya_v12_memories")
        .update({
          memory,
          updated_at: new Date().toISOString()
        })
        .eq("user_id", req.user.id);
    } else {
      result = await supabase
        .from("taya_v12_memories")
        .insert({
          user_id: req.user.id,
          memory,
          updated_at: new Date().toISOString()
        });
    }

    if (result.error) {
      return failure(res, 500, "Impossible d'enregistrer la mémoire.");
    }

    success(res, {
      message: "Mémoire enregistrée."
    });

  } catch (error) {
    return failure(res, 500, "Erreur d'enregistrement.");
  }
});

/* =========================
   RECHERCHE INTERNET
========================= */

async function searchWeb(query) {
  if (!TAVILY_API_KEY) {
    throw new Error("Recherche Internet non configurée.");
  }

  const response = await fetch("https://api.tavily.com/search", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      api_key: TAVILY_API_KEY,
      query,
      search_depth: "advanced",
      max_results: 6,
      include_answer: true
    })
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error("Erreur du service de recherche.");
  }

  return {
    answer: result.answer || "",
    results: (result.results || []).map(item => ({
      title: item.title || "",
      url: item.url || "",
      content: item.content || ""
    }))
  };
}

app.post("/api/search", authenticate, async (req, res) => {
  try {
    const query = String(req.body.query || "").trim();

    if (!query) {
      return failure(res, 400, "Écris ce que tu veux rechercher.");
    }

    if (query.length > 1000) {
      return failure(res, 400, "Recherche trop longue.");
    }

    const results = await searchWeb(query);

    success(res, {
      query,
      answer: results.answer,
      results: results.results
    });

  } catch (error) {
    console.error("Search:", error.message);
    return failure(res, 502, error.message);
  }
});

/* =========================
   CONSTRUCTION DU PROMPT IA
========================= */

async function getUserMemory(userId) {
  const { data, error } = await supabase
    .from("taya_v12_memories")
    .select("memory")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) {
    console.error("Memory read:", error.message);
    return "";
  }

  return data?.memory || "";
}

function buildSystemPrompt(user, memory, webContext = "") {
  return `
Tu es TAYA IA, assistant intelligent créé par MARUCE SOLDADO en Guinée 🇬🇳.

RÈGLES :
- Réponds directement et clairement.
- Comprends le français et les autres langues.
- Aide en programmation, mathématiques, rédaction, traduction et explications.
- Ne fabrique jamais de sources ni de faits.
- Si tu ne connais pas une réponse, dis-le.
- Utilise les résultats de recherche lorsqu'ils sont fournis.
- Distingue les faits vérifiés des hypothèses.
- Adapte la longueur de la réponse à la question.
- Ne prétends pas avoir consulté Internet si aucun résultat n'est fourni.

Utilisateur : ${user.name || "Utilisateur"}

Mémoire enregistrée :
${memory || "Aucune mémoire enregistrée."}

Résultats Internet disponibles :
${webContext || "Aucune recherche Internet effectuée."}
`;
}

/* =========================
   CHAT IA AVEC RECHERCHE
========================= */

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return failure(res, 503, "Service IA non configuré.");
    }

    let messages = [];

    if (Array.isArray(req.body.messages)) {
      messages = req.body.messages;
    } else if (req.body.message) {
      messages = [{
        role: "user",
        content: String(req.body.message)
      }];
    }

    const safeMessages = messages
      .filter(item =>
        item &&
        ["user", "assistant"].includes(item.role) &&
        (
          typeof item.content === "string" ||
          Array.isArray(item.content)
        )
      )
      .slice(-30);

    if (!safeMessages.length) {
      return failure(res, 400, "Écris un message.");
    }

    const lastUserMessage = [...safeMessages]
      .reverse()
      .find(item => item.role === "user");

    if (!lastUserMessage) {
      return failure(res, 400, "Message utilisateur introuvable.");
    }

    const userText = extractText(lastUserMessage.content);

    let webContext = "";

    // La recherche peut être demandée explicitement par le frontend.
    if (req.body.web_search === true && userText) {
      if (!TAVILY_API_KEY) {
        return failure(res, 503, "Recherche Internet non configurée.");
      }

      const searchResults = await searchWeb(userText);

      webContext = JSON.stringify(searchResults);
    }

    const memory = await getUserMemory(req.user.id);

    const systemPrompt = buildSystemPrompt(
      req.user,
      memory,
      webContext
    );

    const response = await fetch(
      `${OPENROUTER_URL}/chat/completions`,
      {
        method: "POST",
        headers: openRouterHeaders(),
        body: JSON.stringify({
          model: OPENROUTER_MODEL || "openai/gpt-4o-mini",
          messages: [
            {
              role: "system",
              content: systemPrompt
            },
            ...safeMessages
          ],
          temperature: 0.7
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error(
        "OpenRouter:",
        response.status,
        result?.error?.message || "Erreur IA"
      );

      return failure(res, 502, "Le service IA ne répond pas actuellement.");
    }

    const reply = result?.choices?.[0]?.message?.content;

    if (!reply) {
      return failure(res, 502, "Réponse IA vide.");
    }

    const { error: userSaveError } = await supabase
      .from("taya_v12_messages")
      .insert({
        user_id: req.user.id,
        role: "user",
        message: userText || "[Message avec contenu multimédia]"
      });

    if (userSaveError) {
      console.error("Save user message:", userSaveError.message);
    }

    const { error: assistantSaveError } = await supabase
      .from("taya_v12_messages")
      .insert({
        user_id: req.user.id,
        role: "assistant",
        message: reply
      });

    if (assistantSaveError) {
      console.error("Save assistant message:", assistantSaveError.message);
    }

    return success(res, {
      reply,
      answer: reply,
      web_search_used: Boolean(webContext)
    });

  } catch (error) {
    console.error("Chat:", error.message);
    return failure(res, 500, "Erreur pendant la réponse de TAYA IA.");
  }
});/* =========================
   ANALYSE DES IMAGES
========================= */

app.post("/api/chat/image", authenticate, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return failure(res, 503, "Service IA non configuré.");
    }

    const image = req.body.image;
    const question = String(
      req.body.question || "Décris et analyse cette image."
    ).trim();

    if (!isAllowedDataUrl(
      image,
      ["data:image/jpeg;base64,", "data:image/png;base64,", "data:image/webp;base64,"],
      12 * 1024 * 1024
    )) {
      return failure(res, 400, "Image invalide ou trop volumineuse.");
    }

    const model =
      process.env.OPENROUTER_VISION_MODEL ||
      OPENROUTER_MODEL ||
      "openai/gpt-4o-mini";

    const memory = await getUserMemory(req.user.id);

    const response = await fetch(
      `${OPENROUTER_URL}/chat/completions`,
      {
        method: "POST",
        headers: openRouterHeaders(),
        body: JSON.stringify({
          model,
          messages: [
            {
              role: "system",
              content: buildSystemPrompt(req.user, memory)
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
                    url: image
                  }
                }
              ]
            }
          ],
          temperature: 0.5
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("Image AI:", result?.error?.message);
      return failure(res, 502, "Impossible d'analyser cette image.");
    }

    const reply = result?.choices?.[0]?.message?.content;

    if (!reply) {
      return failure(res, 502, "Analyse de l'image vide.");
    }

    await supabase.from("taya_v12_messages").insert([
      {
        user_id: req.user.id,
        role: "user",
        message: "[Image] " + question
      },
      {
        user_id: req.user.id,
        role: "assistant",
        message: reply
      }
    ]);

    return success(res, {
      reply,
      answer: reply
    });

  } catch (error) {
    console.error("Image:", error.message);
    return failure(res, 500, "Erreur pendant l'analyse de l'image.");
  }
});


/* =========================
   LECTURE DES PDF
========================= */

app.post("/api/chat/pdf", authenticate, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return failure(res, 503, "Service IA non configuré.");
    }

    const pdf = req.body.pdf;
    const question = String(
      req.body.question || "Lis ce document et résume son contenu."
    ).trim();

    if (!isAllowedDataUrl(
      pdf,
      ["data:application/pdf;base64,"],
      18 * 1024 * 1024
    )) {
      return failure(res, 400, "Document PDF invalide ou trop volumineux.");
    }

    const model =
      process.env.OPENROUTER_PDF_MODEL ||
      OPENROUTER_MODEL ||
      "openai/gpt-4o-mini";

    const memory = await getUserMemory(req.user.id);

    const response = await fetch(
      `${OPENROUTER_URL}/chat/completions`,
      {
        method: "POST",
        headers: openRouterHeaders(),
        body: JSON.stringify({
          model,
          messages: [
            {
              role: "system",
              content: buildSystemPrompt(req.user, memory)
            },
            {
              role: "user",
              content: [
                {
                  type: "text",
                  text: question
                },
                {
                  type: "file",
                  file: {
                    filename: "document.pdf",
                    file_data: pdf
                  }
                }
              ]
            }
          ],
          temperature: 0.4
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("PDF AI:", result?.error?.message);
      return failure(res, 502, "Impossible d'analyser ce PDF.");
    }

    const reply = result?.choices?.[0]?.message?.content;

    if (!reply) {
      return failure(res, 502, "Analyse du PDF vide.");
    }

    await supabase.from("taya_v12_messages").insert([
      {
        user_id: req.user.id,
        role: "user",
        message: "[Document PDF] " + question
      },
      {
        user_id: req.user.id,
        role: "assistant",
        message: reply
      }
    ]);

    return success(res, {
      reply,
      answer: reply
    });

  } catch (error) {
    console.error("PDF:", error.message);
    return failure(res, 500, "Erreur pendant la lecture du PDF.");
  }
});


/* =========================
   TRANSCRIPTION VOCALE
========================= */

app.post(
  "/api/audio/transcriptions",
  authenticate,
  audioLimiter,
  async (req, res) => {
    try {
      if (!OPENROUTER_API_KEY) {
        return failure(res, 503, "Service audio non configuré.");
      }

      const audio = String(req.body.audio || "");
      const format = String(req.body.format || "wav").toLowerCase();

      const allowedFormats = [
        "wav",
        "mp3",
        "flac",
        "m4a",
        "ogg",
        "webm",
        "aac"
      ];

      if (!allowedFormats.includes(format)) {
        return failure(res, 400, "Format audio non accepté.");
      }

      if (
        !audio ||
        audio.length > 20 * 1024 * 1024 ||
        !/^[A-Za-z0-9+/]+={0,2}$/.test(audio)
      ) {
        return failure(res, 400, "Fichier audio invalide ou trop volumineux.");
      }

      const model =
        process.env.OPENROUTER_STT_MODEL ||
        "openai/whisper-1";

      const response = await fetch(
        `${OPENROUTER_URL}/audio/transcriptions`,
        {
          method: "POST",
          headers: openRouterHeaders(),
          body: JSON.stringify({
            model,
            input_audio: {
              data: audio,
              format
            },
            language: "fr"
          })
        }
      );

      const result = await response.json();

      if (!response.ok) {
        console.error("Transcription:", result?.error?.message);
        return failure(res, 502, "Impossible de transcrire cet audio.");
      }

      return success(res, {
        text: result.text || "",
        usage: result.usage || null
      });

    } catch (error) {
      console.error("Audio transcription:", error.message);
      return failure(res, 500, "Erreur de transcription.");
    }
  }
);


/* =========================
   GÉNÉRATION VOCALE
========================= */

app.post(
  "/api/audio/speech",
  authenticate,
  audioLimiter,
  async (req, res) => {
    try {
      if (!OPENROUTER_API_KEY) {
        return failure(res, 503, "Service vocal non configuré.");
      }

      const input = String(req.body.text || "").trim();

      if (!input) {
        return failure(res, 400, "Aucun texte à prononcer.");
      }

      if (input.length > 4000) {
        return failure(res, 400, "Texte trop long pour la lecture vocale.");
      }

      const model =
        process.env.OPENROUTER_TTS_MODEL ||
        "openai/gpt-4o-mini-tts";

      const response = await fetch(
        `${OPENROUTER_URL}/audio/speech`,
        {
          method: "POST",
          headers: openRouterHeaders(),
          body: JSON.stringify({
            model,
            input,
            voice: "alloy",
            response_format: "mp3"
          })
        }
      );

      if (!response.ok) {
        const errorText = await response.text();

        console.error("TTS:", response.status, errorText);

        return failure(res, 502, "Impossible de générer la voix.");
      }

      const audioBuffer = Buffer.from(
        await response.arrayBuffer()
      );

      res.set({
        "Content-Type": "audio/mpeg",
        "Content-Length": audioBuffer.length,
        "Cache-Control": "no-store"
      });

      return res.send(audioBuffer);

    } catch (error) {
      console.error("TTS:", error.message);
      return failure(res, 500, "Erreur de génération vocale.");
    }
  }
);


/* =========================
   CONTACT MARUCE
========================= */

app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message) {
      return failure(res, 400, "Écris un message avant l'envoi.");
    }

    if (message.length > 5000) {
      return failure(res, 400, "Message trop long.");
    }

    const { error } = await supabase
      .from("taya_v12_contacts")
      .insert({
        user_id: req.user.id,
        message
      });

    if (error) {
      console.error("Contact:", error.message);
      return failure(res, 500, "Impossible d'envoyer le message.");
    }

    return success(res, {
      message: "Message envoyé à Maruce."
    });

  } catch (error) {
    console.error("Contact:", error.message);
    return failure(res, 500, "Erreur d'envoi du message.");
  }
});


/* =========================
   ADMIN : UTILISATEURS
========================= */

app.get(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v13_users")
        .select("id,name,phone,email,created_at,role,must_reset_password")
        .order("created_at", { ascending: false });

      if (error) {
        console.error("Admin users:", error.message);
        return failure(res, 500, "Impossible de charger les utilisateurs.");
      }

      const users = (data || []).map(user => ({
        ...user,
        role: isAdmin(user.phone) ? "admin" : "user"
      }));

      return success(res, { users });

    } catch (error) {
      return failure(res, 500, "Erreur de chargement des utilisateurs.");
    }
  }
);


/* =========================
   ADMIN : MESSAGES
========================= */

app.get(
  "/api/admin/messages",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v12_contacts")
        .select("*")
        .order("created_at", { ascending: false });

      if (error) {
        console.error("Admin messages:", error.message);
        return failure(res, 500, "Impossible de charger les messages.");
      }

      return success(res, {
        messages: data || []
      });

    } catch (error) {
      return failure(res, 500, "Erreur de chargement des messages.");
    }
  }
);


/* =========================
   GESTION DES ERREURS
========================= */

app.use((err, req, res, next) => {
  if (err.message === "Origine non autorisée") {
    return failure(res, 403, "Origine non autorisée.");
  }

  if (err.type === "entity.too.large") {
    return failure(res, 413, "Fichier trop volumineux.");
  }

  console.error("Server error:", err.message);

  return failure(res, 500, "Erreur interne du serveur.");
});

app.use((req, res) => {
  return failure(res, 404, "Route introuvable.");
});


/* =========================
   DÉMARRAGE DU SERVEUR
========================= */

app.listen(PORT, () => {
  console.log("--------------------------------");
  console.log("TAYA IA V" + VERSION);
  console.log("Serveur démarré sur le port " + PORT);
  console.log("Créateur : MARUCE SOLDADO 🇬🇳");
  console.log("Supabase :", supabase ? "Configuré" : "Non configuré");
  console.log("OpenRouter :", OPENROUTER_API_KEY ? "Configuré" : "Non configuré");
  console.log("Tavily :", TAVILY_API_KEY ? "Configuré" : "Non configuré");
  console.log("--------------------------------");
});
