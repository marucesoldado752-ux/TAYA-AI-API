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
const VERSION = "19.0.0";
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
  return crypto.createHash("sha256")
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

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto.scryptSync(password, salt, 64).toString("hex");

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

function isAllowedDataUrl(
  value,
  prefixes,
  maxChars = 20 * 1024 * 1024
) {
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
  image_analysis: OPENROUTER_API_KEY
    ? "available_if_model_supports_vision"
    : "not_configured",
  pdf_analysis: OPENROUTER_API_KEY ? "available" : "not_configured",
  voice_transcription: OPENROUTER_API_KEY ? "available" : "not_configured",
  voice_speech: OPENROUTER_API_KEY ? "available" : "not_configured"
}));  pdf_analysis: OPENROUTER_API_KEY ? "available" : "not_configured",
  voice_transcription: OPENROUTER_API_KEY ? "available" : "not_configured",
  voice_speech: OPENROUTER_API_KEY ? "available" : "not_configured"
}));

/* ========================= AUTH ========================= */
app.post("/api/auth/access", (req, res) => failure(res, 403,
  "Cette méthode de connexion est désactivée. Utilise ton mot de passe."));
app.post("/api/auth/legacy-reset", (req, res) => failure(res, 403,
  "Réinitialisation non autorisée sans vérification du compte."));

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim().slice(0, 100);
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");
    if (!name || !phone || password.length < 6 || password.length > 128) {
      return failure(res, 400, "Nom, téléphone et mot de passe de 6 à 128 caractères obligatoires.");
    }
    const { data: existing, error: searchError } = await supabase
      .from("taya_v13_users").select("id").eq("phone", phone).maybeSingle();
    if (searchError) return failure(res, 500, "Erreur lors de la vérification du compte.");
    if (existing) return failure(res, 409, "Ce numéro possède déjà un compte.");

    const recoveryCode = generateRecoveryCode();
    const { data: user, error } = await supabase.from("taya_v13_users").insert({
      name,
      phone,
      password_hash: hashPassword(password),
      password: null,
      recovery_code_hash: hashRecoveryCode(recoveryCode),
      role: isAdmin(phone) ? "admin" : "user",
      must_reset_password: false
    }).select("*").single();
    if (error) {
      console.error("Inscription Supabase:", error.message);
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

app.post("/api/auth/login", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");
    if (!phone || !password) return failure(res, 400, "Téléphone et mot de passe obligatoires.");
    const { data: user, error } = await supabase
      .from("taya_v13_users").select("*").eq("phone", phone).maybeSingle();
    if (error || !user) return failure(res, 401, "Numéro ou mot de passe incorrect.");
    const valid = await verifyPassword(password, user.password_hash || user.password);
    if (!valid) return failure(res, 401, "Numéro ou mot de passe incorrect.");

    if (user.must_reset_password && isAdmin(user.phone)) {
      const { error: updateError } = await supabase.from("taya_v13_users").update({
        must_reset_password: false,
        updated_at: new Date().toISOString()
      }).eq("id", user.id);
      if (updateError) console.error("Admin update:", updateError.message);
    } else if (user.must_reset_password) {
      return failure(res, 403,
        "Ce compte doit être réactivé par une procédure de récupération vérifiée.");
    }

    if (!user.password_hash || !String(user.password_hash).startsWith("scrypt$")) {
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

app.post("/api/auth/recover", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const recoveryCode = String(req.body.recovery_code || "");
    const newPassword = String(req.body.new_password || "");
    if (!phone || !recoveryCode || newPassword.length < 6 || newPassword.length > 128) {
      return failure(res, 400, "Informations de récupération invalides.");
    }
    const { data: user, error } = await supabase
      .from("taya_v13_users").select("*").eq("phone", phone).maybeSingle();
    if (error || !user || !user.recovery_code_hash ||
        !safeEqualText(hashRecoveryCode(recoveryCode), user.recovery_code_hash)) {
      return failure(res, 400, "Code de récupération incorrect.");
    }
    const newRecoveryCode = generateRecoveryCode();
    const { error: updateError } = await supabase.from("taya_v13_users").update({
      password_hash: hashPassword(newPassword),
      password: null,
      recovery_code_hash: hashRecoveryCode(newRecoveryCode),
      must_reset_password: false,
      updated_at: new Date().toISOString()
    }).eq("id", user.id);
    if (updateError) return failure(res, 500, "Impossible de modifier le mot de passe.");
    return success(res, { message: "Mot de passe modifié.", recovery_code: newRecoveryCode });
  } catch (error) {
    console.error("Recover:", error.message);
    return failure(res, 500, "Erreur de récupération.");
  }
});

app.get("/api/auth/me", authenticate, (req, res) => success(res, { user: publicUser(req.user) }));

/* ========================= HISTORIQUE ET MÉMOIRE ========================= */
app.get("/api/history", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from("taya_v12_messages")
      .select("*").eq("user_id", req.user.id).order("created_at", { ascending: true });
    if (error) {
      console.error("History:", error.message);
      return failure(res, 500, "Impossible de charger l'historique.");
    }
    return success(res, { messages: data || [] });
  } catch (error) {
    return failure(res, 500, "Erreur de chargement de l'historique.");
  }
});

app.get("/api/memory", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from("taya_v12_memories")
      .select("*").eq("user_id", req.user.id).maybeSingle();
    if (error) return failure(res, 500, "Impossible de charger la mémoire.");
    return success(res, { memory: data ? data.memory : "" });
  } catch (error) {
    return failure(res, 500, "Erreur de mémoire.");
  }
});

app.put("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = String(req.body.memory || "").slice(0, 12000);
    const { data: existing, error: searchError } = await supabase.from("taya_v12_memories")
      .select("user_id").eq("user_id", req.user.id).maybeSingle();
    if (searchError) return failure(res, 500, "Erreur de mémoire.");
    const result = existing
      ? await supabase.from("taya_v12_memories").update({ memory, updated_at: new Date().toISOString() }).eq("user_id", req.user.id)
      : await supabase.from("taya_v12_memories").insert({ user_id: req.user.id, memory, updated_at: new Date().toISOString() });
    if (result.error) return failure(res, 500, "Impossible d'enregistrer la mémoire.");
    return success(res, { message: "Mémoire enregistrée." });
  } catch (error) {
    return failure(res, 500, "Erreur d'enregistrement.");
  }
});

/* ========================= RECHERCHE WEB TAVILY ========================= */
async function tavilySearch(query) {
  if (!TAVILY_API_KEY) throw new Error("TAVILY_NOT_CONFIGURED");
  const response = await fetch("https://api.tavily.com/search", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${TAVILY_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      query,
      search_depth: "basic",
      topic: "general",
      max_results: 6,
      include_answer: true,
      include_raw_content: false
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error("Tavily error:", response.status, data?.detail || data?.error || "Search error");
    throw new Error("TAVILY_SEARCH_FAILED");
  }
  return {
    answer: data.answer || "",
    results: (data.results || []).slice(0, 6).map(item => ({
      title: String(item.title || "Source"),
      url: String(item.url || ""),
      content: String(item.content || "").slice(0, 1800),
      score: item.score
    }))
  };
}

app.post("/api/search", authenticate, async (req, res) => {
  try {
    const query = String(req.body.query || "").trim().slice(0, 500);
    if (!query) return failure(res, 400, "Écris ce que tu veux rechercher.");
    const search = await tavilySearch(query);
    return success(res, search);
  } catch (error) {
    if (error.message === "TAVILY_NOT_CONFIGURED") {
      return failure(res, 503, "Recherche Web non configurée. Ajoute TAVILY_API_KEY dans Render.");
    }
    return failure(res, 502, "La recherche Internet est momentanément indisponible.");
  }
});

/* ========================= CHAT MULTIMODAL ========================= */
function normalizeChatMessages(inputMessages, attachments) {
  if (!Array.isArray(inputMessages)) return [];
  const output = [];
  for (const item of inputMessages.slice(-30)) {
    if (!item || !["user", "assistant"].includes(item.role)) continue;
    if (typeof item.content === "string") {
      output.push({ role: item.role, content: item.content.slice(0, 20000) });
      continue;
    }
    if (!Array.isArray(item.content)) continue;
    const parts = [];
    for (const part of item.content.slice(0, 8)) {
      if (!part || typeof part !== "object") continue;
      if (part.type === "text" && typeof part.text === "string") {
        parts.push({ type: "text", text: part.text.slice(0, 12000) });
      } else if (part.type === "image_url") {
        const url = typeof part.image_url === "string" ? part.image_url : part.image_url?.url;
        if (isAllowedDataUrl(url, ["data:image/jpeg;base64,", "data:image/png;base64,", "data:image/webp;base64,"], 12 * 1024 * 1024) ||
            (typeof url === "string" && /^https:\/\//i.test(url) && url.length < 3000)) {
          parts.push({ type: "image_url", image_url: { url } });
        }
      } else if (part.type === "file" && part.file) {
        const filename = String(part.file.filename || "document.pdf").slice(0, 120);
        const fileData = part.file.file_data;
        if (/\.pdf$/i.test(filename) && isAllowedDataUrl(fileData, ["data:application/pdf;base64,"], 18 * 1024 * 1024)) {
          parts.push({ type: "file", file: { filename, file_data: fileData } });
        }
      }
    }
    if (parts.length) output.push({ role: item.role, content: parts });
  }

  // Option facultative : pièces jointes envoyées séparément du tableau messages.
  if (Array.isArray(attachments) && attachments.length) {
    const lastUserIndex = [...output].map(m => m.role).lastIndexOf("user");
    if (lastUserIndex >= 0) {
      const current = output[lastUserIndex];
      const parts = typeof current.content === "string"
        ? [{ type: "text", text: current.content }]
        : [...current.content];
      for (const attachment of attachments.slice(0, 4)) {
        if (attachment?.type === "image" && isAllowedDataUrl(attachment.data, [
          "data:image/jpeg;base64,", "data:image/png;base64,", "data:image/webp;base64,"
        ], 12 * 1024 * 1024)) {
          parts.push({ type: "image_url", image_url: { url: attachment.data } });
        }
        if (attachment?.type === "pdf" && isAllowedDataUrl(attachment.data, ["data:application/pdf;base64,"], 18 * 1024 * 1024)) {
          const filename = String(attachment.name || "document.pdf").slice(0, 120);
          parts.push({ type: "file", file: { filename: filename.toLowerCase().endsWith(".pdf") ? filename : `${filename}.pdf`, file_data: attachment.data } });
        }
      }
      output[lastUserIndex] = { role: "user", content: parts };
    }
  }
  return output;
}

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) return failure(res, 503, "Service IA non configuré.");
    let inputMessages = Array.isArray(req.body.messages)
      ? req.body.messages
      : (req.body.message ? [{ role: "user", content: String(req.body.message) }] : []);
    const safeMessages = normalizeChatMessages(inputMessages, req.body.attachments);
    if (!safeMessages.length) return failure(res, 400, "Écris un message ou joins un fichier valide.");
    const lastUserMessage = [...safeMessages].reverse().find(item => item.role === "user");
    const lastUserText = extractText(lastUserMessage?.content).slice(0, 12000);

    const { data: memoryData } = await supabase.from("taya_v12_memories")
      .select("memory").eq("user_id", req.user.id).maybeSingle();
    const memory = String(memoryData?.memory || "").slice(0, 12000);

    let searchContext = "";
    let sources = [];
    if (req.body.web_search === true) {
      if (!lastUserText.trim()) return failure(res, 400, "Ajoute une question écrite pour lancer la recherche Web.");
      try {
        const search = await tavilySearch(lastUserText);
        sources = search.results;
        searchContext = `\n\nINFORMATIONS TROUVÉES SUR LE WEB (à vérifier et à synthétiser) :\n${search.answer}\n` +
          search.results.map((item, index) => `[${index + 1}] ${item.title}\nURL: ${item.url}\n${item.content}`).join("\n\n");
      } catch (searchError) {
        if (searchError.message === "TAVILY_NOT_CONFIGURED") {
          return failure(res, 503, "Recherche Web non configurée. Ajoute TAVILY_API_KEY dans Render.");
        }
        return failure(res, 502, "La recherche Internet a échoué. Réessaie.");
      }
    }

    const systemPrompt = `Tu es TAYA IA, un assistant intelligent créé par MARUCE SOLDADO en Guinée 🇬🇳.
Réponds directement, clairement et dans la langue de l'utilisateur. Aide en programmation, mathématiques, rédaction, traduction et explications. N'invente jamais de faits ou de sources. Si une information manque, dis-le clairement. Lorsque des sources Web sont fournies, base les faits récents sur elles et cite les liens utiles dans ta réponse.
Nom de l'utilisateur : ${req.user.name || "Utilisateur"}
Mémoire de l'utilisateur :\n${memory || "Aucune mémoire enregistrée."}${searchContext}`;

    const response = await fetch(`${OPENROUTER_URL}/chat/completions`, {
      method: "POST",
      headers: openRouterHeaders(),
      body: JSON.stringify({
        model: OPENROUTER_MODEL || "openai/gpt-4o-mini",
        messages: [{ role: "system", content: systemPrompt }, ...safeMessages],
        temperature: 0.7,
        max_tokens: 1800
      })
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      console.error("OpenRouter chat error:", response.status, result?.error?.message || "Erreur IA");
      return failure(res, 502, "Le modèle IA n'a pas pu traiter ce message. Vérifie que le modèle choisi accepte les images/PDF si tu as joint un fichier.");
    }
    const reply = result?.choices?.[0]?.message?.content;
    if (typeof reply !== "string" || !reply.trim()) return failure(res, 502, "Réponse IA vide.");

    // On conserve dans l'historique uniquement le texte, jamais les données base64 des fichiers.
    if (lastUserText.trim()) {
      const { error: saveUserError } = await supabase.from("taya_v12_messages").insert({
        user_id: req.user.id, role: "user", message: lastUserText
      });
      if (saveUserError) console.error("Save user message:", saveUserError.message);
    } else if (lastUserMessage) {
      const { error: saveUserError } = await supabase.from("taya_v12_messages").insert({
        user_id: req.user.id, role: "user", message: "[Pièce jointe envoyée pour analyse]"
      });
      if (saveUserError) console.error("Save attachment message:", saveUserError.message);
    }
    const { error: saveAssistantError } = await supabase.from("taya_v12_messages").insert({
      user_id: req.user.id, role: "assistant", message: reply
    });
    if (saveAssistantError) console.error("Save assistant message:", saveAssistantError.message);

    return success(res, { reply, answer: reply, sources });
  } catch (error) {
    console.error("Chat error:", error.message);
    return failure(res, 500, "Une erreur est survenue pendant la réponse.");
  }
});

/* ========================= AUDIO : TRANSCRIPTION ET VOIX ========================= */
app.post("/api/audio/transcriptions", authenticate, audioLimiter, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) return failure(res, 503, "Service audio non configuré.");
    let audio = String(req.body.audio_base64 || req.body.audio || "");
    let format = String(req.body.format || "webm").toLowerCase().replace(/[^a-z0-9]/g, "");
    const language = String(req.body.language || "").slice(0, 20);
    if (audio.startsWith("data:")) {
      const match = audio.match(/^data:audio\/([a-zA-Z0-9.+-]+);base64,(.+)$/s);
      if (!match) return failure(res, 400, "Format audio invalide.");
      format = match[1].toLowerCase().replace("x-", "");
      audio = match[2];
    }
    if (!audio || audio.length > 18 * 1024 * 1024 || !/^[A-Za-z0-9+/=]+$/.test(audio)) {
      return failure(res, 400, "Fichier audio absent ou trop volumineux.");
    }
    const allowedFormats = ["wav", "mp3", "flac", "m4a", "ogg", "webm", "aac", "mp4"];
    if (!allowedFormats.includes(format)) return failure(res, 400, "Format audio non pris en charge.");
    const payload = {
      model: OPENROUTER_STT_MODEL || "openai/whisper-large-v3",
      input_audio: { data: audio, format }
    };
    if (language) payload.language = language;
    const response = await fetch(`${OPENROUTER_URL}/audio/transcriptions`, {
      method: "POST",
      headers: openRouterHeaders(),
      body: JSON.stringify(payload)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) {
      console.error("OpenRouter transcription:", response.status, result?.error?.message || "Erreur audio");
      return failure(res, 502, "Impossible de transcrire cet audio. Réessaie avec un enregistrement plus court.");
    }
    return success(res, { text: result.text || "", usage: result.usage || null });
  } catch (error) {
    console.error("Transcription:", error.message);
    return failure(res, 500, "Erreur pendant la transcription audio.");
  }
});

app.post("/api/audio/speech", authenticate, audioLimiter, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) return failure(res, 503, "Service vocal non configuré.");
    const input = String(req.body.text || "").trim().slice(0, 4000);
    const voice = String(req.body.voice || "alloy").slice(0, 40);
    if (!input) return failure(res, 400, "Aucun texte à lire.");
    const response = await fetch(`${OPENROUTER_URL}/audio/speech`, {
      method: "POST",
      headers: openRouterHeaders(),
      body: JSON.stringify({
        model: OPENROUTER_TTS_MODEL || "openai/gpt-4o-mini-tts-2025-12-15",
        input,
        voice,
        response_format: "mp3"
      })    });
    if (!response.ok) {
      const errorBody = await response.text().catch(() => "");
      console.error("OpenRouter speech:", response.status, errorBody.slice(0, 500));
      return failure(res, 502, "La génération vocale est momentanément indisponible.");
    }
    const audioBuffer = Buffer.from(await response.arrayBuffer());
    res.set({
      "Content-Type": "audio/mpeg",
      "Content-Length": String(audioBuffer.length),
      "Cache-Control": "no-store"
    });
    return res.status(200).send(audioBuffer);
  } catch (error) {
    console.error("Speech:", error.message);
    return failure(res, 500, "Erreur pendant la génération vocale.");
  }
});

/* ========================= MESSAGERIE UTILISATEUR / ADMIN ========================= */
// Les nouveaux échanges sont stockés dans taya_v19_support_messages.
// Les anciens messages taya_v12_contacts restent consultables et ne sont jamais supprimés.
app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();
    if (!message || message.length > 5000) {
      return failure(res, 400, "Message vide ou trop long.");
    }

    const { error } = await supabase.from("taya_v19_support_messages").insert({
      user_id: req.user.id,
      sender_id: req.user.id,
      sender_role: "user",
      message
    });

    if (error) {
      console.error("Contact:", error.message);
      return failure(res, 500, "Impossible d'envoyer le message. Vérifie que la table de messagerie est créée dans Supabase.");
    }

    return success(res, { message: "Message envoyé à Maruce." });
  } catch (error) {
    console.error("Contact:", error.message);
    return failure(res, 500, "Erreur d'envoi.");
  }
});

// Chaque utilisateur ne peut lire que ses propres échanges.
app.get("/api/contact/messages", authenticate, async (req, res) => {
  try {
    const { data: supportMessages, error } = await supabase
      .from("taya_v19_support_messages")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });

    if (error) {
      console.error("User messages:", error.message);
      return failure(res, 500, "Impossible de charger les messages. Vérifie que la table de messagerie est créée dans Supabase.");
    }

    const { data: oldMessages, error: oldError } = await supabase
      .from("taya_v12_contacts")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });

    if (oldError) {
      console.error("Old messages:", oldError.message);
      return failure(res, 500, "Erreur de lecture des anciens messages.");
    }

    const legacy = (oldMessages || []).map(item => ({
      ...item,
      sender_role: "user",
      legacy: true
    }));

    const messages = [...legacy, ...(supportMessages || [])]
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

    return success(res, { messages });
  } catch (error) {
    console.error("User messages:", error.message);
    return failure(res, 500, "Erreur de chargement.");
  }
});

/* ========================= ADMIN ========================= */
app.get("/api/admin/users", authenticate, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from("taya_v13_users")
      .select("id,name,phone,email,created_at,role,must_reset_password")
      .order("created_at", { ascending: false });
    if (error) return failure(res, 500, "Impossible de charger les utilisateurs.");
    return success(res, {
      users: (data || []).map(user => ({ ...user, role: isAdmin(user.phone) ? "admin" : "user" }))
    });
  } catch (error) {
    console.error("Admin users:", error.message);
    return failure(res, 500, "Erreur de chargement des utilisateurs.");
  }
});// L'administration reçoit les anciens messages et les nouveaux échanges complets.
app.get("/api/admin/messages", authenticate, requireAdmin, async (req, res) => {
  try {
    const { data: users, error: usersError } = await supabase
      .from("taya_v13_users")
      .select("id,name,phone");
    if (usersError) return failure(res, 500, "Impossible de charger les utilisateurs.");

    const { data: supportMessages, error } = await supabase
      .from("taya_v19_support_messages")
      .select("*")
      .order("created_at", { ascending: true });
    if (error) {
      console.error("Admin support messages:", error.message);
      return failure(res, 500, "Impossible de charger les nouveaux messages. Vérifie que la table de messagerie est créée dans Supabase.");
    }

    const { data: oldMessages, error: oldError } = await supabase
      .from("taya_v12_contacts")
      .select("*")
      .order("created_at", { ascending: true });
    if (oldError) return failure(res, 500, "Impossible de charger les anciens messages.");

    const userMap = new Map((users || []).map(user => [user.id, user]));
    const legacy = (oldMessages || []).map(item => ({
      ...item,
      sender_role: "user",
      legacy: true
    }));

    const messages = [...legacy, ...(supportMessages || [])]
      .map(item => ({ ...item, user: userMap.get(item.user_id) || null }))
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

    return success(res, { messages });
  } catch (error) {
    console.error("Admin messages:", error.message);
    return failure(res, 500, "Erreur de chargement des messages.");
  }
});

// L'administrateur répond à un utilisateur précis ; la réponse apparaît dans son compte.
app.post("/api/admin/messages/:userId/reply", authenticate, requireAdmin, async (req, res) => {
  try {
    const userId = String(req.params.userId || "");
    const message = String(req.body.message || "").trim();
    if (!message || message.length > 5000) {
      return failure(res, 400, "Réponse vide ou trop longue.");
    }

    const { data: targetUser, error: userError } = await supabase
      .from("taya_v13_users")
      .select("id")
      .eq("id", userId)
      .maybeSingle();
    if (userError || !targetUser) return failure(res, 404, "Utilisateur introuvable.");

    const { data, error } = await supabase
      .from("taya_v19_support_messages")
      .insert({
        user_id: targetUser.id,
        sender_id: req.user.id,
        sender_role: "admin",
        message
      })
      .select("*")
      .single();

    if (error) {
      console.error("Admin reply:", error.message);
      return failure(res, 500, "Impossible d'envoyer la réponse. Vérifie que la table de messagerie est créée dans Supabase.");
    }

    return success(res, { message: "Réponse envoyée.", reply: data });
  } catch (error) {
    console.error("Admin reply:", error.message);
    return failure(res, 500, "Erreur pendant l'envoi.");
  }
});

/* ========================= ERREURS ========================= */
app.use((err, req, res, next) => {
  if (err.message === "Origine non autorisée") return failure(res, 403, "Origine non autorisée.");
  if (err.type === "entity.too.large") return failure(res, 413, "Fichier trop volumineux. Réduis sa taille et réessaie.");
  console.error("Server error:", err.message);
  return failure(res, 500, "Erreur interne du serveur.");
});
app.use((req, res) => failure(res, 404, "Route introuvable."));

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
