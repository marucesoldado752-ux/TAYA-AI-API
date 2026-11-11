"use strict";

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

const VERSION = "22.0.0";
const PORT = process.env.PORT || 3000;

const {
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET,
  OPENROUTER_API_KEY,
  OPENROUTER_MODEL,
  TAVILY_API_KEY
} = process.env;

const SUPABASE_KEY =
  SUPABASE_SECRET_KEY || SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY || !JWT_SECRET) {
  console.error("Configuration Supabase ou JWT manquante");
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

app.use(helmet());

app.use(cors({
  origin: function (origin, callback) {
    const allowed = [
      "https://marucesoldado752-ux.github.io",
      "https://marucesoldado752-ux.github.io/Ovl-",
      process.env.ALLOWED_ORIGIN
    ].filter(Boolean);

    if (!origin || allowed.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origine non autorisée"));
  },
  credentials: true
}));

app.use(express.json({ limit: "15mb" }));

app.use(express.urlencoded({
  extended: true,
  limit: "15mb"
}));

app.use("/api", rateLimit({
  windowMs: 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false
}));

const scryptAsync = promisify(crypto.scrypt);

function success(res, data = {}) {
  return res.json({
    success: true,
    version: VERSION,
    ...data
  });
}

function failure(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message,
    version: VERSION
  });
}

function normalizePhone(phone) {
  return String(phone || "").replace(/[^\d+]/g, "");
}

function phoneVariants(phone) {
  const p = normalizePhone(phone);
  const digits = p.replace(/\D/g, "");

  const variants = new Set([p, digits]);

  if (digits.startsWith("224")) {
    variants.add("+" + digits);
    variants.add(digits.slice(3));
  } else if (digits.length === 9) {
    variants.add("224" + digits);
    variants.add("+224" + digits);
  }

  return [...variants];
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    email: user.email || null,
    avatar_url: user.avatar_url || null,
    role: user.role || "user",
    created_at: user.created_at,
    must_reset_password: !!user.must_reset_password,
    last_seen_at: user.last_seen_at || null
  };
}

function createToken(user) {
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

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const derived = await scryptAsync(
    password,
    salt,
    64
  );

  return "scrypt:" + salt + ":" + derived.toString("hex");
}

async function verifyPassword(password, stored) {
  if (!stored) return false;

  if (stored.startsWith("scrypt:")) {
    const parts = stored.split(":");

    if (parts.length !== 3) return false;

    const salt = parts[1];
    const original = Buffer.from(parts[2], "hex");

    const derived = await scryptAsync(
      password,
      salt,
      original.length
    );

    return original.length === derived.length &&
      crypto.timingSafeEqual(original, derived);
  }

  if (stored.startsWith("$2")) {
    return bcrypt.compare(password, stored);
  }

  // Compatibilité avec les anciens mots de passe
  return password === stored;
}

function hashRecoveryCode(code) {
  return crypto
    .createHash("sha256")
    .update(String(code).trim())
    .digest("hex");
}

async function getUserById(id) {
  const { data, error } = await supabase
    .from("taya_v13_users")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) throw error;

  return data;
}

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : null;

    if (!token) {
      return failure(res, 401, "Connexion nécessaire");
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await getUserById(decoded.id);

    if (!user) {
      return failure(res, 401, "Compte introuvable");
    }

    req.user = user;
    next();

  } catch (error) {
    return failure(res, 401, "Session invalide ou expirée");
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return failure(res, 403, "Accès administrateur refusé");
  }

  next();
}

async function openRouter(messages, options = {}) {
  if (!OPENROUTER_API_KEY) {
    throw new Error("OPENROUTER_API_KEY manquante");
  }

  const response = await fetch(
    "https://openrouter.ai/api/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://marucesoldado752-ux.github.io",
        "X-Title": "TAYA IA"
      },
      body: JSON.stringify({
        model:
          OPENROUTER_MODEL ||
          "openai/gpt-4o-mini",
        messages,
        max_tokens: options.max_tokens || 4000,
        temperature: 0.7
      })
    }
  );

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      result.error?.message || "Erreur du service IA"
    );
  }

  return result.choices?.[0]?.message?.content || "";
}

app.get("/", (req, res) => {
  success(res, {
    application: "TAYA IA",
    creator: "MARUCE SOLDADO",
    server: "online"
  });
});

app.get("/health", async (req, res) => {
  let database = "unknown";

  try {
    const { error } = await supabase
      .from("taya_v13_users")
      .select("id")
      .limit(1);

    database = error ? "error" : "connected";
  } catch {
    database = "error";
  }

  success(res, {
    server: "online",
    supabase: database,
    ai: OPENROUTER_API_KEY ? "configured" : "missing",
    web_search: TAVILY_API_KEY ? "configured" : "missing"
  });
});// ==========================================
// TAYA IA V22 — AUTHENTIFICATION
// ==========================================

app.post("/api/register", async (req, res) => {
  try {
    const { name, phone, password, email } = req.body;

    if (!name || !phone || !password) {
      return failure(res, 400, "Informations obligatoires manquantes");
    }

    if (String(password).length < 6) {
      return failure(res, 400, "Mot de passe trop court");
    }

    const normalizedPhone = normalizePhone(phone);

    if (normalizedPhone.length < 8) {
      return failure(res, 400, "Numéro de téléphone invalide");
    }

    const variants = phoneVariants(normalizedPhone);

    const { data: existing, error: searchError } = await supabase
      .from("taya_v13_users")
      .select("id,phone")
      .in("phone", variants)
      .limit(1);

    if (searchError) throw searchError;

    if (existing && existing.length) {
      return failure(res, 409, "Ce numéro possède déjà un compte");
    }

    const passwordHash = await hashPassword(password);

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .insert({
        name: String(name).trim(),
        phone: normalizedPhone,
        email: email || null,
        password_hash: passwordHash,
        password: null,
        role: "user",
        must_reset_password: false
      })
      .select("*")
      .single();

    if (error) throw error;

    return success(res, {
      message: "Compte créé avec succès",
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("REGISTER:", error.message);
    return failure(res, 500, "Impossible de créer le compte");
  }
});


// ==========================================
// CONNEXION
// ==========================================

app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return failure(res, 400, "Numéro et mot de passe obligatoires");
    }

    const variants = phoneVariants(phone);

    const { data: users, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .in("phone", variants)
      .limit(1);

    if (error) throw error;

    const user = users?.[0];

    if (!user) {
      return failure(res, 401, "Numéro ou mot de passe incorrect");
    }

    const storedPassword = user.password_hash || user.password;

    const valid = await verifyPassword(
      String(password),
      storedPassword
    );

    if (!valid) {
      return failure(res, 401, "Numéro ou mot de passe incorrect");
    }

    if (user.must_reset_password) {
      return failure(
        res,
        403,
        "Réinitialisation du mot de passe obligatoire"
      );
    }

    // Migration automatique des anciens mots de passe
    if (
      !user.password_hash ||
      !user.password_hash.startsWith("scrypt:")
    ) {
      const newHash = await hashPassword(String(password));

      const { error: updateError } = await supabase
        .from("taya_v13_users")
        .update({
          password_hash: newHash,
          password: null,
          updated_at: new Date().toISOString()
        })
        .eq("id", user.id);

      if (updateError) throw updateError;

      user.password_hash = newHash;
    }

    await supabase
      .from("taya_v13_users")
      .update({
        last_seen_at: new Date().toISOString()
      })
      .eq("id", user.id);

    return success(res, {
      message: "Connexion réussie",
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("LOGIN:", error.message);
    return failure(res, 500, "Erreur pendant la connexion");
  }
});


// ==========================================
// PROFIL
// ==========================================

app.get("/api/me", authenticate, (req, res) => {
  return success(res, {
    user: publicUser(req.user)
  });
});

app.get("/api/profile", authenticate, (req, res) => {
  return success(res, {
    user: publicUser(req.user)
  });
});

app.put("/api/profile/name", authenticate, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();

    if (name.length < 2 || name.length > 80) {
      return failure(res, 400, "Nom invalide");
    }

    const { data, error } = await supabase
      .from("taya_v13_users")
      .update({
        name,
        updated_at: new Date().toISOString()
      })
      .eq("id", req.user.id)
      .select("*")
      .single();

    if (error) throw error;

    return success(res, {
      user: publicUser(data)
    });

  } catch (error) {
    console.error("PROFILE:", error.message);
    return failure(res, 500, "Impossible de modifier le profil");
  }
});


// ==========================================
// RÉCUPÉRATION DU COMPTE
// ==========================================

app.post("/api/recover", async (req, res) => {
  try {
    const { phone, recoveryCode, newPassword } = req.body;

    if (!phone || !recoveryCode || !newPassword) {
      return failure(res, 400, "Informations manquantes");
    }

    if (String(newPassword).length < 6) {
      return failure(res, 400, "Mot de passe trop court");
    }

    const variants = phoneVariants(phone);

    const { data: users, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .in("phone", variants)
      .limit(1);

    if (error) throw error;

    const user = users?.[0];

    if (!user || !user.recovery_code_hash) {
      return failure(res, 400, "Code de récupération incorrect");
    }

    const submittedHash = hashRecoveryCode(recoveryCode);

    const valid =
      submittedHash.length === user.recovery_code_hash.length &&
      crypto.timingSafeEqual(
        Buffer.from(submittedHash),
        Buffer.from(user.recovery_code_hash)
      );

    if (!valid) {
      return failure(res, 400, "Code de récupération incorrect");
    }

    const newHash = await hashPassword(String(newPassword));

    const { error: updateError } = await supabase
      .from("taya_v13_users")
      .update({
        password_hash: newHash,
        password: null,
        must_reset_password: false,
        recovery_code_hash: null,
        updated_at: new Date().toISOString()
      })
      .eq("id", user.id);

    if (updateError) throw updateError;

    return success(res, {
      message: "Mot de passe réinitialisé"
    });

  } catch (error) {
    console.error("RECOVER:", error.message);
    return failure(res, 500, "Erreur de récupération");
  }
});


// ==========================================
// HISTORIQUE DES CONVERSATIONS
// TABLE : taya_v12_messages
// COLONNES : user_id, role, message
// ==========================================

app.get("/api/history", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_v12_messages")
      .select("id,user_id,role,message,created_at")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true })
      .limit(500);

    if (error) throw error;

    return success(res, {
      messages: data || [],
      history: data || []
    });

  } catch (error) {
    console.error("HISTORY:", error.message);
    return failure(res, 500, "Impossible de charger l'historique");
  }
});

async function saveMessage(userId, role, message) {
  const { error } = await supabase
    .from("taya_v12_messages")
    .insert({
      user_id: userId,
      role,
      message
    });

  if (error) throw error;
}


// ==========================================
// MÉMOIRE PERSONNELLE
// TABLE : taya_v12_memories
// COLONNES : user_id, memory, updated_at
// ==========================================

app.get("/api/memory", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_v12_memories")
      .select("user_id,memory,updated_at")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) throw error;

    return success(res, {
      memory: data?.memory || ""
    });

  } catch (error) {
    console.error("MEMORY GET:", error.message);
    return failure(res, 500, "Impossible de charger la mémoire");
  }
});

app.put("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = String(req.body.memory || "").slice(0, 20000);

    const { data: existing, error: searchError } = await supabase
      .from("taya_v12_memories")
      .select("user_id")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (searchError) throw searchError;

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
          memory
        });
    }

    if (result.error) throw result.error;

    return success(res, {
      message: "Mémoire enregistrée",
      memory
    });

  } catch (error) {
    console.error("MEMORY PUT:", error.message);
    return failure(res, 500, "Impossible d'enregistrer la mémoire");
  }
});


// ==========================================
// CONTEXTE POUR L'IA
// ==========================================

async function getUserMemory(userId) {
  const { data, error } = await supabase
    .from("taya_v12_memories")
    .select("memory")
    .eq("user_id", userId)
    .maybeSingle();

  if (error) throw error;

  return data?.memory || "";
}

async function getRecentHistory(userId) {
  const { data, error } = await supabase
    .from("taya_v12_messages")
    .select("role,message,created_at")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
    .limit(20);

  if (error) throw error;

  return (data || [])
    .reverse()
    .map(item => ({
      role: item.role,
      content: item.message
    }));
}


// ==========================================
// RECHERCHE INTERNET TAVILY
// ==========================================

async function webSearch(query) {
  if (!TAVILY_API_KEY) {
    return "La recherche web n'est pas configurée.";
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

  const result = await response.json();

  if (!response.ok) {
    throw new Error("Erreur de recherche web");
  }

  return JSON.stringify({
    answer: result.answer || "",
    results: (result.results || []).map(item => ({
      title: item.title,
      url: item.url,
      content: item.content
    }))
  });
}


// ==========================================
// CHAT TAYA IA
// ==========================================

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    const userMessage = String(req.body.message || "").trim();

    if (!userMessage) {
      return failure(res, 400, "Message vide");
    }

    if (userMessage.length > 20000) {
      return failure(res, 400, "Message trop long");
    }

    const memory = await getUserMemory(req.user.id);
    const history = await getRecentHistory(req.user.id);

    let searchContext = "";

    if (req.body.web_search === true) {
      searchContext = await webSearch(userMessage);
    }

    const systemPrompt = `
Tu es TAYA IA V22.0.0 🤖🇬🇳.

Tu as été créée par MARUCE SOLDADO en Guinée.

Tu es une intelligence artificielle utile, rapide,
précise, polie et capable d'aider les utilisateurs
dans leurs études, leur travail, la programmation,
la rédaction, les traductions et les recherches.

Réponds directement à la question.
Évite les introductions inutiles.
Utilise la langue de l'utilisateur.

Mémoire de l'utilisateur :
${memory}

Informations de recherche :
${searchContext}
`;

    const messages = [
      {
        role: "system",
        content: systemPrompt
      },
      ...history,
      {
        role: "user",
        content: userMessage
      }
    ];

    const answer = await openRouter(messages);

    await saveMessage(
      req.user.id,
      "user",
      userMessage
    );

    await saveMessage(
      req.user.id,
      "assistant",
      answer
    );

    return success(res, {
      answer,
      message: answer,
      model: OPENROUTER_MODEL || "openai/gpt-4o-mini"
    });

  } catch (error) {
    console.error("CHAT:", error.message);
    return failure(res, 500, "TAYA IA n'a pas pu répondre");
  }
});// ==========================================
// ANALYSE D'IMAGES
// ==========================================

app.post("/api/chat/image", authenticate, async (req, res) => {
  try {
    const { image, message } = req.body;

    if (!image) {
      return failure(res, 400, "Image manquante");
    }

    if (!OPENROUTER_API_KEY) {
      return failure(res, 503, "Service IA non configuré");
    }

    const prompt = String(message || "Décris et analyse cette image.");

    const answer = await openRouter([
      {
        role: "system",
        content: "Tu es TAYA IA. Analyse précisément les images et réponds en français si l'utilisateur écrit en français."
      },
      {
        role: "user",
        content: [
          {
            type: "text",
            text: prompt
          },
          {
            type: "image_url",
            image_url: {
              url: image
            }
          }
        ]
      }
    ]);

    await saveMessage(
      req.user.id,
      "user",
      prompt + " [Image jointe]"
    );

    await saveMessage(
      req.user.id,
      "assistant",
      answer
    );

    return success(res, {
      answer,
      message: answer
    });

  } catch (error) {
    console.error("IMAGE:", error.message);
    return failure(res, 500, "Impossible d'analyser cette image");
  }
});


// ==========================================
// LECTURE DES DOCUMENTS PDF
// Nécessite pdf-parse ^1.1.1
// ==========================================

app.post("/api/chat/pdf", authenticate, async (req, res) => {
  try {
    const { file, message } = req.body;

    if (!file) {
      return failure(res, 400, "Document PDF manquant");
    }

    const base64 = String(file).replace(
      /^data:application\/pdf;base64,/,
      ""
    );

    const buffer = Buffer.from(base64, "base64");

    if (!buffer.length || buffer.length > 10 * 1024 * 1024) {
      return failure(res, 400, "Document vide ou trop volumineux");
    }

    const pdfParse = require("pdf-parse");
    const parsed = await pdfParse(buffer);

    const documentText = String(parsed.text || "").slice(0, 30000);

    if (!documentText.trim()) {
      return failure(res, 400, "Aucun texte lisible dans ce PDF");
    }

    const question = String(
      message || "Résume et explique ce document."
    );

    const answer = await openRouter([
      {
        role: "system",
        content: "Tu es TAYA IA. Tu dois comprendre les documents, les résumer et répondre précisément aux questions."
      },
      {
        role: "user",
        content:
          question +
          "\n\nCONTENU DU DOCUMENT :\n" +
          documentText
      }
    ]);

    await saveMessage(
      req.user.id,
      "user",
      question + " [Document PDF]"
    );

    await saveMessage(
      req.user.id,
      "assistant",
      answer
    );

    return success(res, {
      answer,
      message: answer,
      pages: parsed.numpages
    });

  } catch (error) {
    console.error("PDF:", error.message);
    return failure(res, 500, "Impossible de lire ce document PDF");
  }
});


// ==========================================
// CONTACTER MARUCE / SUPPORT
// TABLE : taya_v19_support_messages
// ==========================================

app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message) {
      return failure(res, 400, "Message vide");
    }

    if (message.length > 5000) {
      return failure(res, 400, "Message trop long");
    }

    const { data, error } = await supabase
      .from("taya_v19_support_messages")
      .insert({
        user_id: req.user.id,
        sender_id: req.user.id,
        sender_role: "user",
        message
      })
      .select("id,user_id,sender_id,sender_role,message,created_at,read_at")
      .single();

    if (error) throw error;

    return success(res, {
      message: "Message envoyé à Maruce",
      data
    });

  } catch (error) {
    console.error("CONTACT:", error.message);
    return failure(res, 500, "Impossible d'envoyer le message");
  }
});


// ==========================================
// HISTORIQUE DU SUPPORT UTILISATEUR
// ==========================================

app.get("/api/contact/messages", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_v19_support_messages")
      .select("id,user_id,sender_id,sender_role,message,created_at,read_at")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true })
      .limit(200);

    if (error) throw error;

    return success(res, {
      messages: data || []
    });

  } catch (error) {
    console.error("SUPPORT HISTORY:", error.message);
    return failure(res, 500, "Impossible de charger les messages");
  }
});


// ==========================================
// ADMIN : LISTE DES UTILISATEURS
// ==========================================

app.get(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v13_users")
        .select(
          "id,name,phone,email,avatar_url,role,created_at,last_seen_at,must_reset_password"
        )
        .order("created_at", { ascending: false })
        .limit(1000);

      if (error) throw error;

      return success(res, {
        users: data || [],
        total: (data || []).length
      });

    } catch (error) {
      console.error("ADMIN USERS:", error.message);
      return failure(res, 500, "Impossible de charger les utilisateurs");
    }
  }
);


// ==========================================
// ADMIN : MESSAGES DE SUPPORT
// ==========================================

app.get(
  "/api/admin/messages",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v19_support_messages")
        .select("id,user_id,sender_id,sender_role,message,created_at,read_at")
        .order("created_at", { ascending: false })
        .limit(500);

      if (error) throw error;

      return success(res, {
        messages: data || []
      });

    } catch (error) {
      console.error("ADMIN MESSAGES:", error.message);
      return failure(res, 500, "Impossible de charger les messages");
    }
  }
);


// ==========================================
// ADMIN : RÉPONDRE À UN UTILISATEUR
// ==========================================

app.post(
  "/api/admin/messages/:userId/reply",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const userId = req.params.userId;
      const message = String(req.body.message || "").trim();

      if (!message) {
        return failure(res, 400, "Réponse vide");
      }

      if (message.length > 5000) {
        return failure(res, 400, "Réponse trop longue");
      }

      const target = await getUserById(userId);

      if (!target) {
        return failure(res, 404, "Utilisateur introuvable");
      }

      const { data, error } = await supabase
        .from("taya_v19_support_messages")
        .insert({
          user_id: userId,
          sender_id: req.user.id,
          sender_role: "admin",
          message
        })
        .select("id,user_id,sender_id,sender_role,message,created_at,read_at")
        .single();

      if (error) throw error;

      return success(res, {
        message: "Réponse envoyée",
        data
      });

    } catch (error) {
      console.error("ADMIN REPLY:", error.message);
      return failure(res, 500, "Impossible d'envoyer la réponse");
    }
  }
);


// ==========================================
// ADMIN : MARQUER UN MESSAGE COMME LU
// ==========================================

app.patch(
  "/api/admin/messages/:id/read",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v19_support_messages")
        .update({
          read_at: new Date().toISOString()
        })
        .eq("id", req.params.id)
        .select("id,read_at")
        .single();

      if (error) throw error;

      return success(res, {
        message: "Message marqué comme lu",
        data
      });

    } catch (error) {
      console.error("ADMIN READ:", error.message);
      return failure(res, 500, "Impossible de modifier le message");
    }
  }
);


// ==========================================
// PRÉSENCE DES UTILISATEURS
// ==========================================

app.post("/api/presence/heartbeat", authenticate, async (req, res) => {
  try {
    const { error } = await supabase
      .from("taya_v13_users")
      .update({
        last_seen_at: new Date().toISOString()
      })
      .eq("id", req.user.id);

    if (error) throw error;

    return success(res, {
      message: "Présence actualisée"
    });

  } catch (error) {
    console.error("PRESENCE:", error.message);
    return failure(res, 500, "Impossible d'actualiser la présence");
  }
});


// ==========================================
// ADMIN : PRÉSENCE
// ==========================================

app.get(
  "/api/admin/presence",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v13_users")
        .select("id,name,phone,role,last_seen_at")
        .order("last_seen_at", { ascending: false })
        .limit(1000);

      if (error) throw error;

      return success(res, {
        users: data || []
      });

    } catch (error) {
      console.error("ADMIN PRESENCE:", error.message);
      return failure(res, 500, "Impossible de charger les présences");
    }
  }
);


// ==========================================
// ROUTE INCONNUE
// ==========================================

app.use((req, res) => {
  return failure(res, 404, "Route introuvable");
});


// ==========================================
// GESTION DES ERREURS
// ==========================================

app.use((err, req, res, next) => {
  console.error("SERVER ERROR:", err.message);

  if (res.headersSent) {
    return next(err);
  }

  return failure(
    res,
    500,
    "Une erreur interne est survenue"
  );
});


// ==========================================
// DÉMARRAGE
// ==========================================

app.listen(PORT, () => {
  console.log("--------------------------------");
  console.log("TAYA IA V22.0.0");
  console.log("Créateur : MARUCE SOLDADO");
  console.log("Serveur : ONLINE");
  console.log("Port :", PORT);
  console.log("--------------------------------");
});
