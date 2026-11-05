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

// CORRECTION RENDER : reconnaître le proxy
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const VERSION = "17.0.1";

const {
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET,
  OPENROUTER_API_KEY,
  OPENROUTER_MODEL = "openai/gpt-4o-mini",
  ALLOWED_ORIGIN
} = process.env;

const SUPABASE_KEY =
  SUPABASE_SECRET_KEY || SUPABASE_SERVICE_ROLE_KEY;

const supabase =
  SUPABASE_URL && SUPABASE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_KEY, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      })
    : null;

const ADMIN_PHONES = [
  "+224663401157",
  "+224612768878"
];

const scryptAsync = promisify(crypto.scrypt);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

const allowedOrigins = (ALLOWED_ORIGIN || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 ||
        allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origine non autorisée"));
  },
  methods: ["GET", "POST", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "12mb" }));
app.use(express.urlencoded({ extended: true, limit: "12mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.use("/api", limiter);

function normalizePhone(phone) {
  return String(phone || "").replace(/[\s()-]/g, "");
}

function isAdmin(phone) {
  return ADMIN_PHONES.includes(normalizePhone(phone));
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

function generateRecoveryCode() {
  return crypto.randomBytes(5).toString("hex").toUpperCase();
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = await scryptAsync(password, salt, 64);

  return `scrypt:${salt}:${derived.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  if (!stored) return false;

  if (stored.startsWith("scrypt:")) {
    const parts = stored.split(":");
    if (parts.length !== 3) return false;

    const derived = await scryptAsync(password, parts[1], 64);
    const expected = Buffer.from(parts[2], "hex");

    return expected.length === derived.length &&
      crypto.timingSafeEqual(expected, derived);
  }

  // Compatibilité avec les anciens mots de passe bcrypt
  if (/^\$2[aby]\$/.test(stored)) {
    return bcrypt.compare(password, stored);
  }

  // Compatibilité avec les anciens mots de passe en clair
  return password === stored;
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      phone: user.phone
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "Connexion requise"
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("id", decoded.id)
      .single();

    if (error || !user) {
      return res.status(401).json({
        success: false,
        error: "Compte introuvable"
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      error: "Session invalide ou expirée"
    });
  }
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req.user.phone)) {
    return res.status(403).json({
      success: false,
      error: "Accès administrateur refusé"
    });
  }

  next();
}

function cleanMessages(messages) {
  if (!Array.isArray(messages)) return [];

  return messages
    .filter(m =>
      m &&
      ["user", "assistant"].includes(m.role) &&
      typeof m.content === "string"
    )
    .slice(-20)
    .map(m => ({
      role: m.role,
      content: m.content.slice(0, 12000)
    }));
}

async function getMemory(userId) {
  const { data } = await supabase
    .from("taya_v12_memories")
    .select("memory")
    .eq("user_id", userId)
    .order("updated_at", { ascending: false })
    .limit(1);

  return data?.[0]?.memory || "";
}

async function saveMessage(userId, role, message) {
  const { error } = await supabase
    .from("taya_v12_messages")
    .insert({
      user_id: userId,
      role,
      message
    });

  if (error) {
    console.error("Erreur sauvegarde message :", error.message);
  }
}

async function callAI(messages, memory = "") {
  if (!OPENROUTER_API_KEY) {
    throw new Error("Clé OpenRouter non configurée");
  }

  const systemPrompt = `
Tu es TAYA IA, un assistant intelligent créé par Maruce Soldado en Guinée.

Réponds en français lorsque l'utilisateur écrit en français.
Réponds directement à la question.
Sois précis, utile et naturel.
Évite les introductions inutiles.
Aide pour les questions générales, les calculs, la traduction,
la programmation, la rédaction et l'apprentissage.
N'invente pas des informations que tu ne connais pas.

Mémoire utile de l'utilisateur :
${memory || "Aucune mémoire enregistrée."}
`;

  const response = await fetch(
    "https://openrouter.ai/api/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://marucesoldado752-ux.github.io",
        "X-Title": "TAYA IA by Maruce"
      },
      body: JSON.stringify({
        model: OPENROUTER_MODEL,
        messages: [
          { role: "system", content: systemPrompt },
          ...messages
        ],
        temperature: 0.7,
        max_tokens: 3000
      })
    }
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("OpenRouter :", data);
    throw new Error(
      data?.error?.message || "Erreur du service IA"
    );
  }

  const answer = data?.choices?.[0]?.message?.content;

  if (!answer) {
    throw new Error("Réponse IA vide");
  }

  return answer;
}

// --------------------------------------------------
// ROUTES PUBLIQUES
// --------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "TAYA IA",
    version: VERSION,
    message: "Serveur opérationnel"
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    version: "17.0.1",
    server: "online",
    supabase: supabase ? "configured" : "not_configured",
    ai: OPENROUTER_API_KEY ? "configured" : "not_configured"
  });
});

// --------------------------------------------------
// INSCRIPTION
// --------------------------------------------------

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(
      req.body.name || req.body.full_name || ""
    ).trim();

    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!name || !phone || password.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Nom, téléphone et mot de passe de 6 caractères minimum requis"
      });
    }

    const { data: existing } = await supabase
      .from("taya_v13_users")
      .select("id")
      .eq("phone", phone)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({
        success: false,
        error: "Ce numéro possède déjà un compte"
      });
    }

    const passwordHash = await hashPassword(password);
    const recoveryCode = generateRecoveryCode();
    const recoveryHash = crypto
      .createHash("sha256")
      .update(recoveryCode)
      .digest("hex");

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .insert({
        name,
        phone,
        password_hash: passwordHash,
        recovery_code_hash: recoveryHash,
        role: isAdmin(phone) ? "admin" : "user",
        must_reset_password: false,
        updated_at: new Date().toISOString()
      })
      .select("*")
      .single();

    if (error) throw error;

    return res.status(201).json({
      success: true,
      token: createToken(user),
      user: publicUser(user),
      recoveryCode
    });

  } catch (error) {
    console.error("Register :", error);

    res.status(500).json({
      success: false,
      error: "Impossible de créer le compte"
    });
  }
});

// --------------------------------------------------
// CONNEXION
// --------------------------------------------------

app.post("/api/auth/login", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({
        success: false,
        error: "Numéro ou mot de passe incorrect"
      });
    }

    if (user.must_reset_password) {
      return res.status(403).json({
        success: false,
        error: "LEGACY_RESET_REQUIRED"
      });
    }

    const storedPassword = user.password_hash || user.password;
    const valid = await verifyPassword(password, storedPassword);

    if (!valid) {
      return res.status(401).json({
        success: false,
        error: "Numéro ou mot de passe incorrect"
      });
    }

    // Met à jour les anciens mots de passe après connexion
    if (storedPassword && !storedPassword.startsWith("scrypt:")) {
      const newHash = await hashPassword(password);

      await supabase
        .from("taya_v13_users")
        .update({
          password_hash: newHash,
          updated_at: new Date().toISOString()
        })
        .eq("id", user.id);
    }

    res.json({
      success: true,
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("Login :", error);

    res.status(500).json({
      success: false,
      error: "Erreur pendant la connexion"
    });
  }
});

// --------------------------------------------------
// RÉACTIVATION DES ANCIENS COMPTES
// --------------------------------------------------

app.post("/api/auth/legacy-reset", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const name = String(
      req.body.name || req.body.full_name || ""
    ).trim();
    const password = String(req.body.password || "");

    if (!phone || !name || password.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Informations invalides"
      });
    }

    const { data: user } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (!user || user.name !== name || !user.must_reset_password) {
      return res.status(400).json({
        success: false,
        error: "Informations de réactivation incorrectes"
      });
    }

    const recoveryCode = generateRecoveryCode();
    const recoveryHash = crypto
      .createHash("sha256")
      .update(recoveryCode)
      .digest("hex");

    const { data: updated, error } = await supabase
      .from("taya_v13_users")
      .update({
        password_hash: await hashPassword(password),
        recovery_code_hash: recoveryHash,
        must_reset_password: false,
        updated_at: new Date().toISOString()
      })
      .eq("id", user.id)
      .select("*")
      .single();

    if (error) throw error;

    res.json({
      success: true,
      token: createToken(updated),
      user: publicUser(updated),
      recoveryCode
    });

  } catch (error) {
    console.error("Legacy reset :", error);

    res.status(500).json({
      success: false,
      error: "Impossible de réactiver ce compte"
    });
  }
});

// --------------------------------------------------
// RÉCUPÉRATION DU MOT DE PASSE
// --------------------------------------------------

app.post("/api/auth/recover", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const recoveryCode = String(req.body.recoveryCode || "")
      .trim()
      .toUpperCase();
    const newPassword = String(req.body.newPassword || "");

    if (!phone || !recoveryCode || newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        error: "Informations invalides"
      });
    }

    const { data: user } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    const recoveryHash = crypto
      .createHash("sha256")
      .update(recoveryCode)
      .digest("hex");

    if (!user || !user.recovery_code_hash ||
        user.recovery_code_hash !== recoveryHash) {
      return res.status(400).json({
        success: false,
        error: "Code de récupération incorrect"
      });
    }

    const { data: updated, error } = await supabase
      .from("taya_v13_users")
      .update({
        password_hash: await hashPassword(newPassword),
        updated_at: new Date().toISOString()
      })
      .eq("id", user.id)
      .select("*")
      .single();

    if (error) throw error;

    res.json({
      success: true,
      token: createToken(updated),
      user: publicUser(updated)
    });

  } catch (error) {
    console.error("Recover :", error);

    res.status(500).json({
      success: false,
      error: "Erreur de récupération"
    });
  }
});

// --------------------------------------------------
// UTILISATEUR CONNECTÉ
// --------------------------------------------------

app.get("/api/auth/me", authenticate, (req, res) => {
  res.json({
    success: true,
    user: publicUser(req.user)
  });
});

// --------------------------------------------------
// HISTORIQUE
// --------------------------------------------------

app.get("/api/history", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_v12_messages")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true })
      .limit(500);

    if (error) throw error;

    res.json({
      success: true,
      messages: data || []
    });

  } catch (error) {
    console.error("History :", error);

    res.status(500).json({
      success: false,
      error: "Impossible de charger l'historique"
    });
  }
});

// --------------------------------------------------
// MÉMOIRE
// --------------------------------------------------

app.get("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = await getMemory(req.user.id);

    res.json({
      success: true,
      memory
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Impossible de charger la mémoire"
    });
  }
});

app.put("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = String(req.body.memory || "").slice(0, 10000);

    const { data: existing } = await supabase
      .from("taya_v12_memories")
      .select("user_id")
      .eq("user_id", req.user.id)
      .limit(1);

    let result;

    if (existing && existing.length) {
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

    if (result.error) throw result.error;

    res.json({
      success: true,
      memory
    });

  } catch (error) {
    console.error("Memory :", error);

    res.status(500).json({
      success: false,
      error: "Impossible d'enregistrer la mémoire"
    });
  }
});

// --------------------------------------------------
// DISCUSSION AVEC TAYA IA
// --------------------------------------------------

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    const messages = cleanMessages(
      req.body.messages || []
    );

    if (req.body.message && messages.length === 0) {
      messages.push({
        role: "user",
        content: String(req.body.message).slice(0, 12000)
      });
    }

    if (!messages.length) {
      return res.status(400).json({
        success: false,
        error: "Écris un message"
      });
    }

    const lastUserMessage = [...messages]
      .reverse()
      .find(m => m.role === "user");

    if (!lastUserMessage) {
      return res.status(400).json({
        success: false,
        error: "Message utilisateur manquant"
      });
    }

    const memory = await getMemory(req.user.id);
    const answer = await callAI(messages, memory);

    await saveMessage(
      req.user.id,
      "user",
      lastUserMessage.content
    );

    await saveMessage(
      req.user.id,
      "assistant",
      answer
    );

    res.json({
      success: true,
      reply: answer,
      answer
    });

  } catch (error) {
    console.error("Chat :", error);

    res.status(500).json({
      success: false,
      error: error.message || "Erreur pendant la réponse de TAYA"
    });
  }
});

// --------------------------------------------------
// CONTACT MARUCE
// --------------------------------------------------

app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message) {
      return res.status(400).json({
        success: false,
        error: "Message vide"
      });
    }

    const { error } = await supabase
      .from("taya_v12_contacts")
      .insert({
        user_id: req.user.id,
        message: message.slice(0, 5000)
      });

    if (error) throw error;

    res.json({
      success: true,
      message: "Message envoyé à Maruce"
    });

  } catch (error) {
    console.error("Contact :", error);

    res.status(500).json({
      success: false,
      error: "Impossible d'envoyer le message"
    });
  }
});

// --------------------------------------------------
// ADMIN : UTILISATEURS
// --------------------------------------------------

app.get(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v13_users")
        .select("id,name,phone,role,created_at")
        .order("created_at", { ascending: false })
        .limit(1000);

      if (error) throw error;

      res.json({
        success: true,
        users: data || []
      });

    } catch (error) {
      console.error("Admin users :", error);

      res.status(500).json({
        success: false,
        error: "Impossible de charger les utilisateurs"
      });
    }
  }
);

// --------------------------------------------------
// ADMIN : MESSAGES REÇUS
// --------------------------------------------------

app.get(
  "/api/admin/messages",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v12_contacts")
        .select(`
          id,
          user_id,
          message,
          created_at
        `)
        .order("created_at", { ascending: false })
        .limit(500);

      if (error) throw error;

      res.json({
        success: true,
        messages: data || []
      });

    } catch (error) {
      console.error("Admin messages :", error);

      res.status(500).json({
        success: false,
        error: "Impossible de charger les messages"
      });
    }
  }
);

// --------------------------------------------------
// ERREURS
// --------------------------------------------------

app.use((err, req, res, next) => {
  console.error("Erreur serveur :", err.message);

  if (res.headersSent) return next(err);

  res.status(500).json({
    success: false,
    error: "Erreur interne du serveur"
  });
});

// --------------------------------------------------
// DÉMARRAGE
// --------------------------------------------------

app.listen(PORT, () => {
  console.log("--------------------------------");
  console.log(`TAYA IA V${VERSION}`);
  console.log(`Serveur démarré sur le port ${PORT}`);
  console.log(`Supabase : ${supabase ? "OK" : "NON CONFIGURÉ"}`);
  console.log(`JWT : ${JWT_SECRET ? "OK" : "NON CONFIGURÉ"}`);
  console.log(`OpenRouter : ${OPENROUTER_API_KEY ? "OK" : "NON CONFIGURÉ"}`);
  console.log("--------------------------------");
});
