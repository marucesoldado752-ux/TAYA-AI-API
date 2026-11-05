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

// ==================================================
// TAYA IA V18.2 — BY MARUCE SOLDADO 🇬🇳
// ==================================================

const app = express();

app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const VERSION = "18.2.0";

const {
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET,
  OPENROUTER_API_KEY,
  OPENROUTER_MODEL = "openai/gpt-4o-mini",
  ALLOWED_ORIGIN
} = process.env;

// ==================================================
// CONFIGURATION SUPABASE
// ==================================================

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

// ==================================================
// CONFIGURATION HTTP
// ==================================================

app.use(helmet({
  crossOriginResourcePolicy: {
    policy: "cross-origin"
  }
}));

const allowedOrigins = (ALLOWED_ORIGIN || "")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (
      !origin &&
      process.env.NODE_ENV !== "production"
    ) {
      return callback(null, true);
    }

    if (origin && allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origine non autorisée"));
  },

  methods: ["GET", "POST", "PUT", "OPTIONS"],

  allowedHeaders: [
    "Content-Type",
    "Authorization"
  ]
}));

app.use(express.json({
  limit: "12mb"
}));

app.use(express.urlencoded({
  extended: true,
  limit: "12mb"
}));

// ==================================================
// LIMITATION DES REQUÊTES
// ==================================================

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 150,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    error: "Trop de tentatives. Réessaie dans quelques minutes."
  }
});

app.use("/api", globalLimiter);

app.use("/api/auth/login", authLimiter);
app.use("/api/auth/register", authLimiter);
app.use("/api/auth/recover", authLimiter);

// ==================================================
// OUTILS
// ==================================================

function normalizePhone(phone) {
  return String(phone || "")
    .replace(/[\s()-]/g, "");
}

function isAdmin(phone) {
  return ADMIN_PHONES.includes(
    normalizePhone(phone)
  );
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
  return crypto
    .randomBytes(16)
    .toString("hex")
    .toUpperCase();
}

function hashRecoveryCode(code) {
  return crypto
    .createHash("sha256")
    .update(String(code).trim().toUpperCase())
    .digest("hex");
}

function checkPasswordInput(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 200
  );
}

// ==================================================
// MOT DE PASSE
// ==================================================

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const derived = await scryptAsync(
    password,
    salt,
    64
  );

  return `scrypt:${salt}:${derived.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  if (
    typeof password !== "string" ||
    typeof stored !== "string" ||
    !stored
  ) {
    return false;
  }

  if (stored.startsWith("scrypt:")) {
    const parts = stored.split(":");

    if (parts.length !== 3) return false;

    const expected = Buffer.from(parts[2], "hex");

    if (expected.length !== 64) return false;

    const derived = await scryptAsync(
      password,
      parts[1],
      64
    );

    return crypto.timingSafeEqual(
      expected,
      derived
    );
  }

  if (/^\$2[aby]\$/.test(stored)) {
    return bcrypt.compare(password, stored);
  }

  // Compatibilité avec les anciens mots de passe
  // en clair déjà enregistrés dans la base.
  return password === stored;
}

// ==================================================
// JWT
// ==================================================

function createToken(user) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error("Configuration JWT invalide");
  }

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

// ==================================================
// VÉRIFICATION DE CONFIGURATION
// ==================================================

function checkDatabase(res) {
  if (!supabase) {
    res.status(503).json({
      success: false,
      error: "Supabase non configuré"
    });

    return false;
  }

  return true;
}

function checkJWT(res) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    res.status(503).json({
      success: false,
      error: "Configuration de sécurité indisponible"
    });

    return false;
  }

  return true;
}

// ==================================================
// AUTHENTIFICATION
// ==================================================

async function authenticate(req, res, next) {
  try {
    if (!checkDatabase(res)) return;
    if (!checkJWT(res)) return;

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

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

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

    // Vérification supplémentaire du numéro
    if (
      normalizePhone(user.phone) !==
      normalizePhone(decoded.phone)
    ) {
      return res.status(401).json({
        success: false,
        error: "Session invalide"
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

// ==================================================
// PROTECTION ADMINISTRATEUR
// ==================================================

function requireAdmin(req, res, next) {
  if (!req.user || !isAdmin(req.user.phone)) {
    return res.status(403).json({
      success: false,
      error: "Accès administrateur refusé"
    });
  }

  next();
}

// ==================================================
// NETTOYAGE DES MESSAGES
// ==================================================

function cleanMessages(messages) {
  if (!Array.isArray(messages)) return [];

  return messages
    .filter(message =>
      message &&
      ["user", "assistant"].includes(message.role) &&
      typeof message.content === "string"
    )
    .slice(-20)
    .map(message => ({
      role: message.role,
      content: message.content.slice(0, 12000)
    }));
}

// ==================================================
// MÉMOIRE
// ==================================================

async function getMemory(userId) {
  const { data, error } = await supabase
    .from("taya_v12_memories")
    .select("memory")
    .eq("user_id", userId)
    .order("updated_at", {
      ascending: false
    })
    .limit(1);

  if (error) throw error;

  return data?.[0]?.memory || "";
}

// ==================================================
// SAUVEGARDE DES MESSAGES
// ==================================================

async function saveMessage(userId, role, message) {
  const { error } = await supabase
    .from("taya_v12_messages")
    .insert({
      user_id: userId,
      role,
      message
    });

  if (error) {
    console.error(
      "Erreur sauvegarde message :",
      error.message
    );
  }
}

// ==================================================
// INTELLIGENCE ARTIFICIELLE
// ==================================================

async function callAI(messages, memory = "") {
  if (!OPENROUTER_API_KEY) {
    throw new Error("IA non configurée");
  }

  const systemPrompt = `
Tu es TAYA IA, un assistant intelligent créé par
Maruce Soldado en Guinée 🇬🇳.

Tu réponds dans la langue utilisée par l'utilisateur.

TES RÈGLES :

- Réponds directement à la question.
- Sois précis, utile et naturel.
- Évite les introductions inutiles.
- Ne répète pas inutilement la question.
- Aide pour les questions générales.
- Aide pour les calculs et traductions.
- Aide pour la programmation.
- Aide pour la rédaction.
- Explique clairement les sujets difficiles.
- Respecte le contexte de la conversation.
- N'invente jamais des informations.
- Si tu ne sais pas, dis-le clairement.
- Adapte la longueur de ta réponse à la demande.

Mémoire utile de l'utilisateur :

${memory || "Aucune mémoire enregistrée."}
`;

  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    60000
  );

  try {
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
            {
              role: "system",
              content: systemPrompt
            },
            ...messages
          ],

          temperature: 0.7,
          max_tokens: 3000
        }),

        signal: controller.signal
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error(
        "Erreur OpenRouter :",
        response.status,
        data?.error?.message || "Erreur inconnue"
      );

      throw new Error("Le service IA rencontre un problème.");
    }

    const answer =
      data?.choices?.[0]?.message?.content;

    if (
      typeof answer !== "string" ||
      !answer.trim()
    ) {
      throw new Error("Réponse IA vide");
    }

    return answer;

  } finally {
    clearTimeout(timeout);
  }
}

// ==================================================
// ROUTES PUBLIQUES
// ==================================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "TAYA IA",
    version: VERSION,
    creator: "Maruce Soldado",
    country: "Guinée 🇬🇳",
    message: "Serveur opérationnel"
  });
});

// ==================================================
// STATUT DU SERVEUR
// ==================================================

app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    version: VERSION,
    server: "online",
    supabase: supabase
      ? "configured"
      : "not_configured",
    ai: OPENROUTER_API_KEY
      ? "configured"
      : "not_configured"
  });
});

// ==================================================
// CONNEXION SANS MOT DE PASSE DÉSACTIVÉE
// ==================================================

app.post("/api/auth/access", (req, res) => {
  return res.status(403).json({
    success: false,
    error: "Connexion sans mot de passe désactivée."
  });
});

// ==================================================
// INSCRIPTION
// ==================================================

app.post("/api/auth/register", async (req, res) => {
  try {
    if (!checkDatabase(res)) return;
    if (!checkJWT(res)) return;

    const name = String(
      req.body.name || req.body.full_name || ""
    ).trim();

    const phone = normalizePhone(req.body.phone);

    const password = String(
      req.body.password || ""
    );

    if (
      name.length < 2 ||
      name.length > 80 ||
      !/^\+[1-9]\d{7,14}$/.test(phone) ||
      !checkPasswordInput(password)
    ) {
      return res.status(400).json({
        success: false,
        error: "Informations invalides. Vérifie ton nom, ton numéro et ton mot de passe."
      });
    }

    const { data: existing, error: searchError } =
      await supabase
        .from("taya_v13_users")
        .select("id")
        .eq("phone", phone)
        .maybeSingle();

    if (searchError) throw searchError;

    if (existing) {
      return res.status(409).json({
        success: false,
        error: "Ce numéro possède déjà un compte. Connecte-toi."
      });
    }

    const passwordHash = await hashPassword(password);

    const recoveryCode = generateRecoveryCode();

    const recoveryHash = hashRecoveryCode(
      recoveryCode
    );

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
      recoveryCode,
      message: "Compte créé avec succès."
    });

  } catch (error) {
    console.error("Register :", error.message);

    return res.status(500).json({
      success: false,
      error: "Impossible de créer le compte."
    });
  }
});

// ==================================================
// CONNEXION
// ==================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    if (!checkDatabase(res)) return;
    if (!checkJWT(res)) return;

    const phone = normalizePhone(req.body.phone);

    const password = String(
      req.body.password || ""
    );

    if (
      !/^\+[1-9]\d{7,14}$/.test(phone) ||
      !password ||
      password.length > 200
    ) {
      return res.status(400).json({
        success: false,
        error: "Informations invalides."
      });
    }

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({
        success: false,
        error: "Numéro ou mot de passe incorrect."
      });
    }

    // Les anciens comptes ordinaires restent protégés.
    // Les administrateurs peuvent se connecter avec
    // leur mot de passe existant.

    if (
      user.must_reset_password &&
      !isAdmin(user.phone)
    ) {
      return res.status(403).json({
        success: false,
        error: "LEGACY_RESET_REQUIRED"
      });
    }

    const storedPassword =
      user.password_hash || user.password;

    const valid = await verifyPassword(
      password,
      storedPassword
    );

    if (!valid) {
      return res.status(401).json({
        success: false,
        error: "Numéro ou mot de passe incorrect."
      });
    }

    // Migration automatique des anciens mots
    // de passe après une connexion réussie.

    if (
      storedPassword &&
      !storedPassword.startsWith("scrypt:")
    ) {
      const newHash = await hashPassword(password);

      const { error: hashError } = await supabase
        .from("taya_v13_users")
        .update({
          password_hash: newHash,
          updated_at: new Date().toISOString()
        })
        .eq("id", user.id);

      if (hashError) throw hashError;
    }

    // Réactivation automatique des administrateurs
    // uniquement après vérification du mot de passe.

    if (
      user.must_reset_password &&
      isAdmin(user.phone)
    ) {
      const { error: updateError } = await supabase
        .from("taya_v13_users")
        .update({
          must_reset_password: false,
          updated_at: new Date().toISOString()
        })
        .eq("id", user.id);

      if (updateError) throw updateError;
    }

    return res.json({
      success: true,
      token: createToken(user),
      user: publicUser(user),
      message: "Connexion réussie."
    });

  } catch (error) {
    console.error("Login :", error.message);

    return res.status(500).json({
      success: false,
      error: "Erreur pendant la connexion."
    });
  }
});

// ==================================================
// RÉACTIVATION NON VÉRIFIÉE DÉSACTIVÉE
// ==================================================

app.post("/api/auth/legacy-reset", (req, res) => {
  return res.status(403).json({
    success: false,
    error: "Réactivation sécurisée nécessaire. Contacte Maruce."
  });
});

// ==================================================
// RÉCUPÉRATION AVEC CODE SECRET
// ==================================================

app.post("/api/auth/recover", async (req, res) => {
  try {
    if (!checkDatabase(res)) return;
    if (!checkJWT(res)) return;

    const phone = normalizePhone(req.body.phone);

    const recoveryCode = String(
      req.body.recoveryCode || ""
    ).trim().toUpperCase();

    const newPassword = String(
      req.body.newPassword || ""
    );

    if (
      !phone ||
      !recoveryCode ||
      !checkPasswordInput(newPassword)
    ) {
      return res.status(400).json({
        success: false,
        error: "Informations invalides."
      });
    }

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (error) throw error;

    const recoveryHash = hashRecoveryCode(
      recoveryCode
    );

    if (
      !user ||
      !user.recovery_code_hash ||
      user.recovery_code_hash !== recoveryHash
    ) {
      return res.status(400).json({
        success: false,
        error: "Code de récupération incorrect."
      });
    }

    const newRecoveryCode = generateRecoveryCode();

    const { data: updated, error: updateError } =
      await supabase
        .from("taya_v13_users")
        .update({
          password_hash: await hashPassword(newPassword),
          recovery_code_hash: hashRecoveryCode(
            newRecoveryCode
          ),
          must_reset_password: false,
          updated_at: new Date().toISOString()
        })
        .eq("id", user.id)
        .select("*")
        .single();

    if (updateError) throw updateError;

    return res.json({
      success: true,
      token: createToken(updated),
      user: publicUser(updated),
      recoveryCode: newRecoveryCode
    });

  } catch (error) {
    console.error("Recover :", error.message);

    return res.status(500).json({
      success: false,
      error: "Erreur de récupération."
    });
  }
});

// ==================================================
// UTILISATEUR CONNECTÉ
// ==================================================

app.get(
  "/api/auth/me",
  authenticate,
  (req, res) => {
    res.json({
      success: true,
      user: publicUser(req.user)
    });
  }
);

// ==================================================
// HISTORIQUE
// ==================================================

app.get(
  "/api/history",
  authenticate,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v12_messages")
        .select("*")
        .eq("user_id", req.user.id)
        .order("created_at", {
          ascending: true
        })
        .limit(500);

      if (error) throw error;

      res.json({
        success: true,
        messages: data || []
      });

    } catch (error) {
      console.error("History :", error.message);

      res.status(500).json({
        success: false,
        error: "Impossible de charger l'historique."
      });
    }
  }
);

// ==================================================
// MÉMOIRE : LECTURE
// ==================================================

app.get(
  "/api/memory",
  authenticate,
  async (req, res) => {
    try {
      const memory = await getMemory(req.user.id);

      res.json({
        success: true,
        memory
      });

    } catch (error) {
      console.error("Memory GET :", error.message);

      res.status(500).json({
        success: false,
        error: "Impossible de charger la mémoire."
      });
    }
  }
);

// ==================================================
// MÉMOIRE : ENREGISTREMENT
// ==================================================

app.put(
  "/api/memory",
  authenticate,
  async (req, res) => {
    try {
      const memory = String(
        req.body.memory || ""
      ).slice(0, 10000);

      const { data: existing, error: searchError } =
        await supabase
          .from("taya_v12_memories")
          .select("user_id")
          .eq("user_id", req.user.id)
          .limit(1);

      if (searchError) throw searchError;

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
      console.error("Memory PUT :", error.message);

      res.status(500).json({
        success: false,
        error: "Impossible d'enregistrer la mémoire."
      });
    }
  }
);

// ==================================================
// DISCUSSION AVEC TAYA IA
// ==================================================

app.post(
  "/api/chat",
  authenticate,
  async (req, res) => {
    try {
      const messages = cleanMessages(
        req.body.messages || []
      );

      if (
        req.body.message &&
        messages.length === 0
      ) {
        messages.push({
          role: "user",
          content: String(
            req.body.message
          ).slice(0, 12000)
        });
      }

      if (!messages.length) {
        return res.status(400).json({
          success: false,
          error: "Écris un message."
        });
      }

      const lastUserMessage = [...messages]
        .reverse()
        .find(message => message.role === "user");

      if (!lastUserMessage) {
        return res.status(400).json({
          success: false,
          error: "Message utilisateur manquant."
        });
      }

      const memory = await getMemory(req.user.id);

      const answer = await callAI(
        messages,
        memory
      );

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

      return res.json({
        success: true,
        reply: answer,
        answer
      });

    } catch (error) {
      console.error("Chat :", error.message);

      return res.status(500).json({
        success: false,
        error: "TAYA IA rencontre un problème. Réessaie."
      });
    }
  }
);

// ==================================================
// CONTACT MARUCE
// ==================================================

app.post(
  "/api/contact",
  authenticate,
  async (req, res) => {
    try {
      const message = String(
        req.body.message || ""
      ).trim();

      if (!message) {
        return res.status(400).json({
          success: false,
          error: "Message vide."
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
        message: "Message envoyé à Maruce."
      });

    } catch (error) {
      console.error("Contact :", error.message);

      res.status(500).json({
        success: false,
        error: "Impossible d'envoyer le message."
      });
    }
  }
);

// ==================================================
// ADMIN : UTILISATEURS
// ==================================================

app.get(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data, error } = await supabase
        .from("taya_v13_users")
        .select("id,name,phone,role,created_at")
        .order("created_at", {
          ascending: false
        })
        .limit(1000);

      if (error) throw error;

      res.json({
        success: true,
        users: data || []
      });

    } catch (error) {
      console.error("Admin users :", error.message);

      res.status(500).json({
        success: false,
        error: "Impossible de charger les utilisateurs."
      });
    }
  }
);

// ==================================================
// ADMIN : MESSAGES REÇUS
// ==================================================

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
        .order("created_at", {
          ascending: false
        })
        .limit(500);

      if (error) throw error;

      res.json({
        success: true,
        messages: data || []
      });

    } catch (error) {
      console.error("Admin messages :", error.message);

      res.status(500).json({
        success: false,
        error: "Impossible de charger les messages."
      });
    }
  }
);

// ==================================================
// ERREURS
// ==================================================

app.use((err, req, res, next) => {
  console.error(
    "Erreur serveur :",
    err.message
  );

  if (res.headersSent) {
    return next(err);
  }

  if (err.message === "Origine non autorisée") {
    return res.status(403).json({
      success: false,
      error: "Origine non autorisée."
    });
  }

  res.status(500).json({
    success: false,
    error: "Erreur interne du serveur."
  });
});

// ==================================================
// DÉMARRAGE
// ==================================================

app.listen(PORT, () => {
  console.log("--------------------------------");
  console.log(`TAYA IA V${VERSION}`);
  console.log(`Serveur démarré sur le port ${PORT}`);
  console.log(
    `Supabase : ${supabase ? "OK" : "NON CONFIGURÉ"}`
  );
  console.log(
    `JWT : ${JWT_SECRET ? "OK" : "NON CONFIGURÉ"}`
  );
  console.log(
    `OpenRouter : ${OPENROUTER_API_KEY ? "OK" : "NON CONFIGURÉ"}`
  );
  console.log("--------------------------------");
});
