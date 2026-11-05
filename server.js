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
const VERSION = "18.2.0";

const {
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET,
  OPENROUTER_API_KEY,
  OPENROUTER_MODEL
} = process.env;

const SUPABASE_KEY =
  SUPABASE_SECRET_KEY || SUPABASE_SERVICE_ROLE_KEY;

const FRONTEND_ORIGINS = (
  process.env.ALLOWED_ORIGIN ||
  "https://marucesoldado752-ux.github.io"
)
  .split(",")
  .map(origin => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("Configuration Supabase manquante.");
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET manquant.");
}

const supabase =
  SUPABASE_URL && SUPABASE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_KEY, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      })
    : null;

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" }
  })
);

/* =========================
   CORS CORRIGÉ
========================= */

app.use(
  cors({
    origin(origin, callback) {
      // Autorise les requêtes sans en-tête Origin,
      // notamment l'ouverture directe de /api/status.
      if (!origin) {
        return callback(null, true);
      }

      const normalizedOrigin = origin.replace(/\/$/, "");

      if (FRONTEND_ORIGINS.includes(normalizedOrigin)) {
        return callback(null, true);
      }

      return callback(new Error("Origine non autorisée"));
    },
    methods: ["GET", "POST", "PUT", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use("/api/", limiter);

/* =========================
   OUTILS
========================= */

function success(res, data = {}) {
  return res.json({
    success: true,
    ...data
  });
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
  const normalized = normalizePhone(phone);

  return [
    "+224663401157",
    "+224612768878"
  ].includes(normalized);
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
  return jwt.sign(
    {
      id: user.id,
      phone: user.phone
    },
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

/* =========================
   MOT DE PASSE
========================= */

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

  // Ancien format bcrypt
  if (
    stored.startsWith("$2a$") ||
    stored.startsWith("$2b$") ||
    stored.startsWith("$2y$")
  ) {
    return bcrypt.compare(password, stored);
  }

  // Format scrypt de ce serveur
  if (stored.startsWith("scrypt$")) {
    const parts = stored.split("$");

    if (parts.length !== 3) return false;

    const salt = parts[1];
    const originalHash = Buffer.from(parts[2], "hex");

    const newHash = crypto.scryptSync(
      password,
      salt,
      originalHash.length
    );

    return (
      originalHash.length === newHash.length &&
      crypto.timingSafeEqual(originalHash, newHash)
    );
  }

  // Compatibilité avec les anciens comptes en clair.
  return stored === password;
}

async function savePassword(userId, password) {
  const passwordHash = hashPassword(password);

  const { error } = await supabase
    .from("taya_v13_users")
    .update({
      password_hash: passwordHash,
      password: null,
      must_reset_password: false,
      updated_at: new Date().toISOString()
    })
    .eq("id", userId);

  if (error) throw error;
}

/* =========================
   AUTHENTIFICATION
========================= */

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

/* =========================
   ROUTE PRINCIPALE
========================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    application: "TAYA IA",
    version: VERSION,
    creator: "MARUCE SOLDADO",
    country: "Guinée",
    server: "online"
  });
});

/* =========================
   ÉTAT DU SERVEUR
========================= */

app.get("/api/status", (req, res) => {
  success(res, {
    version: VERSION,
    server: "online",
    supabase: supabase ? "configured" : "not_configured",
    ai: OPENROUTER_API_KEY ? "configured" : "not_configured"
  });
});

/* =========================
   ANCIEN ACCÈS DÉSACTIVÉ
========================= */

app.post("/api/auth/access", (req, res) => {
  failure(
    res,
    403,
    "Cette méthode de connexion est désactivée. Utilise ton mot de passe."
  );
});

app.post("/api/auth/legacy-reset", (req, res) => {
  failure(
    res,
    403,
    "Réinitialisation non autorisée sans vérification du compte."
  );
});

/* =========================
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
      return failure(res, 500, "Erreur lors de la vérification du compte.");
    }

    if (existing) {
      return failure(res, 409, "Ce numéro possède déjà un compte.");
    }

    const recoveryCode = generateRecoveryCode();

    const passwordHash = hashPassword(password);

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .insert({
        name,
        phone,
        password_hash: passwordHash,
        password: null,
        recovery_code_hash: hashRecoveryCode(recoveryCode),
        role: isAdmin(phone) ? "admin" : "user",
        must_reset_password: false
      })
      .select("*")
      .single();

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

    // Les administrateurs conservent leur mot de passe actuel.
    // Leur connexion valide permet de retirer l'ancien indicateur.
    if (user.must_reset_password && isAdmin(user.phone)) {
      const { error: updateError } = await supabase
        .from("taya_v13_users")
        .update({
          must_reset_password: false,
          updated_at: new Date().toISOString()
        })
        .eq("id", user.id);

      if (updateError) {
        console.error("Admin update:", updateError.message);
      }
    } else if (user.must_reset_password) {
      return failure(
        res,
        403,
        "Ce compte doit être réactivé par une procédure de récupération vérifiée."
      );
    }

    // Met à niveau les anciens mots de passe après vérification.
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
   RÉCUPÉRATION PAR CODE
========================= */

app.post("/api/auth/recover", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const recoveryCode = String(req.body.recovery_code || "");
    const newPassword = String(req.body.new_password || "");

    if (!phone || !recoveryCode || newPassword.length < 6) {
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

    const submittedHash = hashRecoveryCode(recoveryCode);

    const valid =
      submittedHash === user.recovery_code_hash;

    if (!valid) {
      return failure(res, 400, "Code de récupération incorrect.");
    }

    const newRecoveryCode = generateRecoveryCode();

    const { error: updateError } = await supabase
      .from("taya_v13_users")
      .update({
        password_hash: hashPassword(newPassword),
        password: null,
        recovery_code_hash: hashRecoveryCode(newRecoveryCode),
        must_reset_password: false,
        updated_at: new Date().toISOString()
      })
      .eq("id", user.id);

    if (updateError) {
      return failure(res, 500, "Impossible de modifier le mot de passe.");
    }

    return success(res, {
      message: "Mot de passe modifié.",
      recovery_code: newRecoveryCode
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
   CHAT IA
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
      messages = [
        {
          role: "user",
          content: String(req.body.message)
        }
      ];
    }

    if (!messages.length) {
      return failure(res, 400, "Écris un message.");
    }

    const safeMessages = messages
      .filter(item =>
        item &&
        ["user", "assistant"].includes(item.role) &&
        typeof item.content === "string"
      )
      .slice(-30);

    if (!safeMessages.length) {
      return failure(res, 400, "Messages invalides.");
    }

    const { data: memoryData } = await supabase
      .from("taya_v12_memories")
      .select("memory")
      .eq("user_id", req.user.id)
      .maybeSingle();

    const memory = memoryData?.memory || "";

    const systemPrompt = `
Tu es TAYA IA, un assistant intelligent créé par MARUCE SOLDADO en Guinée 🇬🇳.

Tu dois :
- Répondre directement et clairement.
- Comprendre les questions en français et dans d'autres langues.
- Aider en programmation, mathématiques, rédaction, traduction et explications.
- Ne pas inventer des informations.
- Dire clairement quand tu ne connais pas une réponse.
- Adapter la longueur de ta réponse à la question.
- Être professionnel, rapide et utile.

Nom de l'utilisateur : ${req.user.name || "Utilisateur"}

Mémoire de l'utilisateur :
${memory}
`;

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
        "OpenRouter error:",
        response.status,
        result?.error?.message || "Erreur IA"
      );

      return failure(
        res,
        502,
        "Le service IA ne répond pas actuellement. Réessaie."
      );
    }

    const reply =
      result?.choices?.[0]?.message?.content;

    if (!reply) {
      return failure(res, 502, "Réponse IA vide.");
    }

    // Enregistrement du dernier message utilisateur et de la réponse.
    const lastUserMessage = [...safeMessages]
      .reverse()
      .find(item => item.role === "user");

    if (lastUserMessage) {
      const { error: saveUserError } = await supabase
        .from("taya_v12_messages")
        .insert({
          user_id: req.user.id,
          role: "user",
          message: lastUserMessage.content
        });

      if (saveUserError) {
        console.error("Save user message:", saveUserError.message);
      }
    }

    const { error: saveAssistantError } = await supabase
      .from("taya_v12_messages")
      .insert({
        user_id: req.user.id,
        role: "assistant",
        message: reply
      });

    if (saveAssistantError) {
      console.error("Save assistant message:", saveAssistantError.message);
    }

    return success(res, {
      reply,
      answer: reply
    });
  } catch (error) {
    console.error("Chat error:", error.message);
    return failure(res, 500, "Une erreur est survenue pendant la réponse.");
  }
});

/* =========================
   CONTACT MARUCE
========================= */

app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message) {
      return failure(res, 400, "Écris un message avant l'envoi.");
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

    success(res, {
      message: "Message envoyé à Maruce."
    });
  } catch (error) {
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
        return failure(res, 500, "Impossible de charger les utilisateurs.");
      }

      const users = (data || []).map(user => ({
        ...user,
        role: isAdmin(user.phone) ? "admin" : "user"
      }));

      success(res, {
        users
      });
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
        return failure(res, 500, "Impossible de charger les messages.");
      }

      success(res, {
        messages: data || []
      });
    } catch (error) {
      return failure(res, 500, "Erreur de chargement des messages.");
    }
  }
);

/* =========================
   ERREURS
========================= */

app.use((err, req, res, next) => {
  if (err.message === "Origine non autorisée") {
    return failure(res, 403, "Origine non autorisée.");
  }

  console.error("Server error:", err.message);

  return failure(res, 500, "Erreur interne du serveur.");
});

app.use((req, res) => {
  failure(res, 404, "Route introuvable.");
});

/* =========================
   DÉMARRAGE
========================= */

app.listen(PORT, () => {
  console.log("--------------------------------");
  console.log("TAYA IA V" + VERSION);
  console.log("Serveur démarré sur le port " + PORT);
  console.log("Créateur : MARUCE SOLDADO 🇬🇳");
  console.log("Supabase :", supabase ? "Configuré" : "Non configuré");
  console.log("OpenRouter :", OPENROUTER_API_KEY ? "Configuré" : "Non configuré");
  console.log("--------------------------------");
});
