require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { promisify } = require("util");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 3000;
const VERSION = "13.0.0";

const {
  OPENROUTER_API_KEY,
  OPENROUTER_MODEL,
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  JWT_SECRET,
  ALLOWED_ORIGIN
} = process.env;

const scrypt = promisify(crypto.scrypt);

const supabase =
  SUPABASE_URL && SUPABASE_SECRET_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
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

app.use(helmet());

app.use(cors({
  origin: ALLOWED_ORIGIN
    ? ALLOWED_ORIGIN.split(",").map(x => x.trim())
    : true
}));

app.use(express.json({ limit: "2mb" }));

app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false
}));

function normalizePhone(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  return digits ? "+" + digits : "";
}

function isAdmin(phone) {
  return ADMIN_PHONES.includes(normalizePhone(phone));
}

function createToken(user) {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET non configuré");
  }

  return jwt.sign(
    {
      id: user.id,
      phone: user.phone,
      role: isAdmin(user.phone) ? "admin" : "user"
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = await scrypt(password, salt, 64);

  return `scrypt$${salt}$${hash.toString("hex")}`;
}

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split("$");

    if (parts.length !== 3 || parts[0] !== "scrypt") {
      return false;
    }

    const salt = parts[1];
    const original = Buffer.from(parts[2], "hex");
    const hash = await scrypt(password, salt, 64);

    return original.length === hash.length &&
      crypto.timingSafeEqual(original, hash);
  } catch {
    return false;
  }
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token || !JWT_SECRET) {
    return res.status(401).json({
      success: false,
      error: "Connexion nécessaire"
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      success: false,
      error: "Session expirée"
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      error: "Accès administrateur refusé"
    });
  }

  next();
}

function requireSupabase(res) {
  if (!supabase) {
    res.status(503).json({
      success: false,
      error: "Supabase non configuré"
    });
    return false;
  }

  return true;
}

const systemPrompt = `
Tu es TAYA IA V13, une intelligence artificielle créée par Maruce Soldado en Guinée 🇬🇳.

RÈGLES :
- Réponds directement à la question.
- Utilise un français naturel et clair.
- Évite les introductions inutiles.
- Ne répète pas la question.
- Aide en programmation, mathématiques, sciences, technologie, rédaction et traduction.
- Donne du code complet et fonctionnel lorsque cela est demandé.
- Explique les sujets difficiles simplement.
- Ne prétends jamais avoir effectué une action que tu n'as pas faite.
- Si tu ne connais pas une réponse, sois honnête.
- Garde le contexte de la conversation.
`;

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "TAYA IA",
    version: VERSION,
    status: "online",
    supabase: !!supabase,
    artificial_intelligence: !!OPENROUTER_API_KEY
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "healthy",
    version: VERSION
  });
});

// INSCRIPTION
app.post("/api/auth/register", async (req, res) => {
  try {
    if (!requireSupabase(res)) return;

    const fullName = String(
      req.body.fullName || req.body.full_name || ""
    ).trim();

    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!fullName || !phone || password.length < 8) {
      return res.status(400).json({
        success: false,
        error: "Nom, numéro et mot de passe de 8 caractères minimum requis"
      });
    }

    const { data: existing, error: lookupError } =
      await supabase
        .from("taya_v13_users")
        .select("id")
        .eq("phone", phone)
        .maybeSingle();

    if (lookupError) throw lookupError;

    if (existing) {
      return res.status(409).json({
        success: false,
        error: "Ce numéro possède déjà un compte"
      });
    }

    const passwordHash = await hashPassword(password);

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .insert({
        full_name: fullName,
        phone,
        password_hash: passwordHash
      })
      .select("id,full_name,phone,created_at")
      .single();

    if (error) throw error;

    const token = createToken(user);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        phone: user.phone,
        role: isAdmin(user.phone) ? "admin" : "user"
      }
    });

  } catch (error) {
    console.error("REGISTER ERROR:", {
      message: error.message,
      code: error.code,
      details: error.details,
      hint: error.hint
    });

    // Diagnostic temporaire pour identifier l'erreur
    res.status(500).json({
      success: false,
      error: error.message || "Erreur inconnue lors de l'inscription"
    });
  }
});

// CONNEXION
app.post("/api/auth/login", async (req, res) => {
  try {
    if (!requireSupabase(res)) return;

    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!phone || !password) {
      return res.status(400).json({
        success: false,
        error: "Numéro et mot de passe requis"
      });
    }

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (error) throw error;

    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({
        success: false,
        error: "Numéro ou mot de passe incorrect"
      });
    }

    const token = createToken(user);

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        phone: user.phone,
        role: isAdmin(user.phone) ? "admin" : "user"
      }
    });

  } catch (error) {
    console.error("LOGIN ERROR:", {
      message: error.message,
      code: error.code,
      details: error.details,
      hint: error.hint
    });

    res.status(500).json({
      success: false,
      error: "Erreur de connexion"
    });
  }
});

// PROFIL
app.get("/api/auth/me", authenticate, async (req, res) => {
  try {
    if (!requireSupabase(res)) return;

    const { data: user, error } = await supabase
      .from("taya_v13_users")
      .select("id,full_name,phone,created_at")
      .eq("id", req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({
        success: false,
        error: "Utilisateur introuvable"
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        fullName: user.full_name,
        phone: user.phone,
        role: isAdmin(user.phone) ? "admin" : "user"
      }
    });

  } catch (error) {
    console.error("PROFILE ERROR:", error.message);

    res.status(500).json({
      success: false,
      error: "Erreur de profil"
    });
  }
});

// INTELLIGENCE ARTIFICIELLE
app.post("/api/chat", async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return res.status(503).json({
        success: false,
        error: "Clé OpenRouter non configurée"
      });
    }

    const messages = Array.isArray(req.body.messages)
      ? req.body.messages
      : [];

    const cleanMessages = messages
      .filter(m =>
        ["user", "assistant"].includes(m.role) &&
        typeof m.content === "string"
      )
      .slice(-20)
      .map(m => ({
        role: m.role,
        content: m.content.slice(0, 12000)
      }));

    if (!cleanMessages.length) {
      return res.status(400).json({
        success: false,
        error: "Aucun message reçu"
      });
    }

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://marucesoldado752-ux.github.io",
          "X-Title": "TAYA IA V13"
        },
        body: JSON.stringify({
          model: OPENROUTER_MODEL ||
            "meta-llama/llama-3.3-70b-instruct:free",
          messages: [
            {
              role: "system",
              content: systemPrompt
            },
            ...cleanMessages
          ],
          temperature: 0.7,
          max_tokens: 2500
        }),
        signal: AbortSignal.timeout(60000)
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("OPENROUTER ERROR:", data);

      return res.status(502).json({
        success: false,
        error: "Le moteur IA n'a pas répondu correctement"
      });
    }

    const answer = data.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        success: false,
        error: "Réponse IA vide"
      });
    }

    res.json({
      success: true,
      reply: answer,
      answer
    });

  } catch (error) {
    console.error("CHAT ERROR:", error.message);

    res.status(500).json({
      success: false,
      error: "Erreur du moteur IA"
    });
  }
});

// ADMIN : LISTE DES UTILISATEURS
app.get(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      if (!requireSupabase(res)) return;

      const { data, error } = await supabase
        .from("taya_v13_users")
        .select("id,full_name,phone,created_at")
        .order("created_at", { ascending: false })
        .limit(500);

      if (error) throw error;

      res.json({
        success: true,
        users: data
      });

    } catch (error) {
      console.error("ADMIN USERS ERROR:", error.message);

      res.status(500).json({
        success: false,
        error: "Impossible de charger les utilisateurs"
      });
    }
  }
);

// ROUTE INCONNUE
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Route introuvable"
  });
});

// ERREUR SERVEUR
app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error.message);

  res.status(500).json({
    success: false,
    error: "Erreur interne du serveur"
  });
});

app.listen(PORT, () => {
  console.log("================================");
  console.log("TAYA IA V13");
  console.log("Serveur démarré sur le port " + PORT);
  console.log("Supabase :", !!supabase);
  console.log("OpenRouter :", !!OPENROUTER_API_KEY);
  console.log("JWT :", !!JWT_SECRET);
  console.log("================================");
});
