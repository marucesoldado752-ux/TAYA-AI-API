require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const VERSION = "12.0.0";

const {
  OPENROUTER_API_KEY,
  AI_MODEL,
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  TAYA_ADMIN_KEY
} = process.env;

if (
  !OPENROUTER_API_KEY ||
  !SUPABASE_URL ||
  !SUPABASE_SECRET_KEY ||
  !TAYA_ADMIN_KEY
) {
  console.error("Configuration manquante dans les variables Render");
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

app.use(helmet({
  crossOriginResourcePolicy: false
}));

app.use(cors({
  origin: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Admin-Key"
  ]
}));

app.use(express.json({ limit: "15mb" }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  standardHeaders: true,
  legacyHeaders: false
}));

const hash = value =>
  crypto.createHash("sha256").update(value).digest("hex");

const normalizePhone = value =>
  String(value || "").replace(/\D/g, "");

const normalizeName = value =>
  String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();

const cleanName = value =>
  String(value || "").trim().replace(/\s+/g, " ");

const generateToken = () =>
  crypto.randomBytes(32).toString("hex");

const safeEqual = (a, b) => {
  const first = Buffer.from(String(a || ""));
  const second = Buffer.from(String(b || ""));

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
};

// =====================================
// AUTHENTIFICATION DES UTILISATEURS
// =====================================

async function authenticate(req, res, next) {
  try {
    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Session manquante"
      });
    }

    const token = authorization.slice(7);

    if (!/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(401).json({
        error: "Session invalide"
      });
    }

    const { data: session, error } = await supabase
      .from("taya_sessions")
      .select("user_id, expires_at")
      .eq("token_hash", hash(token))
      .maybeSingle();

    if (error || !session) {
      return res.status(401).json({
        error: "Session invalide"
      });
    }

    if (new Date(session.expires_at) <= new Date()) {
      await supabase
        .from("taya_sessions")
        .delete()
        .eq("token_hash", hash(token));

      return res.status(401).json({
        error: "Session expirée"
      });
    }

    const { data: user, error: userError } = await supabase
      .from("taya_users")
      .select("id, full_name, phone, created_at")
      .eq("id", session.user_id)
      .single();

    if (userError || !user) {
      return res.status(401).json({
        error: "Compte introuvable"
      });
    }

    req.user = user;
    req.tokenHash = hash(token);

    next();

  } catch (error) {
    console.error("Authentification:", error.message);

    res.status(500).json({
      error: "Erreur d'authentification"
    });
  }
}

// =====================================
// ADMINISTRATION
// =====================================

function authenticateAdmin(req, res, next) {
  const key = req.headers["x-admin-key"];

  if (!key || !safeEqual(key, TAYA_ADMIN_KEY)) {
    return res.status(403).json({
      error: "Accès administrateur refusé"
    });
  }

  next();
}

// =====================================
// ACCUEIL
// =====================================

app.get("/", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online",
    message: "Bienvenue sur TAYA IA 🇬🇳"
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    version: VERSION
  });
});

// =====================================
// INSCRIPTION AUTOMATIQUE
// =====================================

app.post("/api/register", async (req, res) => {
  try {
    const fullName = cleanName(req.body.fullName);
    const phone = String(req.body.phone || "").trim();
    const phoneNormalized = normalizePhone(phone);
    const nameNormalized = normalizeName(fullName);

    if (fullName.length < 2 || fullName.length > 60) {
      return res.status(400).json({
        error: "Nom invalide"
      });
    }

    if (!/^\d{6,15}$/.test(phoneNormalized)) {
      return res.status(400).json({
        error: "Numéro de téléphone invalide"
      });
    }

    const { data: existing, error: searchError } = await supabase
      .from("taya_users")
      .select("id")
      .or(
        `phone_normalized.eq.${phoneNormalized},name_normalized.eq.${nameNormalized}`
      )
      .limit(1);

    if (searchError) throw searchError;

    if (existing && existing.length > 0) {
      return res.status(409).json({
        error: "Ce nom ou ce numéro est déjà utilisé"
      });
    }

    const { data: user, error: insertError } = await supabase
      .from("taya_users")
      .insert({
        id: crypto.randomUUID(),
        full_name: fullName,
        phone,
        phone_normalized: phoneNormalized,
        name_normalized: nameNormalized,
        updated_at: new Date().toISOString()
      })
      .select("id, full_name, phone, created_at")
      .single();

    if (insertError) {
      if (insertError.code === "23505") {
        return res.status(409).json({
          error: "Ce nom ou ce numéro est déjà utilisé"
        });
      }

      throw insertError;
    }

    const token = generateToken();

    const { error: sessionError } = await supabase
      .from("taya_sessions")
      .insert({
        token_hash: hash(token),
        user_id: user.id,
        expires_at: new Date(
          Date.now() + 365 * 24 * 60 * 60 * 1000
        ).toISOString()
      });

    if (sessionError) {
      await supabase
        .from("taya_users")
        .delete()
        .eq("id", user.id);

      throw sessionError;
    }

    res.status(201).json({
      success: true,
      token,
      user
    });

  } catch (error) {
    console.error("Inscription:", error.message);

    res.status(500).json({
      error: "Impossible de créer le compte"
    });
  }
});

// =====================================
// PROFIL UTILISATEUR
// =====================================

app.get("/api/profile", authenticate, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// Modifier le nom
app.put("/api/profile/name", authenticate, async (req, res) => {
  try {
    const currentName = normalizeName(req.body.currentName);
    const newName = cleanName(req.body.newName);
    const confirmName = cleanName(req.body.confirmName);

    if (normalizeName(req.user.full_name) !== currentName) {
      return res.status(400).json({
        error: "Ancien nom incorrect"
      });
    }

    if (
      newName.length < 2 ||
      newName.length > 60 ||
      normalizeName(newName) !== normalizeName(confirmName)
    ) {
      return res.status(400).json({
        error: "Les nouveaux noms ne correspondent pas"
      });
    }

    const { data, error } = await supabase
      .from("taya_users")
      .update({
        full_name: newName,
        name_normalized: normalizeName(newName),
        updated_at: new Date().toISOString()
      })
      .eq("id", req.user.id)
      .select("id, full_name, phone, created_at")
      .single();

    if (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error: "Ce nom est déjà utilisé"
        });
      }

      throw error;
    }

    res.json({
      success: true,
      user: data
    });

  } catch (error) {
    console.error("Modification nom:", error.message);

    res.status(500).json({
      error: "Impossible de modifier le nom"
    });
  }
});

// Modifier le numéro
app.put("/api/profile/phone", authenticate, async (req, res) => {
  try {
    const currentPhone = normalizePhone(req.body.currentPhone);
    const newPhone = String(req.body.newPhone || "").trim();
    const confirmPhone = String(req.body.confirmPhone || "").trim();

    const newNormalized = normalizePhone(newPhone);

    if (normalizePhone(req.user.phone) !== currentPhone) {
      return res.status(400).json({
        error: "Ancien numéro incorrect"
      });
    }

    if (
      !/^\d{6,15}$/.test(newNormalized) ||
      newNormalized !== normalizePhone(confirmPhone)
    ) {
      return res.status(400).json({
        error: "Les nouveaux numéros ne correspondent pas"
      });
    }

    const { data, error } = await supabase
      .from("taya_users")
      .update({
        phone: newPhone,
        phone_normalized: newNormalized,
        updated_at: new Date().toISOString()
      })
      .eq("id", req.user.id)
      .select("id, full_name, phone, created_at")
      .single();

    if (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error: "Ce numéro est déjà utilisé"
        });
      }

      throw error;
    }

    res.json({
      success: true,
      user: data
    });

  } catch (error) {
    console.error("Modification téléphone:", error.message);

    res.status(500).json({
      error: "Impossible de modifier le numéro"
    });
  }
});

// =====================================
// DÉCONNEXION
// =====================================

app.post("/api/logout", authenticate, async (req, res) => {
  const { error } = await supabase
    .from("taya_sessions")
    .delete()
    .eq("token_hash", req.tokenHash);

  if (error) {
    return res.status(500).json({
      error: "Déconnexion impossible"
    });
  }

  res.json({
    success: true,
    message: "Déconnexion réussie"
  });
});

// =====================================
// MÉMOIRE DE TAYA IA
// =====================================

app.get("/api/memory", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_memories")
      .select("memory")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) throw error;

    res.json({
      memory: data?.memory || ""
    });

  } catch (error) {
    res.status(500).json({
      error: "Impossible de charger la mémoire"
    });
  }
});

app.put("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = String(req.body.memory || "").slice(0, 20000);

    const { error } = await supabase
      .from("taya_memories")
      .upsert({
        user_id: req.user.id,
        memory,
        updated_at: new Date().toISOString()
      });

    if (error) throw error;

    res.json({
      success: true
    });

  } catch (error) {
    res.status(500).json({
      error: "Impossible de sauvegarder la mémoire"
    });
  }
});

app.delete("/api/memory", authenticate, async (req, res) => {
  try {
    const { error } = await supabase
      .from("taya_memories")
      .delete()
      .eq("user_id", req.user.id);

    if (error) throw error;

    res.json({
      success: true
    });

  } catch (error) {
    res.status(500).json({
      error: "Impossible de supprimer la mémoire"
    });
  }
});

// =====================================
// INTELLIGENCE ARTIFICIELLE
// =====================================

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return res.status(503).json({
        error: "Service IA indisponible"
      });
    }

    const messages = req.body.messages;

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        error: "Aucun message reçu"
      });
    }

    if (messages.length > 60) {
      return res.status(400).json({
        error: "Conversation trop longue"
      });
    }

    const { data: memoryData } = await supabase
      .from("taya_memories")
      .select("memory")
      .eq("user_id", req.user.id)
      .maybeSingle();

    const memory = memoryData?.memory || "";

    const systemPrompt = `
Tu es TAYA IA 🇬🇳, une intelligence artificielle moderne créée par Maruce.

Tu aides les utilisateurs à répondre à leurs questions dans tous les domaines.

Tes qualités :
- Tu es intelligente, rapide et précise.
- Tu réponds en français si l'utilisateur parle français.
- Tu peux également comprendre d'autres langues.
- Tu expliques clairement les sujets difficiles.
- Tu aides en programmation, sciences, mathématiques, rédaction, études et créativité.
- Tu peux écrire et corriger du code.
- Tu ne prétends jamais avoir effectué une action que tu n'as pas faite.
- Tu reconnais honnêtement tes limites.
- Tu évites les introductions inutiles et réponds directement.

Nom de l'utilisateur : ${req.user.full_name}

Mémoire personnelle de cet utilisateur :
${memory || "Aucune mémoire enregistrée."}
`;

    const conversation = messages.map(message => ({
      role: ["user", "assistant"].includes(message.role)
        ? message.role
        : "user",
      content: message.content
    }));

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://marucesoldado752-ux.github.io/",
          "X-Title": "TAYA IA"
        },
        body: JSON.stringify({
          model: AI_MODEL || "openai/gpt-4o-mini",
          messages: [
            {
              role: "system",
              content: systemPrompt
            },
            ...conversation
          ],
          temperature: 0.7,
          max_tokens: 4000
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("OpenRouter:", result);

      return res.status(502).json({
        error: "Le service IA rencontre un problème"
      });
    }

    const answer = result.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        error: "Aucune réponse reçue de l'IA"
      });
    }

    res.json({
      success: true,
      answer,
      model: result.model || AI_MODEL
    });

  } catch (error) {
    console.error("Chat:", error.message);

    res.status(500).json({
      error: "Une erreur est survenue pendant la discussion"
    });
  }
});

// =====================================
// CONTACT
// =====================================

app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message || message.length > 5000) {
      return res.status(400).json({
        error: "Message invalide"
      });
    }

    const { error } = await supabase
      .from("taya_contact_messages")
      .insert({
        user_id: req.user.id,
        message
      });

    if (error) throw error;

    res.json({
      success: true,
      message: "Message envoyé"
    });

  } catch (error) {
    console.error("Contact:", error.message);

    res.status(500).json({
      error: "Impossible d'envoyer le message"
    });
  }
});

// =====================================
// TABLEAU DE BORD ADMINISTRATEUR
// =====================================

app.get(
  "/api/admin/dashboard",
  authenticateAdmin,
  async (req, res) => {
    try {
      const [usersResult, messagesResult] = await Promise.all([
        supabase
          .from("taya_users")
          .select("id, full_name, phone, created_at, updated_at")
          .order("created_at", { ascending: false }),

        supabase
          .from("taya_contact_messages")
          .select("id, user_id, message, created_at")
          .order("created_at", { ascending: false })
      ]);

      if (usersResult.error) throw usersResult.error;
      if (messagesResult.error) throw messagesResult.error;

      res.json({
        success: true,
        totalUsers: usersResult.data.length,
        totalMessages: messagesResult.data.length,
        users: usersResult.data,
        messages: messagesResult.data
      });

    } catch (error) {
      console.error("Admin:", error.message);

      res.status(500).json({
        error: "Impossible de charger le tableau de bord"
      });
    }
  }
);

// =====================================
// DÉMARRAGE
// =====================================

app.listen(PORT, () => {
  console.log(`TAYA IA ${VERSION} démarré sur le port ${PORT}`);
});
