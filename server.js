require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 3000;
const VERSION = "13.0.0";

const {
  OPENROUTER_API_KEY,
  AI_MODEL = "openai/gpt-4o-mini",
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET,
  TAYA_ADMIN_KEY
} = process.env;

const ADMIN_PHONES = [
  "+224663401157",
  "+224612768878"
];

const supabaseKey =
  SUPABASE_SECRET_KEY || SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !supabaseKey || !JWT_SECRET) {
  console.error("Configuration Supabase ou JWT manquante");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, supabaseKey);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(cors({
  origin: [
    "https://marucesoldado752-ux.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
  ]
}));

app.use(express.json({ limit: "20mb" }));

app.use("/api", rateLimit({
  windowMs: 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false
}));

// OUTILS

function normalizePhone(phone) {
  return String(phone || "").replace(/\s+/g, "");
}

function isAdmin(phone) {
  return ADMIN_PHONES.includes(normalizePhone(phone));
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      phone: user.phone
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function publicUser(user) {
  return {
    id: user.id,
    fullName: user.full_name,
    phone: user.phone,
    isAdmin: isAdmin(user.phone)
  };
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: "Connexion nécessaire"
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.phone = decoded.phone;
    next();
  } catch {
    return res.status(401).json({
      error: "Session expirée ou invalide"
    });
  }
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req.phone)) {
    return res.status(403).json({
      error: "Accès réservé aux administrateurs"
    });
  }

  next();
}

async function getUser(userId) {
  const { data, error } = await supabase
    .from("taya_v12_users")
    .select("*")
    .eq("id", userId)
    .single();

  if (error) return null;
  return data;
}

// TEST DU SERVEUR

app.get("/", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online"
  });
});

app.get("/health", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online",
    aiConfigured: !!OPENROUTER_API_KEY,
    supabaseConfigured: !!SUPABASE_URL && !!supabaseKey,
    model: AI_MODEL
  });
});

// INSCRIPTION

app.post("/api/register", async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!fullName || !phone || password.length < 8) {
      return res.status(400).json({
        error: "Nom, téléphone et mot de passe de 8 caractères minimum obligatoires"
      });
    }

    const { data: existing } = await supabase
      .from("taya_v12_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({
        error: existing.password_hash
          ? "Ce numéro possède déjà un compte. Connecte-toi."
          : "Ancien compte V12 détecté. Une activation sécurisée est nécessaire.",
        code: "ACCOUNT_EXISTS"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data: user, error } = await supabase
      .from("taya_v12_users")
      .insert({
        full_name: fullName,
        phone,
        password_hash: passwordHash,
        password_updated_at: new Date().toISOString()
      })
      .select()
      .single();

    if (error) throw error;

    return res.json({
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("REGISTER:", error.message);
    res.status(500).json({
      error: "Impossible de créer le compte"
    });
  }
});

// CONNEXION

app.post("/api/login", async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!phone || !password) {
      return res.status(400).json({
        error: "Téléphone et mot de passe obligatoires"
      });
    }

    const { data: user, error } = await supabase
      .from("taya_v12_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({
        error: "Numéro ou mot de passe incorrect"
      });
    }

    if (!user.password_hash) {
      return res.status(403).json({
        error: "Ancien compte V12. Activation sécurisée nécessaire.",
        code: "LEGACY_ACCOUNT"
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Numéro ou mot de passe incorrect"
      });
    }

    return res.json({
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("LOGIN:", error.message);
    res.status(500).json({
      error: "Erreur pendant la connexion"
    });
  }
});

// ACTIVATION SÉCURISÉE DES COMPTES ADMINISTRATEURS V12

app.post("/api/admin/activate", async (req, res) => {
  try {
    const { adminKey, fullName, password } = req.body;
    const phone = normalizePhone(req.body.phone);

    if (
      !TAYA_ADMIN_KEY ||
      adminKey !== TAYA_ADMIN_KEY ||
      !isAdmin(phone)
    ) {
      return res.status(403).json({
        error: "Activation refusée"
      });
    }

    if (!password || String(password).length < 8) {
      return res.status(400).json({
        error: "Mot de passe de 8 caractères minimum obligatoire"
      });
    }

    const { data: user } = await supabase
      .from("taya_v12_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (!user) {
      return res.status(404).json({
        error: "Compte administrateur V12 introuvable"
      });
    }

    const passwordHash = await bcrypt.hash(
      String(password),
      12
    );

    const { data: updated, error } = await supabase
      .from("taya_v12_users")
      .update({
        full_name: fullName || user.full_name,
        password_hash: passwordHash,
        password_updated_at: new Date().toISOString()
      })
      .eq("id", user.id)
      .select()
      .single();

    if (error) throw error;

    res.json({
      message: "Compte administrateur activé",
      token: createToken(updated),
      user: publicUser(updated)
    });

  } catch (error) {
    console.error("ADMIN ACTIVATION:", error.message);
    res.status(500).json({
      error: "Impossible d'activer le compte"
    });
  }
});

// PROFIL

app.get("/api/profile", authenticate, async (req, res) => {
  try {
    const user = await getUser(req.userId);

    if (!user) {
      return res.status(404).json({
        error: "Utilisateur introuvable"
      });
    }

    res.json({
      user: publicUser(user)
    });

  } catch {
    res.status(500).json({
      error: "Erreur du profil"
    });
  }
});

// MODIFIER LE NOM

app.put("/api/profile/name", authenticate, async (req, res) => {
  try {
    const { currentName, newName, confirmName } = req.body;

    if (
      !newName ||
      newName !== confirmName ||
      newName.trim().length < 2
    ) {
      return res.status(400).json({
        error: "Vérifie le nouveau nom"
      });
    }

    const user = await getUser(req.userId);

    if (!user || user.full_name !== currentName) {
      return res.status(400).json({
        error: "Nom actuel incorrect"
      });
    }

    const { data, error } = await supabase
      .from("taya_v12_users")
      .update({ full_name: newName.trim() })
      .eq("id", req.userId)
      .select()
      .single();

    if (error) throw error;

    res.json({ user: publicUser(data) });

  } catch {
    res.status(500).json({
      error: "Impossible de modifier le nom"
    });
  }
});

// MODIFIER LE NUMÉRO

app.put("/api/profile/phone", authenticate, async (req, res) => {
  try {
    const phone = normalizePhone(req.body.newPhone);

    if (
      normalizePhone(req.body.currentPhone) !== req.phone ||
      phone !== normalizePhone(req.body.confirmPhone) ||
      !phone
    ) {
      return res.status(400).json({
        error: "Vérifie les numéros"
      });
    }

    const { data: existing } = await supabase
      .from("taya_v12_users")
      .select("id")
      .eq("phone", phone)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({
        error: "Ce numéro est déjà utilisé"
      });
    }

    const { data, error } = await supabase
      .from("taya_v12_users")
      .update({ phone })
      .eq("id", req.userId)
      .select()
      .single();

    if (error) throw error;

    res.json({
      user: publicUser(data),
      token: createToken(data)
    });

  } catch {
    res.status(500).json({
      error: "Impossible de modifier le numéro"
    });
  }
});

// MÉMOIRE

app.get("/api/memory", authenticate, async (req, res) => {
  const { data, error } = await supabase
    .from("taya_v12_memories")
    .select("memory")
    .eq("user_id", req.userId)
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      error: "Erreur de mémoire"
    });
  }

  res.json({
    memory: data?.memory || ""
  });
});

app.put("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = String(req.body.memory || "");

    const { error } = await supabase
      .from("taya_v12_memories")
      .upsert({
        user_id: req.userId,
        memory,
        updated_at: new Date().toISOString()
      }, {
        onConflict: "user_id"
      });

    if (error) throw error;

    res.json({ success: true });

  } catch {
    res.status(500).json({
      error: "Impossible de sauvegarder la mémoire"
    });
  }
});

app.delete("/api/memory", authenticate, async (req, res) => {
  const { error } = await supabase
    .from("taya_v12_memories")
    .delete()
    .eq("user_id", req.userId);

  if (error) {
    return res.status(500).json({
      error: "Impossible de supprimer la mémoire"
    });
  }

  res.json({ success: true });
});

// INTELLIGENCE ARTIFICIELLE

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return res.status(503).json({
        error: "Intelligence artificielle non configurée"
      });
    }

    const messages = req.body.messages;

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        error: "Aucun message reçu"
      });
    }

    const user = await getUser(req.userId);

    if (!user) {
      return res.status(404).json({
        error: "Utilisateur introuvable"
      });
    }

    const { data: memoryData } = await supabase
      .from("taya_v12_memories")
      .select("memory")
      .eq("user_id", req.userId)
      .maybeSingle();

    const memory = memoryData?.memory || "";

    const systemPrompt = `
Tu es TAYA IA V13, une intelligence artificielle développée par MARUCE SOLDADO en Guinée 🇬🇳.

RÈGLES :
- Réponds directement à la question.
- Sois rapide, précis et utile.
- Utilise la langue de l'utilisateur.
- Ne commence pas inutilement par des salutations.
- Ne donne pas d'informations inventées.
- Pour les calculs, donne le résultat exact.
- Pour le code, fournis un code complet lorsque cela est demandé.
- Si tu ne connais pas une information, dis-le clairement.
- Respecte le contexte de la conversation.

Nom de l'utilisateur : ${user.full_name}
Mémoire de l'utilisateur : ${memory}
`;

    const cleanMessages = messages
      .filter(m =>
        m &&
        ["user", "assistant"].includes(m.role) &&
        m.content !== undefined
      )
      .slice(-20);

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
          model: AI_MODEL,
          messages: [
            { role: "system", content: systemPrompt },
            ...cleanMessages
          ],
          temperature: 0.5,
          max_tokens: 2500
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("OPENROUTER:", result);
      return res.status(502).json({
        error: "Le service IA rencontre un problème"
      });
    }

    const answer =
      result.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        error: "Aucune réponse reçue de l'IA"
      });
    }

    const lastUserMessage = cleanMessages
      .filter(m => m.role === "user")
      .pop();

    if (lastUserMessage) {
      await supabase
        .from("taya_v12_messages")
        .insert([
          {
            user_id: req.userId,
            role: "user",
            message: typeof lastUserMessage.content === "string"
              ? lastUserMessage.content
              : "[Message multimodal]"
          },
          {
            user_id: req.userId,
            role: "assistant",
            message: answer
          }
        ]);
    }

    res.json({
      answer,
      model: AI_MODEL,
      memoryEnabled: true
    });

  } catch (error) {
    console.error("CHAT:", error.message);
    res.status(500).json({
      error: "Erreur pendant la génération de la réponse"
    });
  }
});

// MESSAGE À MARUCE

app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message || message.length > 5000) {
      return res.status(400).json({
        error: "Message vide ou trop long"
      });
    }

    const { error } = await supabase
      .from("taya_v12_contacts")
      .insert({
        user_id: req.userId,
        message
      });

    if (error) throw error;

    res.json({
      success: true,
      message: "Message envoyé"
    });

  } catch (error) {
    console.error("CONTACT:", error.message);
    res.status(500).json({
      error: "Impossible d'envoyer le message"
    });
  }
});

// ESPACE ADMINISTRATEUR

app.get(
  "/api/admin/dashboard",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const [
        usersResult,
        conversationsResult,
        contactsResult
      ] = await Promise.all([
        supabase
          .from("taya_v12_users")
          .select("id,full_name,phone,created_at")
          .order("created_at", { ascending: false }),

        supabase
          .from("taya_v12_messages")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(200),

        supabase
          .from("taya_v12_contacts")
          .select("*")
          .order("created_at", { ascending: false })
          .limit(100)
      ]);

      if (usersResult.error) throw usersResult.error;
      if (conversationsResult.error) throw conversationsResult.error;
      if (contactsResult.error) throw contactsResult.error;

      res.json({
        totalUsers: usersResult.data.length,
        totalMessages: conversationsResult.data.length,
        totalContacts: contactsResult.data.length,
        users: usersResult.data,
        messages: conversationsResult.data,
        contacts: contactsResult.data
      });

    } catch (error) {
      console.error("ADMIN DASHBOARD:", error.message);
      res.status(500).json({
        error: "Impossible de charger le tableau de bord"
      });
    }
  }
);

// DÉMARRAGE

app.listen(PORT, () => {
  console.log(`TAYA IA V${VERSION} démarré sur le port ${PORT}`);
});
