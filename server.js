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
  console.error("Configuration Supabase ou JWT manquante.");
  process.exit(1);
}

if (!OPENROUTER_API_KEY) {
  console.error("OPENROUTER_API_KEY manquante.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, supabaseKey);

app.use(helmet());

app.use(cors({
  origin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(",").map(x => x.trim())
    : true
}));

app.use(express.json({ limit: "15mb" }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 40,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use(limiter);

function normalizePhone(phone) {
  return String(phone || "").replace(/[\s()-]/g, "");
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
    full_name: user.full_name,
    phone: user.phone,
    created_at: user.created_at,
    isAdmin: isAdmin(user.phone)
  };
}

function sendError(res, error, status = 400) {
  console.error(error);
  return res.status(status).json({
    error: typeof error === "string"
      ? error
      : "Une erreur est survenue."
  });
}

async function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: "Connexion requise." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const { data: user, error } = await supabase
      .from("taya_v12_users")
      .select("*")
      .eq("id", decoded.userId)
      .single();

    if (error || !user) {
      return res.status(401).json({
        error: "Compte introuvable."
      });
    }

    req.user = user;
    req.userId = user.id;
    req.phone = user.phone;

    next();
  } catch {
    return res.status(401).json({
      error: "Session expirée. Reconnecte-toi."
    });
  }
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req.phone)) {
    return res.status(403).json({
      error: "Accès réservé aux administrateurs."
    });
  }

  next();
}

async function getUserByPhone(phone) {
  const { data, error } = await supabase
    .from("taya_v12_users")
    .select("*")
    .eq("phone", phone)
    .maybeSingle();

  if (error) throw error;

  return data;
}

/* ACCUEIL */

app.get("/", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    creator: "MARUCE SOLDADO",
    country: "Guinée",
    status: "online"
  });
});

/* SANTÉ DU SERVEUR */

app.get("/health", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online",
    aiConfigured: Boolean(OPENROUTER_API_KEY),
    supabaseConfigured: Boolean(SUPABASE_URL && supabaseKey),
    model: AI_MODEL
  });
});

/* INSCRIPTION */

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim();
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!fullName || !phone || !password) {
      return res.status(400).json({
        error: "Remplis tous les champs."
      });
    }

    if (fullName.length < 2 || fullName.length > 80) {
      return res.status(400).json({
        error: "Nom invalide."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 8 caractères."
      });
    }

    if (isAdmin(phone)) {
      return res.status(403).json({
        error: "Ce numéro est réservé à un compte administrateur."
      });
    }

    const existing = await getUserByPhone(phone);

    if (existing) {
      return res.status(409).json({
        error: "Ce numéro possède déjà un compte."
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
      .select("*")
      .single();

    if (error) throw error;

    const token = createToken(user);

    res.status(201).json({
      message: "Compte créé avec succès.",
      token,
      user: publicUser(user)
    });

  } catch (error) {
    sendError(res, error);
  }
});

/* CONNEXION */

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!phone || !password) {
      return res.status(400).json({
        error: "Numéro et mot de passe obligatoires."
      });
    }

    const user = await getUserByPhone(phone);

    if (!user || !user.password_hash) {
      return res.status(401).json({
        error: "Compte introuvable ou mot de passe non configuré."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Mot de passe incorrect."
      });
    }

    res.json({
      message: "Connexion réussie.",
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    sendError(res, error, 500);
  }
});

/* ACTIVATION DES ANCIENS COMPTES ADMINISTRATEURS */

app.post("/api/admin/activate", authLimiter, async (req, res) => {
  try {
    const adminKey = String(req.body.adminKey || "");
    const fullName = String(req.body.fullName || "").trim();
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!TAYA_ADMIN_KEY || adminKey !== TAYA_ADMIN_KEY) {
      return res.status(403).json({
        error: "Clé administrateur incorrecte."
      });
    }

    if (!isAdmin(phone)) {
      return res.status(403).json({
        error: "Numéro non autorisé."
      });
    }

    if (!fullName || password.length < 8) {
      return res.status(400).json({
        error: "Nom obligatoire et mot de passe de 8 caractères minimum."
      });
    }

    const user = await getUserByPhone(phone);

    if (!user) {
      return res.status(404).json({
        error: "Ancien compte administrateur introuvable."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data: updated, error } = await supabase
      .from("taya_v12_users")
      .update({
        full_name: fullName,
        password_hash: passwordHash,
        password_updated_at: new Date().toISOString()
      })
      .eq("id", user.id)
      .select("*")
      .single();

    if (error) throw error;

    res.json({
      message: "Compte administrateur activé.",
      token: createToken(updated),
      user: publicUser(updated)
    });

  } catch (error) {
    sendError(res, error, 500);
  }
});

/* PROFIL */

app.get("/api/profile", authenticate, (req, res) => {
  res.json({
    user: publicUser(req.user)
  });
});

/* MODIFIER LE NOM */

app.put("/api/profile/name", authenticate, async (req, res) => {
  try {
    const currentName = String(req.body.currentName || "").trim();
    const newName = String(req.body.newName || "").trim();
    const confirmName = String(req.body.confirmName || "").trim();

    if (currentName !== req.user.full_name) {
      return res.status(400).json({
        error: "Nom actuel incorrect."
      });
    }

    if (!newName || newName !== confirmName) {
      return res.status(400).json({
        error: "Les nouveaux noms ne correspondent pas."
      });
    }

    const { data: user, error } = await supabase
      .from("taya_v12_users")
      .update({ full_name: newName })
      .eq("id", req.userId)
      .select("*")
      .single();

    if (error) throw error;

    res.json({
      message: "Nom modifié.",
      user: publicUser(user)
    });

  } catch (error) {
    sendError(res, error);
  }
});

/* MODIFIER LE NUMÉRO */

app.put("/api/profile/phone", authenticate, async (req, res) => {
  try {
    const currentPhone = normalizePhone(req.body.currentPhone);
    const newPhone = normalizePhone(req.body.newPhone);
    const confirmPhone = normalizePhone(req.body.confirmPhone);

    if (currentPhone !== req.user.phone) {
      return res.status(400).json({
        error: "Numéro actuel incorrect."
      });
    }

    if (!newPhone || newPhone !== confirmPhone) {
      return res.status(400).json({
        error: "Les numéros ne correspondent pas."
      });
    }

    if (isAdmin(req.phone)) {
      return res.status(403).json({
        error: "Un administrateur ne peut pas modifier son numéro ici."
      });
    }

    if (isAdmin(newPhone)) {
      return res.status(403).json({
        error: "Ce numéro est réservé à l'administration."
      });
    }

    const existing = await getUserByPhone(newPhone);

    if (existing) {
      return res.status(409).json({
        error: "Ce numéro est déjà utilisé."
      });
    }

    const { data: user, error } = await supabase
      .from("taya_v12_users")
      .update({ phone: newPhone })
      .eq("id", req.userId)
      .select("*")
      .single();

    if (error) throw error;

    res.json({
      message: "Numéro modifié.",
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    sendError(res, error);
  }
});

/* MÉMOIRE */

app.get("/api/memory", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_v12_memories")
      .select("*")
      .eq("user_id", req.userId)
      .maybeSingle();

    if (error) throw error;

    res.json({
      memory: data ? data.memory : ""
    });

  } catch (error) {
    sendError(res, error, 500);
  }
});

app.put("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = String(req.body.memory || "");

    if (memory.length > 20000) {
      return res.status(400).json({
        error: "Mémoire trop longue."
      });
    }

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

    res.json({
      message: "Mémoire enregistrée.",
      memory
    });

  } catch (error) {
    sendError(res, error);
  }
});

app.delete("/api/memory", authenticate, async (req, res) => {
  try {
    const { error } = await supabase
      .from("taya_v12_memories")
      .delete()
      .eq("user_id", req.userId);

    if (error) throw error;

    res.json({
      message: "Mémoire supprimée."
    });

  } catch (error) {
    sendError(res, error);
  }
});

/* CHAT IA */

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    const messages = req.body.messages;

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        error: "Aucun message reçu."
      });
    }

    const { data: memoryData } = await supabase
      .from("taya_v12_memories")
      .select("memory")
      .eq("user_id", req.userId)
      .maybeSingle();

    const systemPrompt = `
Tu es TAYA IA V13, une intelligence artificielle créée par MARUCE SOLDADO en Guinée.

RÈGLES :
- Réponds directement à la question.
- Sois rapide, clair et précis.
- Réponds dans la langue utilisée par l'utilisateur.
- Ne commence pas par des salutations inutiles.
- Ne répète pas la question.
- Donne des explications détaillées uniquement lorsqu'elles sont nécessaires ou demandées.
- Aide en rédaction, traduction, programmation, calcul, apprentissage et recherche.
- N'invente jamais une information lorsque tu ne la connais pas.
- Respecte la sécurité et la vie privée.

Mémoire de l'utilisateur :
${memoryData?.memory || "Aucune mémoire enregistrée."}
`;

    const cleanMessages = messages
      .filter(m =>
        m &&
        ["user", "assistant"].includes(m.role) &&
        m.content !== undefined
      )
      .slice(-30);

    if (!cleanMessages.length) {
      return res.status(400).json({
        error: "Conversation vide."
      });
    }

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": process.env.APP_URL || "https://marucesoldado752-ux.github.io",
          "X-Title": "TAYA IA"
        },
        body: JSON.stringify({
          model: AI_MODEL,
          messages: [
            {
              role: "system",
              content: systemPrompt
            },
            ...cleanMessages
          ],
          temperature: 0.7
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error("OpenRouter:", result);
      return res.status(502).json({
        error: "Le service IA est temporairement indisponible."
      });
    }

    const answer = result.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        error: "L'IA n'a pas renvoyé de réponse."
      });
    }

    const lastUser = [...cleanMessages]
      .reverse()
      .find(m => m.role === "user");

    if (lastUser) {
      await supabase
        .from("taya_v12_messages")
        .insert([
          {
            user_id: req.userId,
            role: "user",
            message: typeof lastUser.content === "string"
              ? lastUser.content
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
      model: AI_MODEL
    });

  } catch (error) {
    sendError(res, error, 500);
  }
});

/* CONTACT MARUCE */

app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message || message.length > 5000) {
      return res.status(400).json({
        error: "Message vide ou trop long."
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
      message: "Message envoyé à Maruce."
    });

  } catch (error) {
    sendError(res, error);
  }
});

/* TABLEAU DE BORD ADMIN */

app.get(
  "/api/admin/dashboard",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const [usersResult, messagesResult, contactsResult] =
        await Promise.all([
          supabase
            .from("taya_v12_users")
            .select("id,full_name,phone,created_at")
            .order("created_at", { ascending: false }),

          supabase
            .from("taya_v12_messages")
            .select("*")
            .order("created_at", { ascending: false })
            .limit(100),

          supabase
            .from("taya_v12_contacts")
            .select("*")
            .order("created_at", { ascending: false })
            .limit(100)
        ]);

      if (usersResult.error) throw usersResult.error;
      if (messagesResult.error) throw messagesResult.error;
      if (contactsResult.error) throw contactsResult.error;

      res.json({
        totalUsers: usersResult.data.length,
        totalMessages: messagesResult.data.length,
        totalContacts: contactsResult.data.length,
        users: usersResult.data,
        messages: messagesResult.data,
        contacts: contactsResult.data
      });

    } catch (error) {
      sendError(res, error, 500);
    }
  }
);

/* ROUTE INCONNUE */

app.use((req, res) => {
  res.status(404).json({
    error: "Route introuvable."
  });
});

/* DÉMARRAGE */

app.listen(PORT, () => {
  console.log(`TAYA IA V${VERSION} démarré sur le port ${PORT}`);
});
