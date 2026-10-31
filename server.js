require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// =====================================
// TAYA IA V12.0.0
// =====================================

const VERSION = "12.0.0";
const PORT = process.env.PORT || 3000;

const API_KEY = process.env.OPENROUTER_API_KEY;
const MODEL = process.env.AI_MODEL || "openai/gpt-4o-mini";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const ADMIN_KEY = process.env.TAYA_ADMIN_KEY;

const MAX_MEMORY = 8000;

// IMPORTANT : configuration du proxy Render
app.set("trust proxy", 1);

app.use(helmet());

app.use(cors({
  origin: [
    "https://marucesoldado752-ux.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
  ]
}));

app.use(express.json({ limit: "15mb" }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Trop de demandes. Réessaie plus tard."
  }
}));

// =====================================
// CONFIGURATION SUPABASE
// =====================================

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error("ERREUR : configuration Supabase manquante.");
  process.exit(1);
}

if (!ADMIN_KEY) {
  console.error("ERREUR : TAYA_ADMIN_KEY manquante.");
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

console.log("Supabase connecté");

// =====================================
// IDENTITÉ TAYA IA
// =====================================

const SYSTEM_PROMPT = `
Tu es TAYA IA 🇬🇳, un assistant intelligent créé par Maruce en Guinée.

Tu es un assistant polyvalent qui aide les utilisateurs dans leurs questions.

RÈGLES :
- Réponds directement à la question.
- Sois intelligent, rapide, naturel et précis.
- Comprends le contexte de la conversation.
- Explique clairement les sujets difficiles.
- Aide en programmation, technologie, sciences et études.
- Aide à écrire, traduire, corriger et créer.
- Ne fabrique jamais des faits.
- Ne prétends jamais avoir effectué une action que tu n'as pas réalisée.
- Respecte les consignes de format de l'utilisateur.
- Réponds en français par défaut.
- Utilise la mémoire lorsqu'elle est disponible.
- Ne prétends jamais connaître une information absente.

Tu es TAYA IA.
`;

// =====================================
// OUTILS
// =====================================

function normalizeName(name) {
  return String(name || "")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();
}

function normalizePhone(phone) {
  return String(phone || "")
    .replace(/[^\d+]/g, "");
}

function validName(name) {
  return typeof name === "string" &&
    name.trim().length >= 2 &&
    name.trim().length <= 60;
}

function validPhone(phone) {
  return typeof phone === "string" &&
    /^\+[1-9]\d{6,14}$/.test(phone);
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    created_at: user.created_at
  };
}

// =====================================
// AUTHENTIFICATION
// =====================================

async function authenticate(req, res, next) {
  try {
    const authorization = req.headers.authorization || "";

    const token = authorization.startsWith("Bearer ")
      ? authorization.slice(7).trim()
      : "";

    if (!/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(401).json({
        error: "Session invalide. Reconnecte-toi."
      });
    }

    const tokenHash = hashToken(token);

    const { data: session, error } = await supabase
      .from("taya_sessions")
      .select("user_id, expires_at")
      .eq("token_hash", tokenHash)
      .maybeSingle();

    if (error || !session) {
      return res.status(401).json({
        error: "Session introuvable."
      });
    }

    if (new Date(session.expires_at) < new Date()) {
      await supabase
        .from("taya_sessions")
        .delete()
        .eq("token_hash", tokenHash);

      return res.status(401).json({
        error: "Session expirée."
      });
    }

    const { data: user, error: userError } = await supabase
      .from("taya_users")
      .select("*")
      .eq("id", session.user_id)
      .maybeSingle();

    if (userError || !user) {
      return res.status(401).json({
        error: "Utilisateur introuvable."
      });
    }

    req.user = user;
    req.tokenHash = tokenHash;

    next();

  } catch (error) {
    console.error("Authentification :", error.message);

    return res.status(500).json({
      error: "Erreur d'authentification."
    });
  }
}

// =====================================
// OPENROUTER
// =====================================

async function callAI(messages) {
  if (!API_KEY) {
    throw new Error("OPENROUTER_API_KEY manquante.");
  }

  const response = await fetch(
    "https://openrouter.ai/api/v1/chat/completions",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${API_KEY}`,
        "Content-Type": "application/json",
        "X-OpenRouter-Title": "TAYA IA V12"
      },
      body: JSON.stringify({
        model: MODEL,
        messages,
        temperature: 0.7,
        max_tokens: 3000
      }),
      signal: AbortSignal.timeout(90000)
    }
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("OpenRouter :", data);

    throw new Error(
      data.error?.message || "Erreur du moteur IA."
    );
  }

  const answer = data.choices?.[0]?.message?.content;

  if (Array.isArray(answer)) {
    return {
      answer: answer
        .filter(item => item.type === "text")
        .map(item => item.text || "")
        .join("\n"),
      model: data.model || MODEL
    };
  }

  if (typeof answer !== "string" || !answer.trim()) {
    throw new Error("Réponse IA vide.");
  }

  return {
    answer: answer.trim(),
    model: data.model || MODEL
  };
}

// =====================================
// PAGE PRINCIPALE
// =====================================

app.get("/", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online",
    creator: "Maruce",
    country: "Guinée 🇬🇳",
    memory: true,
    intelligentMemory: true,
    memoryManagement: true,
    webSearch: false,
    optimized: true
  });
});

// =====================================
// SANTÉ DU SERVEUR
// =====================================

app.get("/health", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.json({
    status: "OK",
    version: VERSION,
    memory: true,
    intelligentMemory: true,
    memoryManagement: true,
    webSearch: false,
    optimized: true
  });
});

// =====================================
// INSCRIPTION
// =====================================

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const phone = normalizePhone(req.body.phone);

    if (!validName(name)) {
      return res.status(400).json({
        error: "Nom invalide. Minimum 2 caractères."
      });
    }

    if (!validPhone(phone)) {
      return res.status(400).json({
        error: "Numéro international invalide."
      });
    }

    const nameNormalized = normalizeName(name);
    const phoneNormalized = normalizePhone(phone);

    const { data: existingPhone } = await supabase
      .from("taya_users")
      .select("id")
      .eq("phone_normalized", phoneNormalized)
      .maybeSingle();

    if (existingPhone) {
      return res.status(409).json({
        error: "Ce numéro possède déjà un compte."
      });
    }

    const { data: existingName } = await supabase
      .from("taya_users")
      .select("id")
      .eq("name_normalized", nameNormalized)
      .maybeSingle();

    if (existingName) {
      return res.status(409).json({
        error: "Ce nom est déjà utilisé."
      });
    }

    const { data: user, error } = await supabase
      .from("taya_users")
      .insert({
        name,
        phone,
        name_normalized: nameNormalized,
        phone_normalized: phoneNormalized
      })
      .select()
      .single();

    if (error) {
      console.error("Inscription :", error);

      if (error.code === "23505") {
        return res.status(409).json({
          error: "Ce nom ou ce numéro est déjà utilisé."
        });
      }

      throw error;
    }

    const token = createToken();
    const tokenHash = hashToken(token);

    const expiresAt = new Date(
      Date.now() + 365 * 24 * 60 * 60 * 1000
    ).toISOString();

    const { error: sessionError } = await supabase
      .from("taya_sessions")
      .insert({
        user_id: user.id,
        token_hash: tokenHash,
        expires_at: expiresAt
      });

    if (sessionError) {
      await supabase
        .from("taya_users")
        .delete()
        .eq("id", user.id);

      throw sessionError;
    }

    return res.status(201).json({
      success: true,
      token,
      user: publicUser(user),
      version: VERSION
    });

  } catch (error) {
    console.error("Register :", error);

    return res.status(500).json({
      error: "Impossible de créer le compte."
    });
  }
});

// =====================================
// PROFIL
// =====================================

app.get("/api/profile", authenticate, (req, res) => {
  res.json({
    success: true,
    user: publicUser(req.user)
  });
});

// =====================================
// CHANGER LE NOM
// =====================================

app.put("/api/profile/name", authenticate, async (req, res) => {
  try {
    const currentName = String(req.body.currentName || "").trim();
    const newName = String(req.body.newName || "").trim();
    const confirmName = String(req.body.confirmName || "").trim();

    if (normalizeName(currentName) !== normalizeName(req.user.name)) {
      return res.status(400).json({
        error: "Le nom actuel est incorrect."
      });
    }

    if (!validName(newName) || newName !== confirmName) {
      return res.status(400).json({
        error: "Les deux nouveaux noms doivent être identiques."
      });
    }

    const normalized = normalizeName(newName);

    const { data: existing } = await supabase
      .from("taya_users")
      .select("id")
      .eq("name_normalized", normalized)
      .neq("id", req.user.id)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({
        error: "Ce nom est déjà utilisé."
      });
    }

    const { data, error } = await supabase
      .from("taya_users")
      .update({
        name: newName,
        name_normalized: normalized,
        updated_at: new Date().toISOString()
      })
      .eq("id", req.user.id)
      .select()
      .single();

    if (error) throw error;

    res.json({
      success: true,
      user: publicUser(data)
    });

  } catch (error) {
    console.error("Modification nom :", error);

    res.status(500).json({
      error: "Impossible de modifier le nom."
    });
  }
});

// =====================================
// CHANGER LE NUMÉRO
// =====================================

app.put("/api/profile/phone", authenticate, async (req, res) => {
  try {
    const currentPhone = normalizePhone(req.body.currentPhone);
    const newPhone = normalizePhone(req.body.newPhone);
    const confirmPhone = normalizePhone(req.body.confirmPhone);

    if (currentPhone !== normalizePhone(req.user.phone)) {
      return res.status(400).json({
        error: "Le numéro actuel est incorrect."
      });
    }

    if (!validPhone(newPhone) || newPhone !== confirmPhone) {
      return res.status(400).json({
        error: "Les deux nouveaux numéros doivent être identiques."
      });
    }

    const { data: existing } = await supabase
      .from("taya_users")
      .select("id")
      .eq("phone_normalized", newPhone)
      .neq("id", req.user.id)
      .maybeSingle();

    if (existing) {
      return res.status(409).json({
        error: "Ce numéro est déjà utilisé."
      });
    }

    const { data, error } = await supabase
      .from("taya_users")
      .update({
        phone: newPhone,
        phone_normalized: newPhone,
        updated_at: new Date().toISOString()
      })
      .eq("id", req.user.id)
      .select()
      .single();

    if (error) throw error;

    res.json({
      success: true,
      user: publicUser(data)
    });

  } catch (error) {
    console.error("Modification numéro :", error);

    res.status(500).json({
      error: "Impossible de modifier le numéro."
    });
  }
});

// =====================================
// DÉCONNEXION
// =====================================

app.post("/api/logout", authenticate, async (req, res) => {
  try {
    await supabase
      .from("taya_sessions")
      .delete()
      .eq("token_hash", req.tokenHash);

    res.json({
      success: true,
      message: "Déconnexion réussie."
    });

  } catch (error) {
    res.status(500).json({
      error: "Erreur pendant la déconnexion."
    });
  }
});

// =====================================
// MÉMOIRE
// =====================================

app.get("/api/memory", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_memories")
      .select("memory, updated_at")
      .eq("user_id", req.user.id)
      .maybeSingle();

    if (error) throw error;

    res.json({
      success: true,
      memory: data?.memory || "",
      updatedAt: data?.updated_at || null
    });

  } catch (error) {
    console.error("Lecture mémoire :", error);

    res.status(500).json({
      error: "Impossible de lire la mémoire."
    });
  }
});

app.put("/api/memory", authenticate, async (req, res) => {
  try {
    if (typeof req.body.memory !== "string") {
      return res.status(400).json({
        error: "Mémoire invalide."
      });
    }

    const memory = req.body.memory.trim();

    if (memory.length > MAX_MEMORY) {
      return res.status(413).json({
        error: "Mémoire trop longue."
      });
    }

    const { error } = await supabase
      .from("taya_memories")
      .upsert({
        user_id: req.user.id,
        memory,
        updated_at: new Date().toISOString()
      }, {
        onConflict: "user_id"
      });

    if (error) throw error;

    res.json({
      success: true,
      message: "Mémoire sauvegardée."
    });

  } catch (error) {
    console.error("Sauvegarde mémoire :", error);

    res.status(500).json({
      error: "Impossible de sauvegarder la mémoire."
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
      success: true,
      message: "Mémoire effacée."
    });

  } catch (error) {
    console.error("Suppression mémoire :", error);

    res.status(500).json({
      error: "Impossible d'effacer la mémoire."
    });
  }
});

// =====================================
// DISCUSSION IA
// =====================================

app.post("/api/chat", authenticate, async (req, res) => {
  try {
    const messages = req.body.messages;

    if (!Array.isArray(messages) || !messages.length) {
      return res.status(400).json({
        error: "Aucun message reçu."
      });
    }

    if (messages.length > 40) {
      return res.status(400).json({
        error: "Conversation trop longue."
      });
    }

    const safeMessages = messages
      .filter(message =>
        message &&
        ["user", "assistant"].includes(message.role) &&
        (
          typeof message.content === "string" ||
          Array.isArray(message.content)
        )
      )
      .map(message => ({
        role: message.role,
        content: message.content
      }));

    if (
      !safeMessages.length ||
      safeMessages[safeMessages.length - 1].role !== "user"
    ) {
      return res.status(400).json({
        error: "Message utilisateur manquant."
      });
    }

    const { data: memoryData } = await supabase
      .from("taya_memories")
      .select("memory")
      .eq("user_id", req.user.id)
      .maybeSingle();

    const memory = memoryData?.memory || "";

    const systemMessages = [
      {
        role: "system",
        content: SYSTEM_PROMPT
      }
    ];

    if (memory) {
      systemMessages.push({
        role: "system",
        content: "Mémoire utile de cet utilisateur :\n" + memory
      });
    }

    const result = await callAI([
      ...systemMessages,
      ...safeMessages
    ]);

    res.json({
      success: true,
      answer: result.answer,
      reply: result.answer,
      model: result.model,
      memoryEnabled: true,
      intelligentMemory: true,
      memoryManagement: true,
      version: VERSION
    });

  } catch (error) {
    console.error("Erreur discussion :", error);

    res.status(500).json({
      error: "TAYA IA n'a pas pu répondre. Réessaie."
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
        error: "Message invalide."
      });
    }

    const { error } = await supabase
      .from("taya_contact_messages")
      .insert({
        user_id: req.user.id,
        name: req.user.name,
        phone: req.user.phone,
        message
      });

    if (error) throw error;

    res.json({
      success: true,
      message: "Message envoyé."
    });

  } catch (error) {
    console.error("Contact :", error);

    res.status(500).json({
      error: "Impossible d'envoyer le message."
    });
  }
});

// =====================================
// TABLEAU DE BORD ADMINISTRATEUR
// =====================================

app.get("/api/admin/dashboard", async (req, res) => {
  try {
    const suppliedKey = req.headers["x-admin-key"];

    if (
      typeof suppliedKey !== "string" ||
      suppliedKey.length !== ADMIN_KEY.length ||
      !crypto.timingSafeEqual(
        Buffer.from(suppliedKey),
        Buffer.from(ADMIN_KEY)
      )
    ) {
      return res.status(403).json({
        error: "Accès administrateur refusé."
      });
    }

    const { data: users, error: usersError } = await supabase
      .from("taya_users")
      .select("id, name, phone, created_at")
      .order("created_at", { ascending: false });

    if (usersError) throw usersError;

    const { data: contacts, error: contactsError } = await supabase
      .from("taya_contact_messages")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(200);

    if (contactsError) throw contactsError;

    res.json({
      success: true,
      users: users || [],
      contacts: contacts || [],
      totalUsers: users?.length || 0,
      version: VERSION
    });

  } catch (error) {
    console.error("Dashboard admin :", error);

    res.status(500).json({
      error: "Impossible de charger le tableau de bord."
    });
  }
});

// =====================================
// ROUTES INCONNUES
// =====================================

app.use((req, res) => {
  res.status(404).json({
    error: "Route introuvable."
  });
});

// =====================================
// ERREURS
// =====================================

app.use((error, req, res, next) => {
  console.error("Erreur serveur :", error);

  res.status(500).json({
    error: "Erreur interne du serveur."
  });
});

// =====================================
// DÉMARRAGE RENDER
// =====================================

app.listen(PORT, "0.0.0.0", () => {
  console.log("--------------------------------");
  console.log("TAYA IA V12.0.0 🇬🇳");
  console.log("Serveur : ONLINE");
  console.log("Port :", PORT);
  console.log("Supabase : CONNECTÉ");
  console.log("Authentification : ACTIVÉE");
  console.log("Mémoire : ACTIVÉE");
  console.log("Créateur : Maruce");
  console.log("--------------------------------");
});
