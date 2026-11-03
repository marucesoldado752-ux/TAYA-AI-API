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
const VERSION = "12.1.0";

const {
  OPENROUTER_API_KEY,
  AI_MODEL = "openai/gpt-4o-mini",
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET,
  TAYA_ADMIN_KEY
} = process.env;

const SUPABASE_KEY =
  SUPABASE_SECRET_KEY || SUPABASE_SERVICE_ROLE_KEY;

const supabase =
  SUPABASE_URL && SUPABASE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_KEY)
    : null;

app.set("trust proxy", 1);

app.use(helmet());

app.use(cors({
  origin: [
    "https://marucesoldado752-ux.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Admin-Key"
  ]
}));

app.use(express.json({ limit: "20mb" }));

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop de requêtes. Réessaie plus tard." }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Trop de tentatives. Réessaie dans 15 minutes."
  }
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop de tentatives administrateur." }
});

app.use("/api", generalLimiter);

function errorMessage(res, status, message) {
  return res.status(status).json({ error: message });
}

function checkConfiguration() {
  if (!supabase) {
    throw new Error("Configuration Supabase manquante");
  }

  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error("JWT_SECRET invalide");
  }
}

function normalizePhone(phone) {
  return String(phone || "").replace(/[^\d+]/g, "");
}

function validPhone(phone) {
  return /^\+[1-9]\d{6,14}$/.test(phone);
}

function validPassword(password) {
  if (typeof password !== "string") return false;

  const bytes = Buffer.byteLength(password, "utf8");

  return password.length >= 10 && bytes <= 72;
}

function createToken(user) {
  return jwt.sign(
    { userId: user.id },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function publicUser(user) {
  return {
    id: user.id,
    full_name: user.full_name,
    phone: user.phone,
    created_at: user.created_at
  };
}

function authenticate(req, res, next) {
  try {
    checkConfiguration();

    const authorization = req.headers.authorization || "";

    const token = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : "";

    if (!token) {
      return errorMessage(res, 401, "Connexion requise");
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded.userId) {
      return errorMessage(res, 401, "Session invalide");
    }

    req.userId = decoded.userId;

    next();

  } catch (error) {
    return errorMessage(res, 401, "Session invalide ou expirée");
  }
}

async function getUser(userId) {
  const { data, error } = await supabase
    .from("taya_v12_users")
    .select("*")
    .eq("id", userId)
    .single();

  if (error || !data) return null;

  return data;
}

// PAGE D'ACCUEIL
app.get("/", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online"
  });
});

// ÉTAT DU SERVEUR
app.get("/health", (req, res) => {
  res.json({
    name: "TAYA IA",
    version: VERSION,
    status: "online",
    aiConfigured: Boolean(OPENROUTER_API_KEY),
    supabaseConfigured: Boolean(supabase),
    model: AI_MODEL
  });
});

// INSCRIPTION SÉCURISÉE
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    checkConfiguration();

    const fullName = String(req.body.fullName || "").trim();
    const phone = normalizePhone(req.body.phone);
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;

    if (fullName.length < 2 || fullName.length > 80) {
      return errorMessage(res, 400, "Nom invalide");
    }

    if (!validPhone(phone)) {
      return errorMessage(res, 400, "Numéro de téléphone invalide");
    }

    if (!validPassword(password)) {
      return errorMessage(
        res,
        400,
        "Le mot de passe doit contenir au moins 10 caractères et respecter la limite autorisée"
      );
    }

    if (password !== confirmPassword) {
      return errorMessage(res, 400, "Les mots de passe ne correspondent pas");
    }

    const { data: existingUser, error: searchError } = await supabase
      .from("taya_v12_users")
      .select("id")
      .eq("phone", phone)
      .maybeSingle();

    if (searchError) throw searchError;

    if (existingUser) {
      return errorMessage(
        res,
        409,
        "Ce numéro possède déjà un compte. Connecte-toi."
      );
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data: user, error } = await supabase
      .from("taya_v12_users")
      .insert({
        full_name: fullName,
        phone,
        password_hash: passwordHash
      })
      .select("*")
      .single();

    if (error) {
      if (error.code === "23505") {
        return errorMessage(res, 409, "Ce numéro est déjà utilisé");
      }

      throw error;
    }

    res.status(201).json({
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("REGISTER:", error.message);
    errorMessage(res, 500, "Impossible de créer le compte");
  }
});

// CONNEXION SÉCURISÉE
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    checkConfiguration();

    const phone = normalizePhone(req.body.phone);
    const password = req.body.password;

    if (!validPhone(phone) || typeof password !== "string") {
      return errorMessage(res, 400, "Identifiants invalides");
    }

    const { data: user, error } = await supabase
      .from("taya_v12_users")
      .select("*")
      .eq("phone", phone)
      .maybeSingle();

    if (error) throw error;

    if (!user || !user.password_hash) {
      return errorMessage(res, 401, "Numéro ou mot de passe incorrect");
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return errorMessage(res, 401, "Numéro ou mot de passe incorrect");
    }

    res.json({
      token: createToken(user),
      user: publicUser(user)
    });

  } catch (error) {
    console.error("LOGIN:", error.message);
    errorMessage(res, 500, "Impossible de se connecter");
  }
});

// AJOUTER UN MOT DE PASSE À UN ANCIEN COMPTE
// Cette route exige une ancienne session valide.
app.post("/api/auth/set-password", authenticate, async (req, res) => {
  try {
    const password = req.body.password;
    const confirmPassword = req.body.confirmPassword;

    if (!validPassword(password)) {
      return errorMessage(
        res,
        400,
        "Le mot de passe doit contenir au moins 10 caractères"
      );
    }

    if (password !== confirmPassword) {
      return errorMessage(res, 400, "Les mots de passe ne correspondent pas");
    }

    const user = await getUser(req.userId);

    if (!user) {
      return errorMessage(res, 404, "Compte introuvable");
    }

    if (user.password_hash) {
      return errorMessage(res, 409, "Un mot de passe existe déjà");
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data, error } = await supabase
      .from("taya_v12_users")
      .update({ password_hash: passwordHash })
      .eq("id", req.userId)
      .is("password_hash", null)
      .select("id")
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return errorMessage(
        res,
        409,
        "Le mot de passe a déjà été configuré"
      );
    }

    res.json({
      success: true,
      message: "Mot de passe configuré avec succès"
    });

  } catch (error) {
    console.error("SET PASSWORD:", error.message);
    errorMessage(res, 500, "Impossible de configurer le mot de passe");
  }
});

// CHANGER LE MOT DE PASSE
app.post("/api/auth/change-password", authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    const user = await getUser(req.userId);

    if (!user || !user.password_hash) {
      return errorMessage(res, 400, "Compte non configuré");
    }

    const matches = await bcrypt.compare(
      currentPassword || "",
      user.password_hash
    );

    if (!matches) {
      return errorMessage(res, 401, "Mot de passe actuel incorrect");
    }

    if (!validPassword(newPassword)) {
      return errorMessage(
        res,
        400,
        "Le nouveau mot de passe doit contenir au moins 10 caractères"
      );
    }

    if (newPassword !== confirmPassword) {
      return errorMessage(res, 400, "Les mots de passe ne correspondent pas");
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    const { error } = await supabase
      .from("taya_v12_users")
      .update({ password_hash: passwordHash })
      .eq("id", req.userId);

    if (error) throw error;

    res.json({
      success: true,
      message: "Mot de passe modifié"
    });

  } catch (error) {
    console.error("CHANGE PASSWORD:", error.message);
    errorMessage(res, 500, "Impossible de modifier le mot de passe");
  }
});

// PROFIL
app.get("/api/profile", authenticate, async (req, res) => {
  try {
    const user = await getUser(req.userId);

    if (!user) {
      return errorMessage(res, 404, "Utilisateur introuvable");
    }

    res.json({ user: publicUser(user) });

  } catch (error) {
    console.error("PROFILE:", error.message);
    errorMessage(res, 500, "Erreur du profil");
  }
});

// MODIFIER LE NOM
app.put("/api/profile/name", authenticate, async (req, res) => {
  try {
    const { currentName, newName, confirmName } = req.body;

    const user = await getUser(req.userId);

    if (!user) {
      return errorMessage(res, 404, "Utilisateur introuvable");
    }

    const cleanName = String(newName || "").trim();

    if (
      currentName !== user.full_name ||
      cleanName.length < 2 ||
      cleanName.length > 80 ||
      cleanName !== String(confirmName || "").trim()
    ) {
      return errorMessage(res, 400, "Vérification du nom incorrecte");
    }

    const { data, error } = await supabase
      .from("taya_v12_users")
      .update({ full_name: cleanName })
      .eq("id", req.userId)
      .select("*")
      .single();

    if (error) throw error;

    res.json({ user: publicUser(data) });

  } catch (error) {
    console.error("NAME:", error.message);
    errorMessage(res, 500, "Impossible de modifier le nom");
  }
});

// MODIFIER LE NUMÉRO
app.put("/api/profile/phone", authenticate, async (req, res) => {
  try {
    const { currentPhone, newPhone, confirmPhone } = req.body;

    const user = await getUser(req.userId);

    if (!user) {
      return errorMessage(res, 404, "Utilisateur introuvable");
    }

    const phone = normalizePhone(newPhone);

    if (
      currentPhone !== user.phone ||
      phone !== normalizePhone(confirmPhone) ||
      !validPhone(phone)
    ) {
      return errorMessage(res, 400, "Vérification du numéro incorrecte");
    }

    const { data, error } = await supabase
      .from("taya_v12_users")
      .update({ phone })
      .eq("id", req.userId)
      .select("*")
      .single();

    if (error) {
      if (error.code === "23505") {
        return errorMessage(res, 409, "Ce numéro est déjà utilisé");
      }

      throw error;
    }

    res.json({ user: publicUser(data) });

  } catch (error) {
    console.error("PHONE:", error.message);
    errorMessage(res, 500, "Impossible de modifier le numéro");
  }
});

// MÉMOIRE : LIRE
app.get("/api/memory", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("taya_v12_memories")
      .select("memory")
      .eq("user_id", req.userId)
      .maybeSingle();

    if (error) throw error;

    res.json({
      memory: data?.memory || ""
    });

  } catch (error) {
    console.error("MEMORY GET:", error.message);
    errorMessage(res, 500, "Impossible de charger la mémoire");
  }
});

// MÉMOIRE : ENREGISTRER
app.put("/api/memory", authenticate, async (req, res) => {
  try {
    const memory = String(req.body.memory || "");

    if (memory.length > 20000) {
      return errorMessage(res, 400, "Mémoire trop longue");
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
      success: true,
      message: "Mémoire enregistrée"
    });

  } catch (error) {
    console.error("MEMORY PUT:", error.message);
    errorMessage(res, 500, "Impossible d'enregistrer la mémoire");
  }
});

// MÉMOIRE : EFFACER
app.delete("/api/memory", authenticate, async (req, res) => {
  try {
    const { error } = await supabase
      .from("taya_v12_memories")
      .delete()
      .eq("user_id", req.userId);

    if (error) throw error;

    res.json({
      success: true,
      message: "Mémoire effacée"
    });

  } catch (error) {
    console.error("MEMORY DELETE:", error.message);
    errorMessage(res, 500, "Impossible d'effacer la mémoire");
  }
});

// DISCUSSION AVEC TAYA IA
app.post("/api/chat", authenticate, async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return errorMessage(res, 503, "Intelligence artificielle non configurée");
    }

    const messages = req.body.messages;

    if (!Array.isArray(messages) || messages.length === 0) {
      return errorMessage(res, 400, "Aucun message reçu");
    }

    if (messages.length > 30) {
      return errorMessage(res, 400, "Conversation trop longue");
    }

    const { data: memoryData } = await supabase
      .from("taya_v12_memories")
      .select("memory")
      .eq("user_id", req.userId)
      .maybeSingle();

    const memory = memoryData?.memory || "";

    const systemPrompt = `
Tu es TAYA IA V12, un assistant intelligent créé par Maruce en Guinée.

Tu réponds avec intelligence, rapidité et précision.

RÈGLES :
- Réponds dans la langue de l'utilisateur.
- Donne des réponses exactes, utiles et naturelles.
- Explique clairement lorsque c'est nécessaire.
- Aide pour les études, les sciences, les mathématiques,
  la technologie, la programmation, la rédaction et la culture.
- Ne prétends jamais avoir effectué une action que tu n'as pas faite.
- Si tu ne connais pas une information, dis-le honnêtement.
- Ne fabrique pas de sources ni de faits.
- Sois direct et évite les introductions inutiles.

MÉMOIRE DE L'UTILISATEUR :
${memory || "Aucune information personnelle enregistrée."}
`;

    const cleanMessages = messages
      .filter(m =>
        m &&
        ["user", "assistant"].includes(m.role) &&
        m.content !== undefined
      )
      .map(m => ({
        role: m.role,
        content: m.content
      }));

    if (!cleanMessages.length) {
      return errorMessage(res, 400, "Messages invalides");
    }

    const controller = new AbortController();

    const timeout = setTimeout(
      () => controller.abort(),
      110000
    );

    let response;

    try {
      response = await fetch(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${OPENROUTER_API_KEY}`,
            "Content-Type": "application/json",
            "HTTP-Referer": "https://marucesoldado752-ux.github.io",
            "X-Title": "TAYA IA"
          },
          body: JSON.stringify({
            model: AI_MODEL,
            messages: [
              { role: "system", content: systemPrompt },
              ...cleanMessages
            ],
            temperature: 0.7,
            max_tokens: 4000
          }),
          signal: controller.signal
        }
      );
    } finally {
      clearTimeout(timeout);
    }

    const result = await response.json();

    if (!response.ok) {
      console.error("OPENROUTER:", response.status);
      return errorMessage(
        res,
        502,
        "Le service IA est momentanément indisponible"
      );
    }

    const answer = result.choices?.[0]?.message?.content;

    if (!answer) {
      return errorMessage(res, 502, "Aucune réponse reçue de l'IA");
    }

    const lastUserMessage = [...cleanMessages]
      .reverse()
      .find(m => m.role === "user");

    const rows = [];

    if (lastUserMessage) {
      let messageText = "";

      if (typeof lastUserMessage.content === "string") {
        messageText = lastUserMessage.content;
      } else if (Array.isArray(lastUserMessage.content)) {
        messageText = lastUserMessage.content
          .filter(part => part && part.type === "text")
          .map(part => part.text || "")
          .join("\n");
      }

      rows.push({
        user_id: req.userId,
        role: "user",
        message: messageText.slice(0, 20000) ||
          "[Message multimodal]"
      });
    }

    rows.push({
      user_id: req.userId,
      role: "assistant",
      message: String(answer).slice(0, 20000)
    });

    const { error: saveError } = await supabase
      .from("taya_v12_messages")
      .insert(rows);

    if (saveError) {
      console.error("MESSAGE SAVE:", saveError.message);
    }

    res.json({
      answer,
      model: AI_MODEL,
      memoryEnabled: true
    });

  } catch (error) {
    console.error("CHAT:", error.message);

    if (error.name === "AbortError") {
      return errorMessage(res, 504, "Le délai de réponse est dépassé");
    }

    errorMessage(res, 500, "Une erreur est survenue pendant la discussion");
  }
});

// MESSAGE AU SUPPORT
app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message || message.length > 5000) {
      return errorMessage(res, 400, "Message invalide");
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
    errorMessage(res, 500, "Impossible d'envoyer le message");
  }
});

// TABLEAU DE BORD ADMINISTRATEUR
app.get("/api/admin/dashboard", adminLimiter, async (req, res) => {
  try {
    checkConfiguration();

    if (
      !TAYA_ADMIN_KEY ||
      req.headers["x-admin-key"] !== TAYA_ADMIN_KEY
    ) {
      return errorMessage(res, 403, "Accès administrateur refusé");
    }

    const [
      usersResult,
      messagesResult,
      userCount,
      messageCount
    ] = await Promise.all([
      supabase
        .from("taya_v12_users")
        .select("full_name,phone,created_at")
        .order("created_at", { ascending: false })
        .limit(100),

      supabase
        .from("taya_v12_contacts")
        .select("message,user_id,created_at")
        .order("created_at", { ascending: false })
        .limit(100),

      supabase
        .from("taya_v12_users")
        .select("*", { count: "exact", head: true }),

      supabase
        .from("taya_v12_messages")
        .select("*", { count: "exact", head: true })
    ]);

    if (usersResult.error) throw usersResult.error;
    if (messagesResult.error) throw messagesResult.error;
    if (userCount.error) throw userCount.error;
    if (messageCount.error) throw messageCount.error;

    res.json({
      totalUsers: userCount.count || 0,
      totalMessages: messageCount.count || 0,
      users: usersResult.data || [],
      messages: messagesResult.data || []
    });

  } catch (error) {
    console.error("ADMIN:", error.message);
    errorMessage(res, 500, "Erreur du tableau de bord");
  }
});

// ROUTE INCONNUE
app.use((req, res) => {
  res.status(404).json({
    error: "Route introuvable"
  });
});

// ERREURS GÉNÉRALES
app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error.message);

  if (res.headersSent) return next(error);

  res.status(500).json({
    error: "Une erreur interne est survenue"
  });
});

// DÉMARRAGE
app.listen(PORT, () => {
  console.log(`TAYA IA V${VERSION} démarré sur le port ${PORT}`);
});
