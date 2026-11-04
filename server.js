require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const PORT = process.env.PORT || 10000;
const APP_URL = process.env.APP_URL || 'https://taya-ai-api.onrender.com';

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const TAYA_ADMIN_KEY = process.env.TAYA_ADMIN_KEY;

const SUPABASE_URL = process.env.SUPABASE_URL;

const SUPABASE_KEY =
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_KEY ||
  process.env.SUPABASE_ANON_KEY;

const AI_MODEL =
  process.env.OPENROUTER_MODEL ||
  'meta-llama/llama-3.1-8b-instruct:free';

// ======================================
// CONFIGURATION
// ======================================

app.use(helmet({
  crossOriginResourcePolicy: false
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN
    ? process.env.ALLOWED_ORIGIN.split(',')
    : true
}));

app.use(express.json({ limit: '10mb' }));

app.use('/api/', rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

// ======================================
// SUPABASE
// ======================================

let supabase = null;

if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

  console.log('✅ Supabase configuré');
} else {
  console.error('❌ Configuration Supabase manquante');
}

// ======================================
// ADMINISTRATEURS AUTORISÉS
// ======================================

function normalizePhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

const ADMIN_PHONES = [
  '224663401157',
  '224612768878'
];

async function isAuthorizedAdmin(phone) {
  const normalized = normalizePhone(phone);

  if (ADMIN_PHONES.includes(normalized)) {
    return true;
  }

  if (!supabase) return false;

  try {
    const { data, error } = await supabase
      .from('admin_whitelist')
      .select('phone, numero');

    if (error) {
      console.error('Erreur whitelist:', error.message);
      return false;
    }

    return (data || []).some(row =>
      normalizePhone(row.phone) === normalized ||
      normalizePhone(row.numero) === normalized
    );

  } catch (error) {
    console.error('Whitelist:', error.message);
    return false;
  }
}

// ======================================
// SYSTEM PROMPT TAYA IA
// ======================================

const systemPrompt = `
Tu es TAYA IA V13, une intelligence artificielle développée par
Maruce Soldado, en Guinée.

TES RÈGLES :

1. Réponds directement à la question.
2. Utilise un français naturel, clair et correct.
3. Évite les longues introductions inutiles.
4. Ne répète pas la question de l'utilisateur.
5. Explique les sujets difficiles simplement.
6. Aide en programmation, mathématiques, sciences,
   technologie, rédaction et traduction.
7. Aide à analyser les problèmes et à trouver des solutions.
8. Si tu ne connais pas une réponse, sois honnête.
9. N'invente jamais des informations.
10. Adapte la longueur de la réponse à la demande.
11. Respecte le contexte des conversations précédentes.
12. Tu es TAYA IA, pas ChatGPT.

Ton objectif est de fournir des réponses utiles,
précises et rapides.
`;

// ======================================
// PAGE PRINCIPALE
// ======================================

app.get('/', (req, res) => {
  res.json({
    success: true,
    name: 'TAYA IA',
    version: '13.0.0',
    status: 'online',
    supabase: !!supabase,
    artificial_intelligence: !!OPENROUTER_API_KEY
  });
});

// ======================================
// VÉRIFICATION DU SERVEUR
// ======================================

app.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    version: '13.0.0',
    timestamp: new Date().toISOString()
  });
});

// ======================================
// ACTIVATION ADMINISTRATEUR
// ======================================

app.post('/api/admin/activate', async (req, res) => {
  try {
    const body = req.body || {};

    const adminKey =
      body.adminKey ||
      body.cleAdmin ||
      body.cle_administrateur ||
      body.key;

    const fullName =
      body.fullName ||
      body.nomComplet ||
      body.name ||
      body.nom;

    const phone =
      body.phone ||
      body.numeroAutorise ||
      body.numero ||
      body.numero_autorise;

    const password =
      body.password ||
      body.nouveauMotDePasse ||
      body.motDePasse ||
      body.nouveau_mot_de_passe;

    if (!adminKey || !fullName || !phone || !password) {
      return res.status(400).json({
        success: false,
        error: 'Tous les champs sont obligatoires'
      });
    }

    if (!TAYA_ADMIN_KEY) {
      return res.status(500).json({
        success: false,
        error: 'TAYA_ADMIN_KEY manquant sur Render'
      });
    }

    if (adminKey !== TAYA_ADMIN_KEY) {
      return res.status(403).json({
        success: false,
        error: 'Clé administrateur incorrecte'
      });
    }

    if (!supabase) {
      return res.status(503).json({
        success: false,
        error: 'Supabase non configuré'
      });
    }

    const normalized = normalizePhone(phone);

    if (!await isAuthorizedAdmin(normalized)) {
      return res.status(403).json({
        success: false,
        error: 'Ce numéro n’est pas autorisé'
      });
    }

    // La table admins actuelle contient uniquement phone et created_at.
    // On ne tente donc pas d'y enregistrer des colonnes inexistantes.

    const { data: existing, error: searchError } = await supabase
      .from('admins')
      .select('phone')
      .eq('phone', normalized)
      .maybeSingle();

    if (searchError) throw searchError;

    if (!existing) {
      const { error: insertError } = await supabase
        .from('admins')
        .insert({
          phone: normalized,
          created_at: new Date().toISOString()
        });

      if (insertError) throw insertError;
    }

    return res.json({
      success: true,
      message: 'Numéro administrateur autorisé',
      admin: {
        phone: normalized,
        fullName
      },
      note: 'La configuration du mot de passe administrateur doit être gérée par un système d’authentification sécurisé.'
    });

  } catch (error) {
    console.error('ADMIN ERROR:', error.message);

    return res.status(500).json({
      success: false,
      error: 'Erreur lors de l’activation administrateur'
    });
  }
});

// Routes compatibles avec les anciennes versions.

app.post('/api/activate-admin', (req, res, next) => {
  req.url = '/api/admin/activate';
  next();
});

app.post('/api/admin/activation', (req, res, next) => {
  req.url = '/api/admin/activate';
  next();
});

// ======================================
// INTELLIGENCE ARTIFICIELLE
// ======================================

app.post('/api/chat', async (req, res) => {
  try {
    if (!OPENROUTER_API_KEY) {
      return res.status(503).json({
        success: false,
        error: 'OPENROUTER_API_KEY manquant sur Render'
      });
    }

    const body = req.body || {};

    let messages = body.messages;

    if (!Array.isArray(messages) && body.message) {
      messages = [
        {
          role: 'user',
          content: body.message
        }
      ];
    }

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Message manquant'
      });
    }

    const validMessages = messages
      .filter(item =>
        item &&
        ['user', 'assistant'].includes(item.role) &&
        typeof item.content === 'string' &&
        item.content.trim().length > 0
      )
      .slice(-12)
      .map(item => ({
        role: item.role,
        content: item.content.slice(0, 12000)
      }));

    if (!validMessages.length) {
      return res.status(400).json({
        success: false,
        error: 'Aucun message valide'
      });
    }

    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, 45000);

    let response;

    try {
      response = await fetch(
        'https://openrouter.ai/api/v1/chat/completions',
        {
          method: 'POST',

          headers: {
            'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
            'Content-Type': 'application/json',
            'HTTP-Referer': APP_URL,
            'X-Title': 'TAYA IA V13'
          },

          body: JSON.stringify({
            model: AI_MODEL,

            messages: [
              {
                role: 'system',
                content: systemPrompt
              },
              ...validMessages
            ],

            temperature: 0.7,
            max_tokens: 1500
          }),

          signal: controller.signal
        }
      );

    } finally {
      clearTimeout(timeout);
    }

    const result = await response.json();

    if (!response.ok) {
      console.error('OPENROUTER ERROR:', result);

      return res.status(502).json({
        success: false,
        error: 'Le service IA est temporairement indisponible',
        details: result?.error?.message || 'Erreur OpenRouter'
      });
    }

    const answer = result.choices?.[0]?.message?.content;

    if (!answer) {
      return res.status(502).json({
        success: false,
        error: 'Réponse IA vide'
      });
    }

    return res.json({
      success: true,
      reply: answer,
      answer: answer,
      response: answer
    });

  } catch (error) {
    console.error('CHAT ERROR:', error.message);

    return res.status(500).json({
      success: false,
      error: error.name === 'AbortError'
        ? 'Le délai de réponse IA est dépassé'
        : 'Erreur pendant la génération de la réponse'
    });
  }
});

// Ancienne route compatible.

app.post('/chat', (req, res, next) => {
  req.url = '/api/chat';
  next();
});

// ======================================
// ERREURS
// ======================================

app.use((err, req, res, next) => {
  console.error('SERVER ERROR:', err.message);

  res.status(500).json({
    success: false,
    error: 'Erreur interne du serveur'
  });
});

// ======================================
// DÉMARRAGE DU SERVEUR
// ======================================

app.listen(PORT, '0.0.0.0', () => {
  console.log('================================');
  console.log('🚀 TAYA IA V13 EST EN LIGNE');
  console.log('✅ Serveur démarré');
  console.log('✅ Supabase :', !!supabase);
  console.log('🤖 Intelligence artificielle :', !!OPENROUTER_API_KEY);
  console.log('================================');
});
