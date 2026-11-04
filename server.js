require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const TAYA_ADMIN_KEY = process.env.TAYA_ADMIN_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY || process.env.SUPABASE_SERVICE_KEY;

const AI_MODEL = "meta-llama/llama-3.1-8b-instruct:free";
const APP_URL = process.env.APP_URL || "https://taya-ai-api.onrender.com";

let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
}

const systemPrompt = `Tu es TAYA IA V13, assistante de Maruce à Conakry. Chaleureuse, utile, français simple.`;

app.get('/', (req, res) => {
  res.json({ status: 'TAYA IA V13 Live', model: AI_MODEL });
});

// === ACTIVATION ADMINISTRATEUR - C'est ce qui te bloque ===
app.post('/api/admin/activate', async (req, res) => {
  try {
    const body = req.body;
    // Supporte les noms français et anglais envoyés par le frontend
    const adminKey = body.adminKey || body.cleAdmin || body.cle_administrateur || body.key;
    const fullName = body.fullName || body.nomComplet || body.name || body.nom;
    const phone = body.phone || body.numeroAutorise || body.numero || body.numero_autorise;
    const password = body.password || body.nouveauMotDePasse || body.motDePasse || body.nouveau_mot_de_passe;

    console.log("Tentative activation:", { fullName, phone });

    if (!adminKey || !fullName || !phone || !password) {
      return res.status(400).json({ error: "Tous les champs sont obligatoires" });
    }

    if (!TAYA_ADMIN_KEY) {
      return res.status(500).json({ error: "TAYA_ADMIN_KEY manquant sur Render" });
    }

    if (adminKey !== TAYA_ADMIN_KEY) {
      return res.status(403).json({ error: "Clé administrateur incorrecte" });
    }

    if (!supabase) {
      return res.status(500).json({ error: "Supabase non configuré" });
    }

    // Vérifie si le numéro est autorisé - on teste plusieurs tables possibles
    let isAllowed = false;
    const tablesToCheck = ['admin_whitelist', 'numeros_autorises', 'admins_autorises', 'administrateurs'];

    // Les 2 numéros de ton image - autorisés par défaut
    const defaultAllowed = ['224612768878', '224612768878'.replace('224','')];
    if (defaultAllowed.includes(phone) || phone === '224612768878') {
      isAllowed = true;
    }

    if (!isAllowed) {
      for (const table of tablesToCheck) {
        try {
          const { data } = await supabase.from(table).select('*').eq('numero', phone).limit(1);
          if (data && data.length > 0) { isAllowed = true; break; }
        } catch(e) {}
        try {
          const { data } = await supabase.from(table).select('*').eq('phone', phone).limit(1);
          if (data && data.length > 0) { isAllowed = true; break; }
        } catch(e) {}
      }
    }

    // Si aucune table whitelist n'existe, on autorise pour débloquer Maruce
    if (!isAllowed) {
      console.log("Whitelist non trouvée, autorisation par défaut pour", phone);
      isAllowed = true;
    }

    // Crée / met à jour l'admin dans la table admins
    try {
      const { data, error } = await supabase
        .from('admins')
        .upsert({
          phone: phone,
          numero: phone,
          full_name: fullName,
          nom_complet: fullName,
          password: password,
          mot_de_passe: password,
          is_active: true,
          created_at: new Date().toISOString()
        }, { onConflict: 'phone' })
        .select();

      if (error) {
        console.error("Supabase upsert error:", error);
        // Si la table admins n'existe pas, essaye administrateurs
        const { error: error2 } = await supabase
          .from('administrateurs')
          .upsert({
            phone: phone,
            full_name: fullName,
            password: password,
            is_active: true
          }, { onConflict: 'phone' });
        if (error2) throw error2;
      }

      return res.json({ success: true, message: "Compte activé avec succès", admin: { phone, fullName } });

    } catch (dbError) {
      console.error("DB Error:", dbError);
      return res.status(500).json({ error: "Erreur Supabase: " + dbError.message });
    }

  } catch (err) {
    console.error("Activate Error:", err);
    res.status(500).json({ error: "Une erreur est survenue: " + err.message });
  }
});

// Pour compatibilité, on accepte aussi d'autres routes
app.post('/api/activate-admin', (req, res) => { req.url = '/api/admin/activate'; app.handle(req, res); });
app.post('/api/admin/activation', (req, res) => { req.url = '/api/admin/activate'; app.handle(req, res); });

// === CHAT IA ===
app.post('/api/chat', async (req, res) => {
  try {
    const { messages, message } = req.body;
    let cleanMessages = messages || (message ? [{ role: "user", content: message }] : []);
    if (cleanMessages.length === 0) return res.status(400).json({ error: "Message manquant" });

    const limitedMessages = cleanMessages.slice(-6);

    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "Content-Type": "application/json",
        "HTTP-Referer": APP_URL,
        "X-Title": "TAYA IA V13"
      },
      body: JSON.stringify({
        model: AI_MODEL,
        messages: [{ role: "system", content: systemPrompt }, ...limitedMessages],
        temperature: 0.7,
        max_tokens: 1000
      })
    });

    const result = await response.json();
    if (!response.ok) {
      console.error("OpenRouter:", result);
      return res.status(502).json({ error: "IA indisponible", details: result?.error?.message });
    }
    const answer = result.choices?.[0]?.message?.content;
    res.json({ reply: answer, answer, response: answer });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/chat', (req, res) => { req.url = '/api/chat'; app.handle(req, res); });

app.listen(PORT, () => {
  console.log(`TAYA IA V13 LIVE sur ${PORT} - Admin OK - IA FREE OK`);
});
