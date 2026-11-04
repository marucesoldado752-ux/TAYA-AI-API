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

const SUPABASE_URL = process.env.SUPABASE_URL;

const SUPABASE_KEY =
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_KEY ||
  process.env.SUPABASE_ANON_KEY;

const AI_MODEL = "meta-llama/llama-3.1-8b-instruct:free";

const APP_URL = process.env.APP_URL ||
  "https://taya-ai-api.onrender.com";

let supabase = null;

if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  console.log("✅ Supabase configuré");
} else {
  console.error("❌ Variables Supabase manquantes");
}
