// Limite les messages pour économiser les crédits
const limitedMessages = cleanMessages.slice(-8);

const response = await fetch(
  "https://openrouter.ai/api/v1/chat/completions",
  {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": process.env.APP_URL || "https://taya-ai-api.onrender.com",
      "X-Title": "TAYA IA V13"
    },
    body: JSON.stringify({
      model: AI_MODEL || "meta-llama/llama-3.1-8b-instruct:free",
      messages: [
        {
          role: "system",
          content: systemPrompt.slice(0, 3000) // limite le system prompt
        },
        ...limitedMessages
      ],
      temperature: 0.7,
      max_tokens: 1500, // réduit pour passer avec tes crédits
      top_p: 0.9
    })
  }
);

const result = await response.json();

if (!response.ok) {
  console.error("OpenRouter:", JSON.stringify(result, null, 2));

  // Si plus de crédits, on renvoie le vrai message pour comprendre
  if (result?.error?.code === 402 || result?.error?.message?.includes('credits')) {
    return res.status(402).json({
      error: "Crédits OpenRouter insuffisants. Va sur https://openrouter.ai/settings/credits pour recharger, ou utilise un modèle gratuit.",
      details: result.error.message
    });
  }

  return res.status(502).json({
    error: "Le service IA est temporairement indisponible.",
    details: result?.error?.message || "Erreur inconnue"
  });
}

const answer = result.choices?.[0]?.message?.content;

if (!answer) {
  console.error("Pas de réponse IA:", result);
  return res.status(502).json({
    error: "L'IA n'a pas renvoyé de réponse."
  });
}
