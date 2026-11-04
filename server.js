const response = await fetch(
  "https://openrouter.ai/api/v1/chat/completions",
  {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": process.env.APP_URL || "https://marucesoldado752-ux.github.io",
      "X-Title": "TAYA IA V13"
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
      temperature: 0.7,
      max_tokens: 4000
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
