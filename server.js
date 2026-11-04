const response = await fetch(
  "https://openrouter.ai/api/v1/chat/completions",
  {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "https://taya-ai-api.onrender.com",
      "X-Title": "TAYA IA V13"
    },
    body: JSON.stringify({
      model: "meta-llama/llama-3.1-8b-instruct:free",
      messages: [
        {
          role: "system",
          content: systemPrompt.slice(0, 2000)
        },
        ...cleanMessages.slice(-6)
      ],
      temperature: 0.7,
      max_tokens: 1000
    })
  }
);

const result = await response.json();

if (!response.ok) {
  console.error("OpenRouter:", result);
  return res.status(502).json({
    error: `IA indisponible: ${result?.error?.message || 'credits'}` 
  });
}

const answer = result.choices?.[0]?.message?.content;

if (!answer) {
  return res.status(502).json({
    error: "L'IA n'a pas renvoyé de réponse."
  });
}
