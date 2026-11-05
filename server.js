/* ==========================================
   MESSAGERIE UTILISATEUR / ADMIN
========================================== */

// Envoyer un message à Maruce
app.post("/api/contact", authenticate, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message || message.length > 5000) {
      return failure(res, 400, "Message vide ou trop long.");
    }

    const { error } = await supabase
      .from("taya_v19_support_messages")
      .insert({
        user_id: req.user.id,
        sender_id: req.user.id,
        sender_role: "user",
        message
      });

    if (error) {
      console.error("Contact:", error.message);
      return failure(res, 500, "Impossible d'envoyer le message.");
    }

    return success(res, {
      message: "Message envoyé à Maruce."
    });

  } catch (error) {
    console.error("Contact:", error.message);
    return failure(res, 500, "Erreur d'envoi.");
  }
});


// Lire les messages reçus par l'utilisateur
app.get("/api/contact/messages", authenticate, async (req, res) => {
  try {
    const { data: supportMessages, error } = await supabase
      .from("taya_v19_support_messages")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });

    if (error) {
      console.error("User messages:", error.message);
      return failure(res, 500, "Impossible de charger les messages.");
    }

    // Récupérer également les anciens messages
    const { data: oldMessages, error: oldError } = await supabase
      .from("taya_v12_contacts")
      .select("*")
      .eq("user_id", req.user.id)
      .order("created_at", { ascending: true });

    if (oldError) {
      console.error("Old messages:", oldError.message);
      return failure(res, 500, "Erreur de lecture des anciens messages.");
    }

    const legacy = (oldMessages || []).map(item => ({
      ...item,
      sender_role: "user",
      legacy: true
    }));

    const messages = [...legacy, ...(supportMessages || [])]
      .sort((a, b) =>
        new Date(a.created_at) - new Date(b.created_at)
      );

    return success(res, { messages });

  } catch (error) {
    console.error("User messages:", error.message);
    return failure(res, 500, "Erreur de chargement.");
  }
});


// Liste des conversations dans l'administration
app.get(
  "/api/admin/messages",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { data: users, error: usersError } = await supabase
        .from("taya_v13_users")
        .select("id,name,phone");

      if (usersError) {
        return failure(res, 500, "Impossible de charger les utilisateurs.");
      }

      const { data: supportMessages, error } = await supabase
        .from("taya_v19_support_messages")
        .select("*")
        .order("created_at", { ascending: true });

      if (error) {
        console.error("Admin messages:", error.message);
        return failure(res, 500, "Impossible de charger les messages.");
      }

      const { data: oldMessages, error: oldError } = await supabase
        .from("taya_v12_contacts")
        .select("*")
        .order("created_at", { ascending: true });

      if (oldError) {
        return failure(res, 500, "Impossible de charger les anciens messages.");
      }

      const userMap = new Map(
        (users || []).map(user => [user.id, user])
      );

      const legacy = (oldMessages || []).map(item => ({
        ...item,
        sender_role: "user",
        legacy: true
      }));

      const messages = [...legacy, ...(supportMessages || [])]
        .map(item => ({
          ...item,
          user: userMap.get(item.user_id) || null
        }))
        .sort((a, b) =>
          new Date(a.created_at) - new Date(b.created_at)
        );

      return success(res, { messages });

    } catch (error) {
      console.error("Admin messages:", error.message);
      return failure(res, 500, "Erreur de chargement.");
    }
  }
);


// Répondre à un utilisateur
app.post(
  "/api/admin/messages/:userId/reply",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const userId = String(req.params.userId || "");
      const message = String(req.body.message || "").trim();

      if (!message || message.length > 5000) {
        return failure(res, 400, "Réponse vide ou trop longue.");
      }

      const { data: targetUser, error: userError } = await supabase
        .from("taya_v13_users")
        .select("id")
        .eq("id", userId)
        .maybeSingle();

      if (userError || !targetUser) {
        return failure(res, 404, "Utilisateur introuvable.");
      }

      const { data, error } = await supabase
        .from("taya_v19_support_messages")
        .insert({
          user_id: targetUser.id,
          sender_id: req.user.id,
          sender_role: "admin",
          message
        })
        .select("*")
        .single();

      if (error) {
        console.error("Admin reply:", error.message);
        return failure(res, 500, "Impossible d'envoyer la réponse.");
      }

      return success(res, {
        message: "Réponse envoyée.",
        reply: data
      });

    } catch (error) {
      console.error("Admin reply:", error.message);
      return failure(res, 500, "Erreur pendant l'envoi.");
    }
  }
);
