const ALLOWED_ORIGINS = new Set([
  "https://necto.com.au",
  "https://www.necto.com.au",
]);

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });

const clean = (value, maxLength) =>
  typeof value === "string" ? value.trim().slice(0, maxLength) : "";

const validEmail = (value) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;

const safeSourceUrl = (value) => {
  try {
    const url = new URL(value);
    return ALLOWED_ORIGINS.has(url.origin) ? url.href.slice(0, 2000) : null;
  } catch {
    return null;
  }
};

async function verifyTurnstile(token, ip, secret) {
  const form = new FormData();
  form.set("secret", secret);
  form.set("response", token);
  if (ip) form.set("remoteip", ip);

  const response = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    { method: "POST", body: form },
  );

  if (!response.ok) return false;
  const result = await response.json();
  return result.success === true;
}

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("origin");
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return json({ ok: false, error: "Origin not allowed." }, 403);
  }

  if (!env.NOTION_API_TOKEN || !env.NOTION_DATA_SOURCE_ID) {
    return json({ ok: false, error: "Form service is not configured." }, 500);
  }
  if (!env.TURNSTILE_SECRET_KEY) {
    return json({ ok: false, error: "Spam protection is not configured." }, 500);
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    return json({ ok: false, error: "Unsupported request." }, 415);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Invalid request." }, 400);
  }

  // Honeypot: acknowledge bots without creating a Notion record.
  if (clean(body.website, 200)) return json({ ok: true });

  const name = clean(body.name, 120);
  const email = clean(body.email, 254).toLowerCase();
  const phone = clean(body.phone, 50);
  const organisation = clean(body.organisation, 200);
  const message = clean(body.message, 2000);
  const consent = body.consent === true;
  const sourcePage = safeSourceUrl(clean(body.sourcePage, 2000));
  const turnstileToken = clean(body.turnstileToken, 4096);
  const startedAt = Number(body.startedAt);
  const elapsed = Date.now() - startedAt;

  if (!name || !validEmail(email) || !message || !consent) {
    return json({ ok: false, error: "Please complete all required fields." }, 400);
  }
  if (!Number.isFinite(startedAt) || elapsed < 2000 || elapsed > 86400000) {
    return json({ ok: false, error: "Please refresh the page and try again." }, 400);
  }
  if (!turnstileToken) {
    return json({ ok: false, error: "Please complete the security check." }, 400);
  }

  const verified = await verifyTurnstile(
    turnstileToken,
    request.headers.get("CF-Connecting-IP"),
    env.TURNSTILE_SECRET_KEY,
  );
  if (!verified) {
    return json({ ok: false, error: "Security check failed. Please try again." }, 400);
  }

  const properties = {
    Name: {
      type: "title",
      title: [{ type: "text", text: { content: name } }],
    },
    Email: { type: "email", email },
    Organisation: {
      type: "rich_text",
      rich_text: organisation
        ? [{ type: "text", text: { content: organisation } }]
        : [],
    },
    Message: {
      type: "rich_text",
      rich_text: [{ type: "text", text: { content: message } }],
    },
    Status: { type: "status", status: { name: "New" } },
    "Privacy consent": { type: "checkbox", checkbox: true },
  };

  if (phone) properties.Phone = { type: "phone_number", phone_number: phone };
  if (sourcePage) properties["Source page"] = { type: "url", url: sourcePage };

  const notionResponse = await fetch("https://api.notion.com/v1/pages", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.NOTION_API_TOKEN}`,
      "content-type": "application/json",
      "notion-version": "2026-03-11",
    },
    body: JSON.stringify({
      parent: {
        type: "data_source_id",
        data_source_id: env.NOTION_DATA_SOURCE_ID,
      },
      properties,
    }),
  });

  if (!notionResponse.ok) {
    // Do not expose Notion response details or personal data to the browser.
    console.error("Notion create-page failed", notionResponse.status);
    return json(
      { ok: false, error: "We could not send your message. Please try again." },
      502,
    );
  }

  return json({ ok: true });
}

export function onRequest(context) {
  if (context.request.method !== "POST") {
    return json({ ok: false, error: "Method not allowed." }, 405);
  }
  return onRequestPost(context);
}
