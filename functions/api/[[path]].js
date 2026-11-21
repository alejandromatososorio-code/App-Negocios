// BusinessControl - API base: registro, login, sesion y plan Free/Pro
const enc = new TextEncoder();
const b64 = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

// Limites por plan (null = ilimitado)
const LIMITS = {
  free: { products: 50, users: 1, businesses: 1 },
  pro: { products: null, users: 10, businesses: 5 },
};
// Funciones que solo existen en Pro (la app las muestra bloqueadas)
const PRO_ONLY = ["reportes", "fiados", "exportar", "empleados", "multinegocio", "multimoneda", "respaldo"];

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });

async function hashPw(pw, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256);
  return b64(bits);
}

async function hmac(secret, data) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}

async function makeCookie(env, uid) {
  const p = b64(enc.encode(JSON.stringify({ uid, exp: Date.now() + 30 * 864e5 })));
  const token = p + "." + (await hmac(env.SESSION_SECRET, p));
  return `s=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}

async function getUserId(env, req) {
  const m = /(?:^|; )s=([^;]+)/.exec(req.headers.get("Cookie") || "");
  if (!m) return null;
  const [p, sig] = m[1].split(".");
  if (!p || !sig || sig !== (await hmac(env.SESSION_SECRET, p))) return null;
  try {
    const d = JSON.parse(new TextDecoder().decode(unb64(p)));
    return d.exp > Date.now() ? d.uid : null;
  } catch { return null; }
}

// Fuente unica de verdad: el plan se decide AQUI, en el servidor
const isPro = (u) => u.plan === "pro" && u.plan_expires > Date.now();

function publicUser(u) {
  const pro = isPro(u);
  return {
    id: u.id, name: u.name, email: u.email, business_type: u.business_type,
    plan: pro ? "pro" : "free",
    plan_expires: pro ? u.plan_expires : null,
    limits: LIMITS[pro ? "pro" : "free"],
    locked_features: pro ? [] : PRO_ONLY,
  };
}

// Para usar despues en el panel de pagos (aprobar CUP / confirmar USDT)
export async function activatePro(db, userId, days = 30) {
  const u = await db.prepare("SELECT plan_expires FROM users WHERE id=?").bind(userId).first();
  const base = Math.max(Date.now(), u?.plan_expires || 0);
  await db.prepare("UPDATE users SET plan='pro', plan_expires=? WHERE id=?")
    .bind(base + days * 864e5, userId).run();
}

export async function onRequest({ request, env, params }) {
  const route = (params.path || []).join("/");
  const method = request.method;
  const db = env.DB;
  if (!db || !env.SESSION_SECRET) return json({ error: "config_incompleta" }, 500);

  if (route === "register" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const email = String(b.email || "").trim().toLowerCase();
    const name = String(b.name || "").trim().slice(0, 80);
    const pw = String(b.password || "");
    const type = String(b.business_type || "general").slice(0, 30);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "correo_invalido" }, 400);
    if (!name) return json({ error: "nombre_requerido" }, 400);
    if (pw.length < 8) return json({ error: "clave_corta" }, 400);
    if (await db.prepare("SELECT id FROM users WHERE email=?").bind(email).first())
      return json({ error: "correo_en_uso" }, 409);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await hashPw(pw, salt);
    const r = await db.prepare(
      "INSERT INTO users (email,name,business_type,salt,pass_hash,created_at) VALUES (?,?,?,?,?,?)")
      .bind(email, name, type, b64(salt), hash, Date.now()).run();
    const id = r.meta.last_row_id;
    const u = await db.prepare("SELECT * FROM users WHERE id=?").bind(id).first();
    return json({ user: publicUser(u) }, 201, { "Set-Cookie": await makeCookie(env, id) });
  }

  if (route === "login" && method === "POST") {
    const b = await request.json().catch(() => ({}));
    const email = String(b.email || "").trim().toLowerCase();
    const u = await db.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
    const ok = u && (await hashPw(String(b.password || ""), unb64(u.salt))) === u.pass_hash;
    if (!ok) return json({ error: "credenciales_incorrectas" }, 401);
    return json({ user: publicUser(u) }, 200, { "Set-Cookie": await makeCookie(env, u.id) });
  }

  if (route === "logout" && method === "POST")
    return json({ ok: true }, 200, { "Set-Cookie": "s=; Path=/; HttpOnly; Secure; Max-Age=0" });

  if (route === "me" && method === "GET") {
    const uid = await getUserId(env, request);
    if (!uid) return json({ error: "sin_sesion" }, 401);
    const u = await db.prepare("SELECT * FROM users WHERE id=?").bind(uid).first();
    if (!u) return json({ error: "sin_sesion" }, 401);
    return json({ user: publicUser(u) });
  }

  return json({ error: "no_encontrado" }, 404);
}

