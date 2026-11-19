// Kargo Rota sunucusu (Cloudflare Workers + D1)
// Gizli değişkenler (Settings > Variables and Secrets):
//   ADMIN_USER, ADMIN_PASSWORD  : yönetici girişi
//   GOOGLE_SERVER_KEY           : yalnız Geocoding + Routes API izinli, sunucuda kalan anahtar
//   MAPS_BROWSER_KEY            : yalnız Maps JavaScript API izinli, site adresine kısıtlı anahtar
//   ALLOWED_ORIGIN              : https://KULLANICIADI.github.io
// Bağlantı (Settings > Bindings): D1 veritabanı, adı DB

const DAY_MS = 86400000;
const SESSION_DAYS = 30;
const CACHE_DAYS = 30; // Google koşulları: koordinatlar en fazla 30 gün saklanabilir
const DEF_GEO = 400, DEF_ROUTE = 250;

let migrated = false;
async function migrate(db) {
  if (migrated) return;
  const sql = [
    `CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, name TEXT, pass_hash TEXT, salt TEXT,
      role TEXT DEFAULT 'courier', active INTEGER DEFAULT 1, daily_geo INTEGER DEFAULT ${DEF_GEO}, daily_route INTEGER DEFAULT ${DEF_ROUTE},
      created_at INTEGER, last_seen INTEGER, last_stats TEXT, last_error TEXT, last_error_at INTEGER, message TEXT, fails INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, created_at INTEGER, expires_at INTEGER)`,
    `CREATE TABLE IF NOT EXISTS usage(user_id INTEGER, day TEXT, geo INTEGER DEFAULT 0, geo_cache INTEGER DEFAULT 0, route INTEGER DEFAULT 0, PRIMARY KEY(user_id, day))`,
    `CREATE TABLE IF NOT EXISTS geocache(q TEXT PRIMARY KEY, data TEXT, created_at INTEGER)`,
  ];
  await db.batch(sql.map((s) => db.prepare(s)));
  migrated = true;
}

const now = () => Date.now();
const today = () => new Date(Date.now() + 3 * 3600000).toISOString().slice(0, 10); // İstanbul günü
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const rand = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

async function hashPw(pw, salt) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 100000, hash: 'SHA-256' }, key, 256);
  return hex(bits);
}
function same(a, b) { // sabit süreli karşılaştırma
  a = String(a); b = String(b);
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

function cors(env, req) {
  const o = req.headers.get('Origin') || '';
  const allow = env.ALLOWED_ORIGIN ? (o === env.ALLOWED_ORIGIN ? o : env.ALLOWED_ORIGIN) : '*';
  return { 'Access-Control-Allow-Origin': allow, 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,Authorization', 'Vary': 'Origin' };
}
const J = (env, req, data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...cors(env, req) } });
const err = (env, req, msg, status = 400) => J(env, req, { error: msg }, status);

async function userFromToken(env, req) {
  const h = req.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  const row = await env.DB.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?`).bind(token, now()).first();
  if (!row || !row.active) return null;
  row.token = token;
  return row;
}
const pub = (u) => ({ id: u.id, username: u.username, name: u.name, role: u.role });

async function bumpUsage(env, uid, col) {
  await env.DB.prepare(`INSERT INTO usage(user_id,day,${col}) VALUES(?,?,1) ON CONFLICT(user_id,day) DO UPDATE SET ${col}=${col}+1`).bind(uid, today()).run();
}
async function usageToday(env, uid) {
  return (await env.DB.prepare(`SELECT geo,geo_cache,route FROM usage WHERE user_id=? AND day=?`).bind(uid, today()).first()) || { geo: 0, geo_cache: 0, route: 0 };
}

// ---------- giriş ----------
async function login(env, req) {
  const b = await req.json().catch(() => ({}));
  const username = String(b.username || '').trim().toLowerCase(), password = String(b.password || '');
  if (!username || !password) return err(env, req, 'Kullanıcı adı ve şifre gerekli');
  let u = await env.DB.prepare(`SELECT * FROM users WHERE username=?`).bind(username).first();
  if (u && u.locked_until > now()) return err(env, req, 'Çok fazla hatalı deneme. 15 dakika sonra tekrar deneyin.', 429);
  let ok = false;
  if (env.ADMIN_USER && username === String(env.ADMIN_USER).toLowerCase()) {
    ok = !!env.ADMIN_PASSWORD && same(password, env.ADMIN_PASSWORD);
    if (ok && !u) {
      await env.DB.prepare(`INSERT INTO users(username,name,role,active,daily_geo,daily_route,created_at) VALUES(?,?,?,?,?,?,?)`).bind(username, 'Yönetici', 'admin', 1, 100000, 100000, now()).run();
      u = await env.DB.prepare(`SELECT * FROM users WHERE username=?`).bind(username).first();
    }
  } else if (u && u.pass_hash) {
    ok = same(await hashPw(password, u.salt), u.pass_hash);
  }
  if (!ok) {
    if (u) {
      const f = (u.fails || 0) + 1;
      await env.DB.prepare(`UPDATE users SET fails=?, locked_until=? WHERE id=?`).bind(f >= 10 ? 0 : f, f >= 10 ? now() + 15 * 60000 : 0, u.id).run();
    }
    return err(env, req, 'Kullanıcı adı veya şifre hatalı', 401);
  }
  if (!u.active) return err(env, req, 'Hesabınız kapatılmış. Yöneticinizle görüşün.', 403);
  const token = rand(32);
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)`).bind(token, u.id, now(), now() + SESSION_DAYS * DAY_MS),
    env.DB.prepare(`UPDATE users SET fails=0, locked_until=0, last_seen=? WHERE id=?`).bind(now(), u.id),
  ]);
  return J(env, req, { token, user: pub(u) });
}

// ---------- adres arama (gizli anahtarla, 30 gün ortak önbellek) ----------
async function googleGeocode(env, q, bounds) {
  let url = 'https://maps.googleapis.com/maps/api/geocode/json?address=' + encodeURIComponent(q) + '&components=country:TR&language=tr&region=tr&key=' + encodeURIComponent(env.GOOGLE_SERVER_KEY);
  if (bounds) url += '&bounds=' + bounds;
  const j = await (await fetch(url)).json();
  if (j.status === 'ZERO_RESULTS') return { zero: true };
  if (j.status !== 'OK' || !j.results || !j.results.length) throw new Error('Google: ' + j.status + (j.error_message ? ' – ' + j.error_message : ''));
  const g = j.results[0];
  return { lat: g.geometry.location.lat, lng: g.geometry.location.lng, types: g.types || [], lt: g.geometry.location_type, partial: !!g.partial_match, found: g.formatted_address };
}
async function geocode(env, req, u) {
  const b = await req.json().catch(() => ({}));
  const tries = (Array.isArray(b.tries) ? b.tries : [b.q]).map((x) => String(x || '').trim()).filter(Boolean).slice(0, 3);
  if (!tries.length) return err(env, req, 'Adres boş');
  const bounds = typeof b.bounds === 'string' && /^[-\d.,|]+$/.test(b.bounds) ? b.bounds : '';
  for (let k = 0; k < tries.length; k++) {
    const key = tries[k].toLocaleLowerCase('tr-TR').replace(/\s+/g, ' ');
    let r = null, cached = false;
    const c = await env.DB.prepare(`SELECT data,created_at FROM geocache WHERE q=?`).bind(key).first();
    if (c && c.created_at > now() - CACHE_DAYS * DAY_MS) { r = JSON.parse(c.data); cached = true; await bumpUsage(env, u.id, 'geo_cache'); }
    if (!r) {
      const use = await usageToday(env, u.id);
      if (use.geo >= u.daily_geo) return J(env, req, { geo: 'none', err: 'Günlük adres arama sınırınız doldu' }, 429);
      try { r = await googleGeocode(env, tries[k], bounds); } catch (e) { return J(env, req, { geo: 'none', err: String(e.message || e) }, 502); }
      await bumpUsage(env, u.id, 'geo');
      await env.DB.prepare(`INSERT INTO geocache(q,data,created_at) VALUES(?,?,?) ON CONFLICT(q) DO UPDATE SET data=excluded.data, created_at=excluded.created_at`).bind(key, JSON.stringify(r), now()).run();
      if (Math.random() < 0.02) await env.DB.prepare(`DELETE FROM geocache WHERE created_at<?`).bind(now() - CACHE_DAYS * DAY_MS).run();
    }
    if (r.zero) continue; // bulunamadı: bir sonraki (daha kısa) sorguyu dene
    const street = r.types.some((t) => ['street_address', 'premise', 'subpremise'].includes(t)) || ['ROOFTOP', 'RANGE_INTERPOLATED'].includes(r.lt);
    const exact = k === 0 && !!b.hasNo && !r.partial && street;
    return J(env, req, { geo: exact ? 'ok' : 'approx', lat: r.lat, lng: r.lng, found: r.found, cached });
  }
  return J(env, req, { geo: 'none', err: 'Google adresi bulamadı' });
}

// ---------- rota (en fazla 10 durak: ucuz Essentials tarifesi) ----------
async function route(env, req, u) {
  const b = await req.json().catch(() => ({}));
  const ok = (p) => p && isFinite(p.lat) && isFinite(p.lng);
  const stops = Array.isArray(b.stops) ? b.stops.filter(ok) : [];
  if (!ok(b.origin) || !stops.length) return err(env, req, 'Başlangıç ve durak gerekli');
  if (stops.length > 10) return err(env, req, 'Bir istekte en fazla 10 durak');
  const use = await usageToday(env, u.id);
  if (use.route >= u.daily_route) return J(env, req, { error: 'Günlük rota sınırınız doldu' }, 429);
  const L = (x) => ({ location: { latLng: { latitude: +x.lat, longitude: +x.lng } } });
  const r = await fetch('https://routes.googleapis.com/directions/v2:computeRoutes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Goog-Api-Key': env.GOOGLE_SERVER_KEY,
      'X-Goog-FieldMask': 'routes.legs.distanceMeters,routes.legs.duration,routes.legs.steps.distanceMeters,routes.legs.steps.navigationInstruction,routes.legs.steps.polyline,routes.legs.steps.endLocation' },
    body: JSON.stringify({ origin: L(b.origin), destination: L(stops[stops.length - 1]), intermediates: stops.slice(0, -1).map(L), travelMode: 'DRIVE', routingPreference: 'TRAFFIC_UNAWARE', languageCode: 'tr', units: 'METRIC' }),
  });
  const j = await r.json();
  await bumpUsage(env, u.id, 'route');
  if (!r.ok) return J(env, req, { error: (j.error && j.error.message) || 'Google rota hatası ' + r.status }, 502);
  return J(env, req, j);
}

// ---------- yönetim ----------
async function adminUsers(env, req) {
  const rows = await env.DB.prepare(`SELECT u.id,u.username,u.name,u.role,u.active,u.daily_geo,u.daily_route,u.created_at,u.last_seen,u.last_stats,u.last_error,u.last_error_at,u.message,
      COALESCE(g.geo,0) geo, COALESCE(g.geo_cache,0) geo_cache, COALESCE(g.route,0) route
    FROM users u LEFT JOIN usage g ON g.user_id=u.id AND g.day=? ORDER BY u.role='admin' DESC, u.name COLLATE NOCASE`).bind(today()).all();
  const month = today().slice(0, 7);
  const tot = await env.DB.prepare(`SELECT COALESCE(SUM(geo),0) geo, COALESCE(SUM(geo_cache),0) geo_cache, COALESCE(SUM(route),0) route FROM usage WHERE day LIKE ?`).bind(month + '%').first();
  return J(env, req, { users: rows.results.map((x) => ({ ...x, last_stats: x.last_stats ? JSON.parse(x.last_stats) : null })), month: tot, now: now() });
}
async function adminCreate(env, req) {
  const b = await req.json().catch(() => ({}));
  const username = String(b.username || '').trim().toLowerCase();
  const name = String(b.name || '').trim().slice(0, 80), password = String(b.password || '');
  if (!/^[a-z0-9._-]{3,30}$/.test(username)) return err(env, req, 'Kullanıcı adı 3–30 karakter olmalı: küçük harf, rakam, nokta, tire');
  if (username === String(env.ADMIN_USER || '').toLowerCase()) return err(env, req, 'Bu kullanıcı adı yöneticiye ayrılmış');
  if (password.length < 6) return err(env, req, 'Şifre en az 6 karakter olmalı');
  if (await env.DB.prepare(`SELECT id FROM users WHERE username=?`).bind(username).first()) return err(env, req, 'Bu kullanıcı adı zaten var');
  const salt = rand(16);
  await env.DB.prepare(`INSERT INTO users(username,name,pass_hash,salt,role,active,daily_geo,daily_route,created_at) VALUES(?,?,?,?,?,?,?,?,?)`)
    .bind(username, name || username, await hashPw(password, salt), salt, 'courier', 1, +b.daily_geo || DEF_GEO, +b.daily_route || DEF_ROUTE, now()).run();
  return J(env, req, { ok: true });
}
async function adminAction(env, req, id) {
  const b = await req.json().catch(() => ({}));
  const u = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(id).first();
  if (!u) return err(env, req, 'Kullanıcı bulunamadı', 404);
  if (u.role === 'admin' && b.action !== 'message') return err(env, req, 'Yönetici hesabı buradan değiştirilemez');
  const db = env.DB;
  switch (b.action) {
    case 'disable': await db.batch([db.prepare(`UPDATE users SET active=0 WHERE id=?`).bind(id), db.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id)]); break;
    case 'enable': await db.prepare(`UPDATE users SET active=1, fails=0, locked_until=0 WHERE id=?`).bind(id).run(); break;
    case 'logout': await db.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id).run(); break;
    case 'password': {
      const p = String(b.password || '');
      if (p.length < 6) return err(env, req, 'Şifre en az 6 karakter olmalı');
      const salt = rand(16);
      await db.batch([db.prepare(`UPDATE users SET pass_hash=?, salt=?, fails=0, locked_until=0 WHERE id=?`).bind(await hashPw(p, salt), salt, id), db.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id)]);
      break;
    }
    case 'limits': await db.prepare(`UPDATE users SET daily_geo=?, daily_route=? WHERE id=?`).bind(Math.max(0, +b.daily_geo || 0), Math.max(0, +b.daily_route || 0), id).run(); break;
    case 'message': await db.prepare(`UPDATE users SET message=? WHERE id=?`).bind(String(b.message || '').slice(0, 300) || null, id).run(); break;
    case 'clear_error': await db.prepare(`UPDATE users SET last_error=NULL, last_error_at=NULL WHERE id=?`).bind(id).run(); break;
    case 'delete': await db.batch([db.prepare(`DELETE FROM sessions WHERE user_id=?`).bind(id), db.prepare(`DELETE FROM usage WHERE user_id=?`).bind(id), db.prepare(`DELETE FROM users WHERE id=?`).bind(id)]); break;
    default: return err(env, req, 'Bilinmeyen işlem');
  }
  return J(env, req, { ok: true });
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(env, req) });
    const url = new URL(req.url), p = url.pathname.replace(/\/+$/, '');
    try {
      if (!env.DB) return err(env, req, 'Sunucuya D1 veritabanı (DB) bağlanmamış', 500);
      await migrate(env.DB);
      if (p === '' || p === '/api') return J(env, req, { ok: true, service: 'kargo-rota' });
      if (p === '/api/login' && req.method === 'POST') return await login(env, req);
      const u = await userFromToken(env, req);
      if (!u) return err(env, req, 'Oturum geçersiz, tekrar giriş yapın', 401);
      if (p === '/api/me') {
        await env.DB.prepare(`UPDATE users SET last_seen=? WHERE id=?`).bind(now(), u.id).run();
        return J(env, req, { user: pub(u), mapsKey: env.MAPS_BROWSER_KEY || '', limits: { geo: u.daily_geo, route: u.daily_route }, usage: await usageToday(env, u.id) });
      }
      if (p === '/api/logout' && req.method === 'POST') { await env.DB.prepare(`DELETE FROM sessions WHERE token=?`).bind(u.token).run(); return J(env, req, { ok: true }); }
      if (p === '/api/geocode' && req.method === 'POST') return await geocode(env, req, u);
      if (p === '/api/route' && req.method === 'POST') return await route(env, req, u);
      if (p === '/api/ping' && req.method === 'POST') {
        const b = await req.json().catch(() => ({}));
        await env.DB.prepare(`UPDATE users SET last_seen=?, last_stats=?, message=NULL WHERE id=?`).bind(now(), JSON.stringify(b.stats || {}).slice(0, 1000), u.id).run();
        return J(env, req, { ok: true, message: u.message || null });
      }
      if (p === '/api/log' && req.method === 'POST') {
        const b = await req.json().catch(() => ({}));
        await env.DB.prepare(`UPDATE users SET last_error=?, last_error_at=? WHERE id=?`).bind(String(b.error || '').slice(0, 500), now(), u.id).run();
        return J(env, req, { ok: true });
      }
      if (p.startsWith('/api/admin/')) {
        if (u.role !== 'admin') return err(env, req, 'Bu bölüm yalnız yönetici içindir', 403);
        if (p === '/api/admin/users' && req.method === 'GET') return await adminUsers(env, req);
        if (p === '/api/admin/users' && req.method === 'POST') return await adminCreate(env, req);
        const m = p.match(/^\/api\/admin\/users\/(\d+)$/);
        if (m && req.method === 'POST') return await adminAction(env, req, +m[1]);
      }
      return err(env, req, 'Bulunamadı', 404);
    } catch (e) {
      return err(env, req, 'Sunucu hatası: ' + (e && e.message ? e.message : e), 500);
    }
  },
};
