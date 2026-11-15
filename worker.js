// JAAT MATCH - Cloudflare Worker (proxy + PWA)
//   /                    -> website (index.html)
//   /list                -> channel list (naam + encrypted token). Asli URL client ko nahi jata.
//   /start               -> token kholta hai, (web page ho to) page se stream nikaalta hai
//   /f                   -> asli player ko iframe mein kholna (fallback)
//   /s                   -> stream / playlist / manifest proxy (HLS + DASH dono rewrite hote hain)
//   /p/<token>/<path>    -> DASH segments proxy (MPD ke relative links yahin se guzarte hain)
//   /manifest.webmanifest, /sw.js, /icon-*.png -> "Install App" (PWA) ke liye
//
// Cloudflare secrets:
//   SOURCES     = links.json ka URL (kai ho to alag line mein ya comma se)   [zaroori]
//   SECRET_KEY  = koi bhi lamba random text (token lock karne ke liye)       [zaroori nahi, par daal do]

import INDEX_HTML from "./index.html";

const UA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36";
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Expose-Headers": "*"
};
const enc = new TextEncoder();
const dec = new TextDecoder();

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, CORS)
  });
}

function parseTarget(t) {
  if (!t) return null;
  try {
    const u = new URL(t);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u;
  } catch (e) { return null; }
}

/* ---------------- token (encrypt / decrypt) ---------------- */
function b64u(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64u(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let KEYS = null, KEYSRC = "";
async function getKeys(env) {
  const material = String((env && (env.SECRET_KEY || env.SOURCES)) || "");
  if (!material) throw new Error("SOURCES / SECRET_KEY secret set nahi hai");
  if (KEYS && KEYSRC === material) return KEYS;
  const a = await crypto.subtle.digest("SHA-256", enc.encode("enc:" + material));
  const m = await crypto.subtle.digest("SHA-256", enc.encode("mac:" + material));
  KEYS = {
    aes: await crypto.subtle.importKey("raw", a, "AES-GCM", false, ["encrypt", "decrypt"]),
    mac: await crypto.subtle.importKey("raw", m, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
  };
  KEYSRC = material;
  return KEYS;
}

// same input -> same token (stable URLs, player ko fayda)
async function seal(obj, env) {
  const k = await getKeys(env);
  const plain = enc.encode(JSON.stringify(obj));
  const iv = new Uint8Array(await crypto.subtle.sign("HMAC", k.mac, plain)).slice(0, 12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k.aes, plain));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0); out.set(ct, 12);
  return b64u(out);
}

async function unseal(tok, env) {
  try {
    const k = await getKeys(env);
    const raw = unb64u(String(tok || ""));
    if (raw.length < 29) return null;
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, k.aes, raw.slice(12));
    return JSON.parse(dec.decode(pt));
  } catch (e) { return null; }
}

/* ---------------- links.json ko samajhna (server side) ---------------- */
const NAME_KEYS = ["name", "title", "channel", "channelname", "match", "matchname", "label", "event", "team", "nm", "caption", "heading"];
const URL_KEYS = ["url", "link", "src", "stream", "streamurl", "file", "m3u8", "mpd", "source", "play", "playurl", "embed", "iframe"];
const HEX32 = /^[0-9a-f]{32}$/i;

function lc(s) { return String(s || "").toLowerCase().replace(/[\s_-]/g, ""); }

function pickName(o, i) {
  if (typeof o === "string") {
    const base = o.split("?")[0].split("/").pop() || "";
    if (/\.(m3u8|mpd|mp4|webm)$/i.test(base)) return base.replace(/\.[a-z0-9]+$/i, "");
    return "Channel " + (i + 1);
  }
  if (!o || typeof o !== "object") return "Channel " + (i + 1);
  const keys = Object.keys(o);
  for (let k = 0; k < NAME_KEYS.length; k++) {
    for (let j = 0; j < keys.length; j++) {
      if (lc(keys[j]).indexOf(NAME_KEYS[k]) > -1) {
        const v = o[keys[j]];
        if (typeof v === "string" && v.trim() && !/^https?:/i.test(v)) return v.trim();
        if (typeof v === "number") return String(v);
      }
    }
  }
  for (let a = 0; a < keys.length; a++) {
    const vv = o[keys[a]];
    if (typeof vv === "string" && vv.trim() && !/^https?:/i.test(vv)) return vv.trim();
  }
  return "Channel " + (i + 1);
}

function pickUrl(o) {
  if (typeof o === "string") return /^https?:\/\//i.test(o.trim()) ? o.trim() : "";
  if (!o || typeof o !== "object") return "";
  const keys = Object.keys(o);
  for (let k = 0; k < URL_KEYS.length; k++) {
    for (let j = 0; j < keys.length; j++) {
      if (lc(keys[j]).indexOf(URL_KEYS[k]) > -1) {
        const v = o[keys[j]];
        if (typeof v === "string" && /^https?:\/\//i.test(v.trim())) return v.trim();
      }
    }
  }
  for (let a = 0; a < keys.length; a++) {
    const vv = o[keys[a]];
    if (typeof vv === "string" && /^https?:\/\//i.test(vv.trim())) return vv.trim();
  }
  return "";
}

// ClearKey DRM (agar links.json mein ho): "kid:key" (32 hex : 32 hex) ya alag keyid + key
function pickKey(o) {
  if (!o || typeof o !== "object") return "";
  const get = (re) => {
    for (const k of Object.keys(o)) if (re.test(lc(k)) && typeof o[k] === "string") return o[k].trim();
    return "";
  };
  const kid = get(/^(keyid|kid)$/);
  const key = get(/^(key|clearkey|drmkey|licensekey|license)$/);
  if (HEX32.test(kid) && HEX32.test(key)) return kid + ":" + key;
  if (/^[0-9a-f]{32}:[0-9a-f]{32}$/i.test(key)) return key;
  return "";
}

function kindOf(u) {
  const s = u.split("?")[0].toLowerCase();
  if (/\.m3u8$/.test(s) || s.indexOf("m3u8") > -1) return "hls";
  if (/\.mpd$/.test(s)) return "dash";
  if (/\.(mp4|webm|mkv|m4v)$/.test(s)) return "file";
  return "web";
}

function harvest(data) {
  const out = [], seen = {};
  function push(obj, i) {
    const url = pickUrl(obj);
    if (!url || seen[url]) return;
    seen[url] = 1;
    out.push({ name: pickName(obj, i), url: url, k: pickKey(obj) });
  }
  function walk(node, depth) {
    if (!node || depth > 6) return;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const it = node[i];
        if (typeof it === "string") {
          if (/^https?:\/\//i.test(it)) push(it, out.length);
        } else if (it && typeof it === "object") {
          if (pickUrl(it)) push(it, out.length); else walk(it, depth + 1);
        }
      }
      return;
    }
    if (typeof node === "object") {
      const ks = Object.keys(node);
      let plain = 0, hits = 0;
      for (let k = 0; k < ks.length; k++) {
        const v = node[ks[k]];
        if (typeof v === "string") {
          plain++;
          if (/^https?:\/\//i.test(v)) { hits++; push({ name: ks[k], url: v }, out.length); }
        }
      }
      if (plain && hits === plain) return;
      for (let m = 0; m < ks.length; m++) {
        const c = node[ks[m]];
        if (c && typeof c === "object") walk(c, depth + 1);
      }
    }
  }
  walk(data, 0);
  return out;
}

/* ---------------- /list ---------------- */
async function list(env) {
  const srcs = String((env && env.SOURCES) || "").split(/[\s,]+/).filter((u) => /^https?:\/\//i.test(u));
  if (!srcs.length) return json({ ok: false, error: "SOURCES secret set nahi hai" }, 500);
  for (const s of srcs) {
    try {
      const r = await fetch(s, {
        headers: { "User-Agent": UA, "Accept": "application/json,*/*" },
        cf: { cacheTtl: 15, cacheEverything: true }
      });
      if (!r.ok) continue;
      let data;
      try { data = JSON.parse(await r.text()); } catch (e) { continue; }
      const items = harvest(data);
      if (!items.length) continue;
      const out = [];
      for (const it of items) out.push({ name: it.name, t: await seal({ u: it.url, k: it.k || "" }, env) });
      return json({ ok: true, items: out });
    } catch (e) {}
  }
  return json({ ok: false, error: "koi source nahi khula" }, 502);
}

/* ---------------- web page se stream nikaalna ---------------- */
function pageHeaders(url, ref) {
  let r = ref;
  if (!r) { try { r = new URL(url).origin + "/"; } catch (e) { r = ""; } }
  const h = { "User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9" };
  if (r) h["Referer"] = r;
  return h;
}

function normalize(t) {
  return t.replace(/\\\//g, "/").replace(/\\u0026/gi, "&").replace(/\\u002F/gi, "/")
          .replace(/\\x2F/gi, "/").replace(/&amp;/g, "&");
}

function decodeB64(t) {
  const out = [];
  const re = /atob\(\s*["']([A-Za-z0-9+\/=]{24,})["']\s*\)/g;
  let m;
  while ((m = re.exec(t))) { try { out.push(atob(m[1])); } catch (e) {} }
  return out.join("\n");
}

/* ---------- page ke andar chhupi stream dhundhne ke tools ---------- */

// Dean Edwards packer:  eval(function(p,a,c,k,e,d){...}('....',62,N,'a|b|c'.split('|'),0,{}))
function unpackAll(txt) {
  let out = "";
  const re = /\}\s*\(\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s*\.split\(\s*['"]\|['"]\s*\)/g;
  let m, guard = 0;
  while ((m = re.exec(txt)) && guard++ < 6) {
    try {
      const p = m[1].slice(1, -1).replace(/\\(['"\\])/g, "$1");
      const a = +m[2];
      let c = +m[3];
      const k = m[4].slice(1, -1).split("|");
      const e = (n) => (n < a ? "" : e(Math.floor(n / a))) + ((n = n % a) > 35 ? String.fromCharCode(n + 29) : n.toString(36));
      const d = {};
      while (c--) d[e(c)] = k[c] || e(c);
      out += "\n" + p.replace(/\b\w+\b/g, (w) => (d[w] !== undefined ? d[w] : w));
    } catch (x) {}
  }
  return out;
}

function unescapeJs(t) {
  return t.replace(/\\x([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)))
          .replace(/\\u([0-9a-f]{4})/gi, (m, h) => String.fromCharCode(parseInt(h, 16)));
}

// lambi base64 strings jinke andar link chhupa ho ("aHR0cHM6Ly8...")
function decodeBlobs(t) {
  const out = [];
  const re = /["'`=]([A-Za-z0-9+\/_-]{32,}={0,2})(?=["'`&\s]|$)/g;
  let m, n = 0;
  while ((m = re.exec(t)) && n < 60) {
    n++;
    try {
      let s = m[1].replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) s += "=";
      const d = atob(s);
      if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(d) && /(https?:\/\/|\.m3u8|\.mpd)/i.test(d)) out.push(d);
    } catch (e) {}
  }
  return out.join("\n");
}

// ulte likhe link ("8u3m.xedni/...//:sptth")
function decodeReversed(t) {
  const out = [];
  const re = /["'`]((?:8u3m|dpm)\.[^"'`\s]{8,})["'`]/gi;
  let m, n = 0;
  while ((m = re.exec(t)) && n < 20) {
    n++;
    const r = m[1].split("").reverse().join("");
    if (/^https?:\/\//i.test(r)) out.push(r);
  }
  return out.join("\n");
}

function expandText(raw) {
  let t = raw + "\n" + decodeB64(raw);
  t += "\n" + unpackAll(t);
  t = normalize(unescapeJs(t));
  t += "\n" + decodeBlobs(t) + "\n" + decodeReversed(t);
  return normalize(t);
}

// ClearKey: "kid:key" (32 hex : 32 hex) ya keyId / key alag-alag
function extractKey(txt) {
  const m = txt.match(/([0-9a-f]{32})["']?\s*[:=,]\s*["']?([0-9a-f]{32})/i);
  if (m) return m[1].toLowerCase() + ":" + m[2].toLowerCase();
  const kid = txt.match(/key_?id["']?\s*[:=]\s*["']([0-9a-f]{32})["']/i);
  const key = txt.match(/\bkey["']?\s*[:=]\s*["']([0-9a-f]{32})["']/i);
  if (kid && key) return kid[1].toLowerCase() + ":" + key[1].toLowerCase();
  return "";
}

function extractStreams(raw, base, hint) {
  const txt = expandText(raw);
  const found = [];
  const seen = new Set();
  const add = (u, idx) => {
    if (/[{}$]/.test(u)) return;
    try {
      const a = new URL(u, base).toString();
      if (!/^https?:/i.test(a) || seen.has(a)) return;
      seen.add(a); found.push({ u: a, i: idx });
    } catch (e) {}
  };
  const re1 = /["'`(]\s*((?:https?:)?\/\/[^"'`\s<>)]+?\.(?:m3u8|mpd)(?:\?[^"'`\s<>)]*)?|[^"'`\s<>)]+?\.(?:m3u8|mpd)(?:\?[^"'`\s<>)]*)?)\s*["'`)]/gi;
  let m;
  while ((m = re1.exec(txt))) add(m[1], m.index);
  const re2 = /https?:\/\/[^\s"'`<>)\\]+?\.(?:m3u8|mpd)(?:\?[^\s"'`<>)\\]*)?/gi;
  while ((m = re2.exec(txt))) add(m[0], m.index);
  // page ek se zyada channel ki list rakhti ho to jis ke paas channel ka id likha ho wo pehle
  const h = String(hint || "").toLowerCase();
  if (h.length > 1 && found.length > 1) {
    const low = txt.toLowerCase();
    const pos = [];
    let p = low.indexOf(h);
    while (p > -1 && pos.length < 60) { pos.push(p); p = low.indexOf(h, p + 1); }
    const dist = (f) => {
      let best = 1e9;
      for (const q of pos) { const d = Math.abs(q - f.i); if (d < best) best = d; }
      return best > 400 ? 1e9 : best;
    };
    found.forEach((f) => { f.d = dist(f); });
    found.sort((a, b) => (a.d - b.d) || ((/\.mpd/i.test(a.u) ? 1 : 0) - (/\.mpd/i.test(b.u) ? 1 : 0)));
  } else {
    found.sort((a, b) => (/\.mpd/i.test(a.u) ? 1 : 0) - (/\.mpd/i.test(b.u) ? 1 : 0));
  }
  return found.map((f) => f.u);
}

function extractIframes(raw, base) {
  const out = [];
  const add = (u) => {
    try {
      const a = new URL(String(u).replace(/&amp;/g, "&"), base).toString();
      if (/^https?:/i.test(a) && out.indexOf(a) < 0) out.push(a);
    } catch (e) {}
  };
  let m;
  const re = /<(?:iframe|frame|embed)[^>]+?src=["']([^"']+)["']/gi;
  while ((m = re.exec(raw))) add(m[1]);
  // redirect wale pages
  const rm = /<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url=([^"'>\s]+)/gi;
  while ((m = rm.exec(raw))) add(m[1]);
  const rl = /(?:window\.|top\.|parent\.|document\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.(?:replace|assign)\(\s*["']([^"']+)["']\s*\)/gi;
  while ((m = rl.exec(raw))) { const u = m[1] || m[2]; if (u && !/^(#|javascript:)/i.test(u)) add(u); }
  return out;
}

function typeOf(u) {
  let p = u;
  try { p = new URL(u).pathname; } catch (e) {}
  return /\.mpd$/i.test(p) ? "dash" : "hls";
}

function shortUrl(u) {
  try { const x = new URL(u); return (x.host + x.pathname).slice(0, 70); } catch (e) { return String(u).slice(0, 50); }
}

function hintOf(u) {
  try {
    const x = new URL(u);
    for (const k of ["id", "ch", "channel", "c", "stream", "name"]) { const v = x.searchParams.get(k); if (v) return v; }
    const last = x.pathname.split("/").filter(Boolean).pop() || "";
    return last.length > 1 ? last : "";
  } catch (e) { return ""; }
}

async function resolveStreams(target) {
  const streams = [];
  const seenStream = new Set();
  const visited = new Set();
  const trace = [];
  let pageKey = "";
  const hint = hintOf(target);

  const addStream = (url, type, ref, key) => {
    if (seenStream.has(url)) return;
    seenStream.add(url);
    streams.push({ url: url, type: type, ref: ref || "", key: key || "" });
  };

  async function scan(pageUrl, depth, ref) {
    if (visited.has(pageUrl) || visited.size >= 22) return;
    visited.add(pageUrl);

    // link ke query mein hi stream (+key) ho to fetch ki zaroorat nahi
    const fq = depth > 0 ? fromQuery(pageUrl) : [];
    if (fq.length) {
      fq.forEach((s) => addStream(s.url, s.type, s.ref, s.key));
      trace.push("query " + shortUrl(pageUrl) + " -> " + fq.length + " stream");
      return;
    }

    let r;
    try { r = await fetch(pageUrl, { headers: pageHeaders(pageUrl, ref), redirect: "follow", signal: AbortSignal.timeout(9000) }); }
    catch (e) { trace.push(shortUrl(pageUrl) + " -> fetch fail"); return; }
    const finalUrl = r.url || pageUrl;
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    if (/mpegurl/.test(ct)) { addStream(finalUrl, "hls", ref, ""); trace.push(shortUrl(finalUrl) + " -> hls playlist"); return; }
    if (/dash\+xml/.test(ct)) { addStream(finalUrl, "dash", ref, ""); trace.push(shortUrl(finalUrl) + " -> dash manifest"); return; }
    let txt = "";
    try { txt = await r.text(); } catch (e) { return; }
    if (txt.length > 900000) txt = txt.slice(0, 900000);

    const head = txt.trimStart().slice(0, 400);
    if (head.indexOf("#EXTM3U") === 0) { addStream(finalUrl, "hls", ref, ""); trace.push(shortUrl(finalUrl) + " -> hls playlist"); return; }
    if (/<MPD[\s>]/.test(head)) { addStream(finalUrl, "dash", ref, ""); trace.push(shortUrl(finalUrl) + " -> dash manifest"); return; }

    const k = extractKey(expandText(txt));
    if (k && !pageKey) pageKey = k;

    const found = extractStreams(txt, finalUrl, hint);
    found.forEach((s) => addStream(s, typeOf(s), finalUrl, ""));
    const frames = extractIframes(txt, finalUrl);
    trace.push(shortUrl(finalUrl) + " -> HTTP " + r.status + " " + txt.length + "b, stream " + found.length + ", frame " + frames.length + (k ? ", key" : ""));
    if (streams.length) return;

    if (depth < 3) {
      for (const f of frames.slice(0, 4)) {
        await scan(f, depth + 1, finalUrl);
        if (streams.length) return;
      }
      // player page ke andar ki js / api files bhi dekho (stream wahin chhupi hoti hai)
      for (const x of extraResources(txt, finalUrl, hint).slice(0, 8)) {
        await scan(x, depth + 1, finalUrl);
        if (streams.length) return;
      }
    }
  }

  await scan(target, 0, "");
  streams.forEach((s) => { if (s.type === "dash" && !s.key && pageKey) s.key = pageKey; });
  streams.trace = trace;
  return streams;
}

// page ki same-site <script src> aur fetch("...") / .json / .php wali api files
function extraResources(raw, base, hint) {
  const out = [], seen = new Set();
  let origin = ""; try { origin = new URL(base).origin; } catch (e) {}
  const h = encodeURIComponent(hint || "");
  const add = (u0) => {
    let u = String(u0).replace(/&amp;/g, "&");
    if (/\$\{[^}]*\}|\{[a-z_]*id[a-z_]*\}/i.test(u)) { if (!h) return; u = u.replace(/\$\{[^}]*\}|\{[a-z_]*id[a-z_]*\}/gi, h); }
    if (/[{}$]/.test(u)) return;
    if (h && /[=\/]$/.test(u) && !/^(https?:)?\/\/$/.test(u)) u += h;   // "api?id=" + id wali concat
    try {
      const a = new URL(u, base);
      if (!/^https?:$/.test(a.protocol)) return;
      if (/\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|webp|mp3)$/i.test(a.pathname)) return;
      if (/(google|gstatic|facebook|twitter|cloudflare|jquery|bootstrap|fontawesome|analytics|doubleclick|googletag|disqus)/i.test(a.host)) return;
      const s = a.toString();
      if (seen.has(s) || s === base) return;
      seen.add(s); out.push(s);
    } catch (e) {}
  };
  let m;
  const rs = /<script[^>]+?src=["']([^"']+)["']/gi;
  while ((m = rs.exec(raw))) { try { if (new URL(m[1], base).origin === origin) add(m[1]); } catch (e) {} }
  const rf = /(?:fetch|axios\.get|axios|getJSON|\$\.get|\$\.ajax|\.load)\(\s*\{?\s*(?:url\s*:\s*)?["'`]([^"'`]+)["'`]/gi;
  while ((m = rf.exec(raw))) add(m[1]);
  const ro = /\.open\(\s*["'][A-Za-z]+["']\s*,\s*["'`]([^"'`]+)["'`]/gi;
  while ((m = ro.exec(raw))) add(m[1]);
  const rj = /["'`]([^"'`\s<>]+\.(?:json|php|txt|aspx?)(?:\?[^"'`\s<>]*)?)["'`]/gi;
  while ((m = rj.exec(raw))) add(m[1]);
  // api jaisi dikhne wale pehle
  const pri = (u) => (/(api|stream|chan|link|token|live|source|play|config|data|\.json|\.php)/i.test(u) ? 0 : 1);
  return out.map((u, i) => ({ u, i })).sort((a, b) => (pri(a.u) - pri(b.u)) || (a.i - b.i)).map((x) => x.u);
}

// wrapper link ke QUERY ke andar hi manifest + ClearKey hota hai:
//   .../drm?url=https://x/cenc.mpd&keys=KID:KEY
//   .../?url=https://x/a.mpd?|drmScheme=clearkey&drmLicense=KID:KEY
//   .../ios2?url=https://proxy/api/proxy?u=https://y/a.m3u8
function fromQuery(pageUrl) {
  let u; try { u = new URL(pageUrl); } catch (e) { return []; }
  if (!u.search) return [];
  let q = u.search.slice(1);
  try { q = decodeURIComponent(q); } catch (e) {}
  q = normalize(q);
  q += "\n" + decodeBlobs(q);
  let key = "";
  const km = q.match(/([0-9a-f]{32})["']?\s*[:=,]\s*["']?([0-9a-f]{32})/i);
  if (km) key = km[1].toLowerCase() + ":" + km[2].toLowerCase();
  const ref = u.origin + "/";
  const out = [], seen = new Set();
  const re = /https?:\/\/[^\s"'&|]+?\.(?:m3u8|mpd)(?:\?[^\s"'&|]*)?/gi;
  let m;
  while ((m = re.exec(q))) {
    let s = m[0].replace(/\?$/, "");
    // proxy ke andar proxy ho to sabse andar wala asli link hai
    const hits = []; const rh = /https?:\/\//gi; let h;
    while ((h = rh.exec(s))) hits.push(h.index);
    const cands = [];
    if (hits.length > 1) cands.push(s.slice(hits[hits.length - 1]));
    cands.push(s);
    for (const c of cands) {
      if (seen.has(c)) continue;
      seen.add(c);
      const t = typeOf(c);
      out.push({ url: c, type: t, ref: ref, key: t === "dash" ? key : "" });
    }
  }
  return out;
}

async function resolveAny(o) {
  const k = kindOf(o.u);
  if (k !== "web") { const one = [{ url: o.u, type: k, ref: o.r || "", key: o.k || "" }]; one.trace = ["direct link"]; return one; }
  const q = fromQuery(o.u);
  if (q.length) {
    const r = q.map((s) => Object.assign({}, s, { key: s.key || o.k || "" }));
    r.trace = ["link ke query mein stream mili: " + q.length];
    return r;
  }
  const res = await resolveStreams(o.u);
  const out = res.map((s) => Object.assign({}, s, { key: s.key || o.k || "" }));
  out.trace = res.trace || [];
  return out;
}

/* ---------------- /start ---------------- */
async function start(tok, env) {
  const o = await unseal(tok, env);
  if (!o || !o.u) return json({ ok: false, error: "token galat" }, 403);
  const frame = kindOf(o.u) === "web" ? "/f?t=" + encodeURIComponent(tok) : "";
  let streams = [];
  try { streams = await resolveAny(o); } catch (e) {}
  if (!streams.length) return json({ ok: false, error: "stream nahi mili", frame: frame });

  const out = [];
  for (const s of streams) {
    const item = {
      type: s.type,
      src: "/s?t=" + await seal({ u: s.url, r: s.ref, p: s.type === "hls" ? 1 : 0, d: s.type === "dash" ? 1 : 0 }, env)
    };
    if (s.type === "dash" && s.key) item.key = s.key;
    out.push(item);
  }
  return json({ ok: true, streams: out, frame: frame });
}

// asli (original) player ko iframe mein kholne ke liye (jab stream nikal na paaye)
async function frameRedirect(tok, env) {
  const o = await unseal(tok, env);
  if (!o || !o.u || kindOf(o.u) !== "web") return new Response("forbidden", { status: 403, headers: CORS });
  return new Response(null, { status: 302, headers: { "Location": o.u.replace(/^http:\/\//i, "https://"), "Cache-Control": "no-store" } });
}

/* ---------------- HLS playlist rewrite ---------------- */
async function rewriteM3u8(text, base, ref, self, env) {
  const P = async (u, isPl) => {
    if (/^data:/i.test(u)) return u;
    let abs;
    try { abs = new URL(u, base).toString(); } catch (e) { return u; }
    return self + "/s?t=" + await seal({ u: abs, r: ref, p: isPl ? 1 : 0 }, env);
  };
  const out = [];
  let nextIsPl = false;
  for (const line of text.split(/\r?\n/)) {
    const l = line.trim();
    if (!l) { out.push(line); continue; }
    if (l[0] === "#") {
      if (/^#EXT-X-STREAM-INF/.test(l)) nextIsPl = true;
      let nl = line;
      const ms = line.match(/URI="([^"]+)"/g) || [];
      for (const full of ms) {
        const u = full.slice(5, -1);
        const rep = 'URI="' + await P(u, /\.m3u8/i.test(u)) + '"';
        nl = nl.replace(full, () => rep);
      }
      out.push(nl);
      continue;
    }
    out.push(await P(l, nextIsPl || /\.m3u8/i.test(l)));
    nextIsPl = false;
  }
  return out.join("\n");
}

/* ---------------- DASH manifest rewrite ----------------
   Purani galti yahi thi: MPD ke relative segment links worker ke /s par
   resolve ho jaate the aur player "dash error" deta tha. Ab MPD ke andar
   ek BaseURL daal dete hain jo /p/<token>/ par jaata hai; worker wahan se
   asli origin par segment laata hai. */
async function rewriteMpd(text, base, ref, self, env) {
  const re = /<BaseURL([^>]*)>([^<]*)<\/BaseURL>/g;
  const unesc = (v) => v.trim().replace(/&amp;/g, "&");
  const px = async (abs) => self + "/p/" + await seal({ u: abs, r: ref }, env) + "/";

  const pi = text.search(/<Period[\s>]/);
  let head = pi > -1 ? text.slice(0, pi) : text;
  let tail = pi > -1 ? text.slice(pi) : "";

  let first = null;
  head = head.replace(re, (m, a, v) => { if (first === null) first = unesc(v); return ""; });
  head = head.replace(/<Location>[^<]*<\/Location>/g, "");
  let root = base;
  if (first) { try { root = new URL(first, base).toString(); } catch (e) {} }
  const tag = "<BaseURL>" + await px(root) + "</BaseURL>";
  head = head.replace(/<MPD[^>]*>/, (m) => m + tag);

  const parts = [];
  let last = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(tail))) {
    parts.push(tail.slice(last, m.index));
    const v = unesc(m[2]);
    parts.push(/^https?:\/\//i.test(v) ? "<BaseURL" + m[1] + ">" + await px(v) + "</BaseURL>" : m[0]);
    last = m.index + m[0].length;
  }
  parts.push(tail.slice(last));
  return head + parts.join("");
}

/* ---------------- /s aur /p (proxy) ---------------- */
async function proxyFetch(o, env, self, req) {
  const t = parseTarget(o && o.u);
  if (!t) return new Response("bad", { status: 400, headers: CORS });

  const h = new Headers({ "User-Agent": UA, "Accept": "*/*" });
  if (o.r) {
    try { h.set("Referer", o.r); h.set("Origin", new URL(o.r).origin); } catch (e) {}
  }
  const range = req.headers.get("Range");
  if (range) h.set("Range", range);

  let up;
  try { up = await fetch(t.toString(), { headers: h, redirect: "follow" }); }
  catch (e) { return new Response("upstream error", { status: 502, headers: CORS }); }
  const ct = (up.headers.get("content-type") || "").toLowerCase();
  const finalUrl = up.url || t.toString();
  let finalPath = "";
  try { finalPath = new URL(finalUrl).pathname; } catch (e) {}

  if (/mpegurl/.test(ct) || /\.m3u8$/i.test(finalPath) || o.p) {
    const text = await up.text();
    if (text.trimStart().startsWith("#EXTM3U")) {
      return new Response(await rewriteM3u8(text, finalUrl, o.r || "", self, env), {
        status: up.status,
        headers: Object.assign({ "Content-Type": "application/vnd.apple.mpegurl", "Cache-Control": "no-store" }, CORS)
      });
    }
    return new Response(text, { status: up.status, headers: Object.assign({ "Content-Type": ct || "text/plain" }, CORS) });
  }

  if (/dash\+xml/.test(ct) || /\.mpd$/i.test(finalPath) || o.d) {
    const text = await up.text();
    if (/<MPD[\s>]/.test(text)) {
      return new Response(await rewriteMpd(text, finalUrl, o.r || "", self, env), {
        status: up.status,
        headers: Object.assign({ "Content-Type": "application/dash+xml", "Cache-Control": "no-store" }, CORS)
      });
    }
    return new Response(text, { status: up.status, headers: Object.assign({ "Content-Type": ct || "text/plain" }, CORS) });
  }

  const rh = new Headers(CORS);
  ["content-type", "content-range", "accept-ranges", "content-length"].forEach((k) => {
    const v = up.headers.get(k);
    if (v) rh.set(k, v);
  });
  return new Response(up.body, { status: up.status, headers: rh });
}

async function stream(tok, env, self, req) {
  const o = await unseal(tok, env);
  if (!o || !o.u) return new Response("forbidden", { status: 403, headers: CORS });
  return proxyFetch(o, env, self, req);
}

// /p/<token>/<relative path...>  (DASH segments)
async function segment(pathname, search, env, self, req) {
  const rest = pathname.slice(3);                    // "<token>/<path>"
  const i = rest.indexOf("/");
  if (i < 1) return new Response("bad", { status: 400, headers: CORS });
  const o = await unseal(rest.slice(0, i), env);
  if (!o || !o.u) return new Response("forbidden", { status: 403, headers: CORS });
  let target;
  try { target = new URL(rest.slice(i + 1) + (search || ""), o.u).toString(); }
  catch (e) { return new Response("bad", { status: 400, headers: CORS }); }
  return proxyFetch({ u: target, r: o.r || "", p: 0, d: 0 }, env, self, req);
}

/* ---------------- PWA (Install App) ---------------- */
const MANIFEST = {
  name: "JAAT MATCH",
  short_name: "JAAT MATCH",
  description: "JAAT MATCH - Live Cricket",
  id: "/",
  start_url: "/",
  scope: "/",
  display: "standalone",
  orientation: "any",
  background_color: "#05070a",
  theme_color: "#05070a",
  lang: "hi",
  categories: ["sports", "entertainment"],
  icons: [
    { src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
    { src: "/icon-maskable.png", sizes: "512x512", type: "image/png", purpose: "maskable" }
  ]
};

// Service worker: sirf app ka dhancha (shell) cache hota hai. Video / list / stream kabhi nahi.
const SW_JS = [
  'var C="jaat-shell-v2";',
  'self.addEventListener("install",function(e){self.skipWaiting();e.waitUntil(caches.open(C).then(function(c){return c.addAll(["/","/manifest.webmanifest","/icon-192.png"]);}).catch(function(){}));});',
  'self.addEventListener("activate",function(e){e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k!==C;}).map(function(k){return caches.delete(k);}));}).then(function(){return self.clients.claim();}));});',
  'self.addEventListener("fetch",function(e){',
  '  var r=e.request; if(r.method!=="GET") return;',
  '  var u=new URL(r.url); if(u.origin!==location.origin) return;',
  '  if(r.mode==="navigate"||u.pathname==="/"){',
  '    e.respondWith(fetch(r).then(function(x){var cp=x.clone();caches.open(C).then(function(c){c.put("/",cp);});return x;}).catch(function(){return caches.match("/");}));',
  '    return;',
  '  }',
  '  if(u.pathname.indexOf("/icon-")===0||u.pathname==="/manifest.webmanifest"){',
  '    e.respondWith(caches.match(r).then(function(h){return h||fetch(r);}));',
  '  }',
  '});'
].join("\n");

const ICONS_B64 = {
  "icon-192.png": "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",
  "icon-512.png": "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",
  "icon-maskable.png": "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"
};
const ICON_BYTES = {};
function iconResponse(name) {
  if (!ICONS_B64[name]) return null;
  if (!ICON_BYTES[name]) {
    const bin = atob(ICONS_B64[name]);
    const b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    ICON_BYTES[name] = b;
  }
  return new Response(ICON_BYTES[name], { headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" } });
}

/* ---------------- /diag (video kyu nahi chala - jaanch) ---------------- */
async function diag(tok, env) {
  const o = await unseal(tok, env);
  if (!o || !o.u) return json({ ok: false, step: "token", note: "token galat - SOURCES / SECRET_KEY secret check karo, phir page reload karo" });
  const k = kindOf(o.u);
  let host = ""; try { host = new URL(o.u).host; } catch (e) {}
  let streams;
  try { streams = await resolveAny(o); }
  catch (e) { return json({ ok: false, step: "resolve", host, note: "page kholne mein error" }); }
  const trace = streams.trace || [];
  if (!streams.length) return json({ ok: false, step: "resolve", kind: k, host, note: "page mein koi m3u8/mpd nahi mili", trace: trace });
  const out = [];
  for (const s of streams.slice(0, 2)) {
    const h = new Headers({ "User-Agent": UA, "Accept": "*/*" });
    if (s.ref) { try { h.set("Referer", s.ref); h.set("Origin", new URL(s.ref).origin); } catch (e) {} }
    let sh = ""; try { sh = new URL(s.url).host; } catch (e) {}
    try {
      const r = await fetch(s.url, { headers: h, redirect: "follow" });
      const t = (await r.text()).slice(0, 80).replace(/\s+/g, " ");
      out.push({ type: s.type, host: sh, status: r.status, ct: r.headers.get("content-type") || "", key: s.key ? "haan" : "nahi", head: t });
    } catch (e) { out.push({ type: s.type, host: sh, status: 0, head: "fetch fail: " + String((e && e.message) || e).slice(0, 60) }); }
  }
  return json({ ok: true, kind: k, streams: out, trace: trace });
}

/* ---------------- router ---------------- */
export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const u = new URL(req.url);
    const path = u.pathname.replace(/\/+$/, "") || "/";
    try {
      if (u.pathname.indexOf("/p/") === 0) return await segment(u.pathname, u.search, env, u.origin, req);
      if (path === "/" || path === "/index.html") {
        return new Response(INDEX_HTML, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
      }
      if (path === "/list") return await list(env);
      if (path === "/start") return await start(u.searchParams.get("t"), env);
      if (path === "/diag") return await diag(u.searchParams.get("t"), env);
      if (path === "/f") return await frameRedirect(u.searchParams.get("t"), env);
      if (path === "/s") return await stream(u.searchParams.get("t"), env, u.origin, req);
      if (path === "/manifest.webmanifest") {
        return new Response(JSON.stringify(MANIFEST), { headers: { "Content-Type": "application/manifest+json; charset=utf-8", "Cache-Control": "no-cache" } });
      }
      if (path === "/sw.js") {
        return new Response(SW_JS, { headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache", "Service-Worker-Allowed": "/" } });
      }
      if (path.indexOf("/icon-") === 0) {
        const r = iconResponse(path.slice(1));
        if (r) return r;
      }
    } catch (e) {
      return json({ ok: false, error: String((e && e.message) || e) }, 500);
    }
    return new Response("not found", { status: 404, headers: CORS });
  }
};
