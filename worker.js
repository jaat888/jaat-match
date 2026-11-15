// JAAT proxy - Cloudflare Worker
// Client sirf is worker ka link kholta hai:
//   /        -> website (index.html)
//   /list    -> channel list (names + encrypted token). Asli URL kabhi client ko nahi jata.
//   /start   -> token ko worker kholta hai, (web page ho to) page se stream nikaalta hai
//   /s       -> stream/segments proxy (playlist ke andar ke saare links bhi encrypted token mein badal deta hai)
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

// same input -> same token (stable URLs, hls.js ko fayda)
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

function kindOf(u) {
  const s = u.split("?")[0].toLowerCase();
  if (/\.m3u8$/.test(s) || s.indexOf("m3u8") > -1) return "hls";
  if (/\.mpd$/.test(s) || s.indexOf("dash") > -1) return "dash";
  if (/\.(mp4|webm|mkv|m4v)$/.test(s)) return "file";
  return "web";
}

function harvest(data) {
  const out = [], seen = {};
  function push(obj, i) {
    const url = pickUrl(obj);
    if (!url || seen[url]) return;
    seen[url] = 1;
    out.push({ name: pickName(obj, i), url: url });
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
      for (const it of items) out.push({ name: it.name, t: await seal({ u: it.url }, env) });
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

function extractStreams(raw, base) {
  const txt = normalize(raw + "\n" + decodeB64(raw));
  const found = [];
  const seen = new Set();
  const add = (u) => {
    if (/[{}$]/.test(u)) return;
    try {
      const a = new URL(u, base).toString();
      if (!/^https?:/i.test(a) || seen.has(a)) return;
      seen.add(a); found.push(a);
    } catch (e) {}
  };
  const re1 = /["'`(]\s*((?:https?:)?\/\/[^"'`\s<>)]+?\.(?:m3u8|mpd)(?:\?[^"'`\s<>)]*)?|[^"'`\s<>)]+?\.(?:m3u8|mpd)(?:\?[^"'`\s<>)]*)?)\s*["'`)]/gi;
  let m;
  while ((m = re1.exec(txt))) add(m[1]);
  const re2 = /https?:\/\/[^\s"'`<>)\\]+?\.(?:m3u8|mpd)(?:\?[^\s"'`<>)\\]*)?/gi;
  while ((m = re2.exec(txt))) add(m[0]);
  found.sort((a, b) => (/\.mpd/i.test(a) ? 1 : 0) - (/\.mpd/i.test(b) ? 1 : 0));
  return found;
}

function extractIframes(raw, base) {
  const out = [];
  const re = /<iframe[^>]+?src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(raw))) {
    try {
      const a = new URL(m[1].replace(/&amp;/g, "&"), base).toString();
      if (/^https?:/i.test(a)) out.push(a);
    } catch (e) {}
  }
  return out;
}

function typeOf(u) {
  let p = u;
  try { p = new URL(u).pathname; } catch (e) {}
  return /\.mpd$/i.test(p) ? "dash" : "hls";
}

async function resolveStreams(target) {
  const streams = [];
  const seenStream = new Set();
  const visited = new Set();

  async function scan(pageUrl, depth, ref) {
    if (visited.has(pageUrl) || visited.size >= 8) return;
    visited.add(pageUrl);
    let r;
    try { r = await fetch(pageUrl, { headers: pageHeaders(pageUrl, ref), redirect: "follow" }); }
    catch (e) { return; }
    const finalUrl = r.url || pageUrl;
    const ct = (r.headers.get("content-type") || "").toLowerCase();
    if (/mpegurl|dash\+xml/.test(ct)) {
      if (!seenStream.has(finalUrl)) { seenStream.add(finalUrl); streams.push({ url: finalUrl, type: typeOf(finalUrl), ref: ref || "" }); }
      return;
    }
    let txt = "";
    try { txt = await r.text(); } catch (e) { return; }
    if (txt.length > 1500000) txt = txt.slice(0, 1500000);

    extractStreams(txt, finalUrl).forEach((s) => {
      if (seenStream.has(s)) return;
      seenStream.add(s);
      streams.push({ url: s, type: typeOf(s), ref: finalUrl });
    });

    if (!streams.length && depth < 2) {
      const frames = extractIframes(txt, finalUrl).slice(0, 4);
      for (const f of frames) {
        await scan(f, depth + 1, finalUrl);
        if (streams.length) break;
      }
    }
  }

  await scan(target, 0, "");
  return streams;
}

/* ---------------- /start ---------------- */
async function start(tok, env) {
  const o = await unseal(tok, env);
  if (!o || !o.u) return json({ ok: false, error: "token galat" }, 403);
  const k = kindOf(o.u);
  let streams;
  if (k === "web") streams = await resolveStreams(o.u);
  else streams = [{ url: o.u, type: k, ref: o.r || "" }];
  if (!streams.length) return json({ ok: false, error: "stream nahi mili" });

  const out = [];
  for (const s of streams) {
    out.push({ type: s.type, src: "/s?t=" + await seal({ u: s.url, r: s.ref, p: s.type === "hls" ? 1 : 0 }, env) });
  }
  return json({ ok: true, streams: out });
}

/* ---------------- /s (stream proxy) ---------------- */
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

async function stream(tok, env, self, req) {
  const o = await unseal(tok, env);
  if (!o || !o.u) return new Response("forbidden", { status: 403, headers: CORS });
  const t = parseTarget(o.u);
  if (!t) return new Response("bad", { status: 400, headers: CORS });

  const h = new Headers({ "User-Agent": UA, "Accept": "*/*" });
  if (o.r) {
    try { h.set("Referer", o.r); h.set("Origin", new URL(o.r).origin); } catch (e) {}
  }
  const range = req.headers.get("Range");
  if (range) h.set("Range", range);

  const up = await fetch(t.toString(), { headers: h, redirect: "follow" });
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

  const rh = new Headers(CORS);
  ["content-type", "content-range", "accept-ranges", "content-length"].forEach((k) => {
    const v = up.headers.get(k);
    if (v) rh.set(k, v);
  });
  return new Response(up.body, { status: up.status, headers: rh });
}

/* ---------------- router ---------------- */
export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const u = new URL(req.url);
    const path = u.pathname.replace(/\/+$/, "") || "/";
    try {
      if (path === "/" || path === "/index.html") {
        return new Response(INDEX_HTML, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
      }
      if (path === "/list") return await list(env);
      if (path === "/start") return await start(u.searchParams.get("t"), env);
      if (path === "/s") return await stream(u.searchParams.get("t"), env, u.origin, req);
    } catch (e) {
      return json({ ok: false, error: String((e && e.message) || e) }, 500);
    }
    return new Response("not found", { status: 404, headers: CORS });
  }
};
