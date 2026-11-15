/* jaat-match worker
   /          -> website (public/index.html)
   /list      -> channel list (sirf naam + token, source url client ko nahi jata)
   /p?t=      -> WEB channel: source ka page laata hai, ads hatata hai, video poore frame me phailata hai
   /s?t=      -> HLS/FILE channel: stream worker se guzarta hai
   Token = AES-GCM se encrypt kiya hua url. Key: SECRET (Cloudflare me secret banao). */

var SOURCES = [
  "https://cust-1zx.pages.dev/links.json",
  "https://streamxcricket.pages.dev/links.json",
  "https://streamxcricket.pages.dev/links"
];

/* jis channel ka poora naam inme se ho wo list se hat jayega */
var BLOCK_NAMES = ["Channel 46"];

var DEFAULT_SECRET = "jaat-default-secret-change-me";

var UA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";

var CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,OPTIONS"
};

/* ---------------- token (AES-GCM) ---------------- */
var keyP = null;
function getKey(env){
  if(!keyP){
    var sec = (env && env.SECRET) || DEFAULT_SECRET;
    keyP = crypto.subtle.digest("SHA-256", new TextEncoder().encode(sec)).then(function(h){
      return crypto.subtle.importKey("raw", h, "AES-GCM", false, ["encrypt", "decrypt"]);
    });
  }
  return keyP;
}
function b64u(buf){
  var a = new Uint8Array(buf), s = "";
  for(var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64u(str){
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while(str.length % 4) str += "=";
  var b = atob(str), a = new Uint8Array(b.length);
  for(var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
  return a;
}
async function seal(env, obj){
  var key = await getKey(env);
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key,
    new TextEncoder().encode(JSON.stringify(obj))));
  var out = new Uint8Array(12 + ct.length);
  out.set(iv, 0); out.set(ct, 12);
  return b64u(out);
}
async function unseal(env, tok){
  try{
    var key = await getKey(env);
    var a = unb64u(tok);
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: a.slice(0, 12) }, key, a.slice(12));
    var o = JSON.parse(new TextDecoder().decode(pt));
    return o && o.u ? o : null;
  }catch(e){ return null; }
}

/* ---------------- list nikalna ---------------- */
var NAME_KEYS = ["name","title","channel","channelname","match","matchname","label","event","team","nm","caption","heading"];
var URL_KEYS  = ["url","link","src","stream","streamurl","file","m3u8","mpd","source","play","playurl","embed","iframe"];

function lc(s){ return String(s || "").toLowerCase().replace(/[\s_-]/g, ""); }

function pickName(o, i){
  if(typeof o === "string"){
    var base = o.split("?")[0].split("/").pop() || "";
    if(/\.(m3u8|mpd|mp4|webm)$/i.test(base)) return base.replace(/\.[a-z0-9]+$/i, "");
    return "Channel " + (i + 1);
  }
  if(!o || typeof o !== "object") return "Channel " + (i + 1);
  var keys = Object.keys(o);
  for(var k = 0; k < NAME_KEYS.length; k++){
    for(var j = 0; j < keys.length; j++){
      if(lc(keys[j]).indexOf(NAME_KEYS[k]) > -1){
        var v = o[keys[j]];
        if(typeof v === "string" && v.trim() && !/^https?:/i.test(v)) return v.trim();
        if(typeof v === "number") return String(v);
      }
    }
  }
  for(var a = 0; a < keys.length; a++){
    var vv = o[keys[a]];
    if(typeof vv === "string" && vv.trim() && !/^https?:/i.test(vv)) return vv.trim();
  }
  return "Channel " + (i + 1);
}

function pickUrl(o){
  if(typeof o === "string") return /^https?:|^\//i.test(o) ? o.trim() : "";
  if(!o || typeof o !== "object") return "";
  var keys = Object.keys(o);
  for(var k = 0; k < URL_KEYS.length; k++){
    for(var j = 0; j < keys.length; j++){
      if(lc(keys[j]).indexOf(URL_KEYS[k]) > -1){
        var v = o[keys[j]];
        if(typeof v === "string" && /^https?:|^\/\//i.test(v.trim())) return v.trim();
      }
    }
  }
  for(var a = 0; a < keys.length; a++){
    var vv = o[keys[a]];
    if(typeof vv === "string" && /^https?:\/\//i.test(vv.trim())) return vv.trim();
  }
  return "";
}

function kind(u){
  var s = u.split("?")[0].toLowerCase();
  if(/\.m3u8$/.test(s) || s.indexOf("m3u8") > -1) return "hls";
  if(/\.mpd$/.test(s) || s.indexOf("dash") > -1) return "dash";
  if(/\.(mp4|webm|mkv|m4v)$/.test(s)) return "file";
  return "web";
}

function harvest(data){
  var out = [], seen = {};

  function push(obj, i){
    var url = pickUrl(obj);
    if(!url || seen[url]) return;
    seen[url] = 1;
    out.push({ name: pickName(obj, i), url: url, kind: kind(url) });
  }

  function walk(node, depth){
    if(!node || depth > 6) return;
    if(Array.isArray(node)){
      for(var i = 0; i < node.length; i++){
        var it = node[i];
        if(typeof it === "string"){
          if(/^https?:\/\//i.test(it)) push(it, out.length);
        } else if(it && typeof it === "object"){
          if(pickUrl(it)) push(it, out.length);
          else walk(it, depth + 1);
        }
      }
      return;
    }
    if(typeof node === "object"){
      var ks = Object.keys(node), plain = 0, hits = 0;
      for(var k = 0; k < ks.length; k++){
        var v = node[ks[k]];
        if(typeof v === "string"){
          plain++;
          if(/^https?:\/\//i.test(v)){ hits++; push({ name: ks[k], url: v }, out.length); }
        }
      }
      if(plain && hits === plain) return;
      for(var m = 0; m < ks.length; m++){
        var c = node[ks[m]];
        if(c && typeof c === "object") walk(c, depth + 1);
      }
    }
  }

  walk(data, 0);

  var clean = [];
  for(var q = 0; q < out.length; q++){
    var o = out[q], bad = false;
    for(var w = 0; w < BLOCK_NAMES.length && !bad; w++){
      if(lc(o.name) === lc(BLOCK_NAMES[w])) bad = true;
    }
    if(!bad) clean.push(o);
  }
  return clean;
}

async function loadList(){
  for(var i = 0; i < SOURCES.length; i++){
    try{
      var r = await fetch(SOURCES[i], { headers: { "User-Agent": UA }, cf: { cacheTtl: 60, cacheEverything: true } });
      if(!r.ok) continue;
      var items = harvest(JSON.parse(await r.text()));
      if(items.length) return items;
    }catch(e){}
  }
  return [];
}

/* ---------------- helpers ---------------- */
function json(obj, status){
  var h = new Headers(CORS);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(obj), { status: status || 200, headers: h });
}

/* bahar ki site / bot se aayi request rok do (header ho tabhi check hota hai) */
function sameSite(req){
  var s = req.headers.get("Sec-Fetch-Site");
  return !s || s === "same-origin";
}

function srcHeaders(req, target, ref){
  var h = new Headers();
  h.set("User-Agent", UA);
  h.set("Referer", ref || (target.origin + "/"));
  h.set("Accept", req.headers.get("Accept") || "*/*");
  h.set("Accept-Language", "en-US,en;q=0.9,hi;q=0.8");
  var rng = req.headers.get("Range");
  if(rng) h.set("Range", rng);
  return h;
}

function cleanHeaders(src){
  var oh = new Headers(src);
  ["content-security-policy", "content-security-policy-report-only", "x-frame-options",
   "content-encoding", "content-length", "set-cookie"].forEach(function(k){ oh.delete(k); });
  for(var k in CORS) oh.set(k, CORS[k]);
  oh.set("Cache-Control", "no-store");
  return oh;
}

/* page ke andar daali jaane wali script + css */
var INJECT = "<style>" +
  "html,body{margin:0!important;padding:0!important;overflow:hidden!important;background:#000!important;width:100%!important;height:100%!important}" +
  ".jx-fill{position:fixed!important;top:0!important;left:0!important;right:0!important;bottom:0!important;" +
  "width:100vw!important;height:100vh!important;max-width:none!important;max-height:none!important;" +
  "margin:0!important;padding:0!important;transform:none!important;z-index:2147483000!important;" +
  "border:0!important;background:#000!important}" +
  "video.jx-fill{object-fit:contain!important}" +
  ".jx-hide{display:none!important}" +
  "</style>" +
  "<script>(function(){" +
  "try{window.open=function(){return null};}catch(e){}" +
  "var D=Document.prototype,g1=Object.getOwnPropertyDescriptor(D,'fullscreenElement'),g2=Object.getOwnPropertyDescriptor(D,'webkitFullscreenElement'),fakeOn=false,fakeEl=null;" +
  "function realFs(){try{return !!((g1&&g1.get.call(document))||(g2&&g2.get.call(document)));}catch(e){return false;}}" +
  "function fire(el){try{['fullscreenchange','webkitfullscreenchange'].forEach(function(n){el.dispatchEvent(new Event(n,{bubbles:true}));});}catch(e){}}" +
  "function fakeReq(){fakeEl=this;fakeOn=true;fire(this);return Promise.resolve();}" +
  "try{Element.prototype.requestFullscreen=fakeReq;Element.prototype.webkitRequestFullscreen=fakeReq;Element.prototype.webkitRequestFullScreen=fakeReq;}catch(e){}" +
  "function def(k,f){try{Object.defineProperty(document,k,{get:f,configurable:true});}catch(e){}}" +
  "def('fullscreenElement',function(){return fakeOn?fakeEl:(g1?g1.get.call(document):null);});" +
  "def('webkitFullscreenElement',function(){return fakeOn?fakeEl:(g2?g2.get.call(document):null);});" +
  "def('fullscreen',function(){return fakeOn||realFs();});" +
  "def('webkitIsFullScreen',function(){return fakeOn||realFs();});" +
  "def('fullscreenEnabled',function(){return true;});" +
  "def('webkitFullscreenEnabled',function(){return true;});" +
  "document.addEventListener('click',function(e){" +
  "var a=e.target&&e.target.closest?e.target.closest('a[target=_blank],a[target=_top],a[target=_parent]'):null;" +
  "if(a)e.preventDefault();},true);" +
  "var cur=null;" +
  "function area(el){var r=el.getBoundingClientRect();return r.width*r.height;}" +
  "function pick(){" +
  "if(cur&&cur.isConnected)return cur;" +
  "var best=null,ba=0,i,a,v=document.querySelectorAll('video');" +
  "for(i=0;i<v.length;i++){a=area(v[i]);if(a>ba){ba=a;best=v[i];}}" +
  "if(best&&ba>=6000)return best;" +
  "best=null;ba=0;var f=document.querySelectorAll('iframe');" +
  "for(i=0;i<f.length;i++){a=area(f[i]);if(a>ba){ba=a;best=f[i];}}" +
  "return ba>=6000?best:null;}" +
  "function skip(t){return t==='SCRIPT'||t==='STYLE'||t==='LINK'||t==='META';}" +
  "function apply(el){" +
  "var chain=[],n=el;" +
  "while(n&&n!==document.body&&n!==document.documentElement){chain.push(n);n=n.parentElement;}" +
  "var i,c,p;" +
  "for(i=0;i<chain.length;i++){" +
  "chain[i].classList.add('jx-fill');" +
  "p=chain[i].parentElement;" +
  "if(p&&(i>=2||p===document.body)){" +
  "for(c=p.firstElementChild;c;c=c.nextElementSibling){" +
  "if(c!==chain[i]&&!c.classList.contains('jx-fill')&&!skip(c.tagName))c.classList.add('jx-hide');}}}" +
  "if(el.tagName==='VIDEO'){" +
  "var root=chain[Math.min(2,chain.length-1)];" +
  "if(root){var fr=root.querySelectorAll('iframe');" +
  "for(i=0;i<fr.length;i++){if(chain.indexOf(fr[i])<0)fr[i].classList.add('jx-hide');}}}}" +
  "function run(){try{var el=pick();if(el){cur=el;el.setAttribute('data-jx','1');apply(el);}}catch(e){}}" +
  "var busy=0,own=false;" +
  "var SEL=['.vjs-fullscreen-control','.jw-icon-fullscreen','.plyr__control[data-plyr=fullscreen]','.mejs__fullscreen-button button','.fp-fullscreen','.dplayer-full-icon','.art-control-fullscreen','.shaka-fullscreen-button','.ytp-fullscreen-button','button[aria-label*=ullscreen i]','[aria-label*=ullscreen i]','[title*=ullscreen i]','[class*=fullscreen i]','[id*=fullscreen i]','[class*=-fs i]','[class*=_fs i]'];" +
  "function findBtn(){" +
  "for(var i=0;i<SEL.length;i++){var l;try{l=document.querySelectorAll(SEL[i]);}catch(e){continue;}" +
  "for(var j=0;j<l.length;j++){var b=l[j];if(b.offsetWidth>0&&b.offsetHeight>0)return b;}}" +
  "return null;}" +
  "function inFs(){return fakeOn||realFs();}" +
  "function goFs(){" +
  "if(inFs()||Date.now()-busy<900)return;busy=Date.now();" +
  "var b=findBtn();if(b){own=true;try{b.click();}catch(e){}own=false;}" +
  "setTimeout(function(){" +
  "if(inFs())return;" +
  "var t=(cur&&cur.tagName==='VIDEO')?cur:document.querySelector('video');" +
  "var el=(t&&t.parentElement)||document.documentElement;" +
  "var rq=el.requestFullscreen||el.webkitRequestFullscreen;" +
  "if(rq){try{var pr=rq.call(el);if(pr&&pr.catch)pr.catch(function(){});}catch(e){}}" +
  "},500);}" +
  "document.addEventListener('pointerup',goFs,true);" +
  "document.addEventListener('touchend',goFs,true);" +
  "function lockL(force){try{if(!realFs())return;if(!force&&window.innerHeight<=window.innerWidth)return;" +
  "if(screen.orientation&&screen.orientation.lock){var p=screen.orientation.lock('landscape');if(p&&p.catch)p.catch(function(){});}}catch(e){}}" +
  "document.addEventListener('fullscreenchange',function(){if(inFs())lockL(true);});" +
  "document.addEventListener('webkitfullscreenchange',function(){if(inFs())lockL(true);});" +
  "window.addEventListener('resize',function(){lockL(false);});" +
  "window.addEventListener('orientationchange',function(){lockL(false);});" +
  "setInterval(function(){lockL(false);},1000);" +
  "function big(el){var r=el.getBoundingClientRect();return r.width*r.height>window.innerWidth*window.innerHeight*.25;}" +
  "function fsBtn(t){if(!t||!t.closest)return null;" +
  "for(var i=0;i<SEL.length;i++){var m;try{m=t.closest(SEL[i]);}catch(e){continue;}if(m&&!big(m))return m;}" +
  "return null;}" +
  "function block(e){if(own)return;if(!(inFs()||Date.now()-busy<900))return;" +
  "if(e.type==='dblclick'||fsBtn(e.target)){e.preventDefault();e.stopImmediatePropagation();}}" +
  "document.addEventListener('click',block,true);" +
  "document.addEventListener('dblclick',block,true);" +
  "document.addEventListener('keydown',function(e){if(inFs()&&(e.key==='f'||e.key==='F')){e.preventDefault();e.stopImmediatePropagation();}},true);" +
  "try{document.exitFullscreen=function(){return Promise.resolve();};document.webkitExitFullscreen=function(){};}catch(e){}" +
  "try{var so=screen.orientation;if(so){var ol=so.lock&&so.lock.bind(so);so.unlock=function(){};if(ol)so.lock=function(){return ol('landscape');};}}catch(e){}" +
  "var TG=['t.me','telegram.me','telegram.org','telegram.dog'];" +
  "function adLink(a){var h=(a.hostname||'').toLowerCase();for(var i=0;i<TG.length;i++){if(h===TG[i]||h.slice(-TG[i].length-1)==='.'+TG[i])return true;}return false;}" +
  "function foreign(a){if(!a.protocol||a.protocol.indexOf('http')!==0)return false;try{return a.hostname!==new URL(document.baseURI).hostname;}catch(e){return false;}}" +
  "document.addEventListener('click',function(e){if(own)return;var a=e.target&&e.target.closest?e.target.closest('a[href]'):null;" +
  "if(a&&(adLink(a)||foreign(a))){e.preventDefault();e.stopImmediatePropagation();}},true);" +
  "function nuke(){try{var l=document.querySelectorAll('a[href]:not([data-jxa])');" +
  "for(var i=0;i<l.length;i++){var a=l[i];a.setAttribute('data-jxa','1');if(!adLink(a))continue;" +
  "var t=a,n=a.parentElement;" +
  "while(n&&n!==document.body&&n!==document.documentElement){" +
  "if(n.querySelector('video,iframe')||n.classList.contains('jx-fill'))break;" +
  "t=n;var p=getComputedStyle(n).position;if(p==='fixed'||p==='absolute'||p==='sticky')break;" +
  "n=n.parentElement;}" +
  "t.classList.add('jx-hide');}}catch(e){}}" +
  "try{new MutationObserver(nuke).observe(document.documentElement,{childList:true,subtree:true});}catch(e){}" +
  "nuke();" +
  "run();setInterval(run,600);" +
  "})();<\/script>";


export default {
  async fetch(req, env) {
    var self = new URL(req.url);
    var path = self.pathname;

    if(path !== "/p" && path !== "/s" && path !== "/list"){
      /* sab files ek hi folder me hain, isliye sirf website dikhao; worker.js / wrangler.toml band */
      if(path === "/" || path === "/index.html") return env.ASSETS.fetch(req);
      return new Response("not found", { status: 404 });
    }
    if(req.method === "OPTIONS") return new Response(null, { headers: CORS });

    /* ---- /list ---- */
    if(path === "/list"){
      if(!sameSite(req)) return json({ error: "no" }, 403);
      var items = await loadList();
      var out = await Promise.all(items.map(async function(it, i){
        return { id: i, name: it.name, kind: it.kind, t: await seal(env, { u: it.url }) };
      }));
      return json({ items: out });
    }

    /* ---- token kholo ---- */
    var tok = self.searchParams.get("t");
    var info = tok ? await unseal(env, tok) : null;
    if(!info) return new Response("bad token", { status: 403, headers: CORS });

    var target;
    try { target = new URL(info.u); } catch (e) { return new Response("bad url", { status: 400, headers: CORS }); }
    if(target.protocol !== "http:" && target.protocol !== "https:") {
      return new Response("bad url", { status: 400, headers: CORS });
    }

    /* ---- /s : stream (HLS / FILE / DASH) ---- */
    if(path === "/s"){
      if(!sameSite(req)) return new Response("no", { status: 403, headers: CORS });
      var sr;
      try { sr = await fetch(target.href, { headers: srcHeaders(req, target, info.r), redirect: "follow" }); }
      catch (e) { return new Response("source fail", { status: 502, headers: CORS }); }

      var sct = (sr.headers.get("content-type") || "").toLowerCase();
      var isM3u8 = sct.indexOf("mpegurl") > -1 || /\.m3u8(\?|$)/i.test(target.pathname + target.search);
      if(!isM3u8) return new Response(sr.body, { status: sr.status, headers: cleanHeaders(sr.headers) });

      var txt = await sr.text();
      if(txt.indexOf("#EXTM3U") !== 0) return new Response(txt, { status: sr.status, headers: cleanHeaders(sr.headers) });

      var base = sr.url || target.href;
      var refUrl = target.origin + "/";
      async function wrap(u){
        try{
          var abs = new URL(u, base).href;
          return self.origin + "/s?t=" + await seal(env, { u: abs, r: refUrl });
        }catch(e){ return u; }
      }
      var lines = txt.split(/\r?\n/);
      var rewritten = await Promise.all(lines.map(async function(line){
        if(!line.trim()) return line;
        if(line.charAt(0) !== "#") return await wrap(line.trim());
        var m = line.match(/URI="([^"]+)"/);
        if(!m) return line;
        return line.replace(m[0], 'URI="' + await wrap(m[1]) + '"');
      }));
      var mh = cleanHeaders(sr.headers);
      mh.set("Content-Type", "application/vnd.apple.mpegurl");
      return new Response(rewritten.join("\n"), { status: 200, headers: mh });
    }

    /* ---- /p : WEB channel page ---- */
    var r;
    try {
      r = await fetch(target.href, { headers: srcHeaders(req, target, info.r), redirect: "follow" });
    } catch (e) {
      return new Response("source fail", { status: 502, headers: CORS });
    }

    var ct = (r.headers.get("content-type") || "").toLowerCase();
    var res = new Response(r.body, { status: r.status, headers: cleanHeaders(r.headers) });
    if (ct.indexOf("text/html") < 0) return res;

    var finalUrl = r.url || target.href;
    var done = false;
    function inject(el) {
      if (done) return;
      done = true;
      el.prepend('<base href="' + finalUrl.replace(/"/g, "&quot;") + '">' + INJECT, { html: true });
    }

    return new HTMLRewriter()
      .on("head", { element: inject })
      .on("html", { element: inject })
      .on("meta", {
        element(el) {
          var h = el.getAttribute("http-equiv");
          if (h && h.toLowerCase() === "refresh") el.remove();
        }
      })
      .on("iframe", {
        async element(el) {
          var s = el.getAttribute("src");
          if (!s || /^(about:|javascript:|data:|blob:)/i.test(s.trim())) return;
          try {
            var abs = new URL(s.trim(), finalUrl).href;
            el.setAttribute("src", self.origin + "/p?t=" + await seal(env, { u: abs, r: finalUrl }));
          } catch (e) {}
        }
      })
      .transform(res);
  }
};
