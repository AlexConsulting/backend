
// server.js - Updated: separates AI payload and Technical Summary, IA always called.
// Keys kept as in your current code (do not change unless you want to).


const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const dns = require("dns").promises;
const { URL } = require("url");

// === NEW: Cookie parser (necessário para login) ===
const cookieParser = require("cookie-parser");
const COOKIE_SECRET = "ALTERE_ESTE_SEGREDO_123456789";


const app = express();
app.use(express.json());
app.use(cors());
// Enable cookie parser AFTER cors/json
app.use(cookieParser(COOKIE_SECRET));


// ---------------- CONFIG (kept as in your project - DO NOT CHANGE unless you want to) ----------------
const VT_KEY = "102a8c19f67898e3db47e90fee49c0ee0a315a8264d3c70099b7be84e9419aa0";
const ABUSEIPDB_KEY = "e466cbefa6796a501c6b68ced351b0951d870cf1a76dfedac8a4b735ca144f051da944f10bf739df";
const OTX_KEY = "9e13d9f198fffb5f1ea121a1f80a061ab51d79495af422af270a95e083a7426b";
const URLSCAN_KEY = "019abdb4-581e-74a8-b2c4-facff93a5087";
const GOOGLE_SAFE_KEY = "AIzaSyBQb0UOodglRRLRpUWb6V-Ucf12bbWKWyU";
const SHODAN_KEY = "wLA1or83JWGmeHODxRgizGftKE3hFMwV";
const GEMINI_API_KEY = "AIzaSyC06sD30vpLh9pY_3AZ4rQc_5gsrdkea6k";
// ---------------------------------------------------------------------------------

// Rate limiter
// app.use(rateLimit({ windowMs: 15 * 1000, max: 12 }));

// Rate limit apenas na API de análise
//app.use("/analisar", rateLimit({
  //  windowMs: 60 * 1000,  // 1 minuto
    //max: 30               // 30 análises por minuto
// }));


// Simple in-memory cache
const cache = new Map();

function cacheSet(key, value, ttlSeconds) {
  cache.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  console.log(`🟦 CACHE SET: ${key} (TTL ${ttlSeconds}s)`);
}

function cacheGet(key) {
  const e = cache.get(key);

  if (!e) {
    console.log(`❌ CACHE MISS: ${key}`);
    return null;
  }

  if (Date.now() > e.expiresAt) {
    console.log(`⏳ CACHE EXPIRED: ${key}`);
    cache.delete(key);
    return null;
  }

  console.log(`⚡ CACHE HIT: ${key}`);
  return e.value;
}

const TTL = {
  vt: 3600,
  urlscan: 3600,
  abuse: 6 * 3600,
  otx: 6 * 3600,
  google: 3600,
  shodan: 6 * 3600,
  dns: 3600,
  geo: 3600,
  ia: 12 * 3600
};

// fetch with timeout (node fetch available in Node 18+)
async function fetchTimeout(resource, options = {}, timeout = 10000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  try {
    const res = await fetch(resource, { ...options, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}


// ---------------- External queries (collect raw/technical_summary) ----------------

// VirusTotal: POST -> GET proper flow for URLs. For IP/domain/hash use dedicated endpoints.
async function vtAnalyzeUrl(urlToScan) {
  const cacheKey = `vt:url:${urlToScan}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;
  try {
    // POST to request analysis
    const params = new URLSearchParams(); params.append("url", urlToScan);
    const post = await fetchTimeout("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": VT_KEY, "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString()
    }, 12000);
    if (!post.ok) {
      const text = await post.text().catch(()=>"");
      const out = { error: true, reason: `VT POST ${post.status}`, detail: text };
      cacheSet(cacheKey,out,TTL.vt);
      return out;
    }
    const postJson = await post.json();
    // analysis id path: postJson.data.id e.g. "analysis/UUID"
    const analysisId = postJson.data && postJson.data.id;
    // Wait and GET analysis
    const get = await fetchTimeout(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { "x-apikey": VT_KEY }
    }, 12000);
    if (!get.ok) {
      const text = await get.text().catch(()=>"");
      const out = { error: true, reason: `VT GET ${get.status}`, detail: text };
      cacheSet(cacheKey,out,TTL.vt);
      return out;
    }
    const resJson = await get.json();
    // Also attempt to fetch url object (some VT data in /urls/{id})
    let urlObj = null;
    try {
      // sometimes VT returns a resource id in postJson.data.id like "analysis:....", but the url object can be fetched via /urls endpoint using base64
      const encode = Buffer.from(urlToScan).toString("base64").replace(/=+$/,'');
      const uget = await fetchTimeout(`https://www.virustotal.com/api/v3/urls/${encode}`, { headers: {"x-apikey": VT_KEY} }, 10000);
      if (uget.ok) urlObj = await uget.json();
    } catch(e){}
    const out = { analysis: resJson, url_obj: urlObj };
    cacheSet(cacheKey,out,TTL.vt);
    return out;
  } catch (err) {
    const out = { error: true, reason: "VT request failed", detail: err.message };
    cacheSet(cacheKey,out,TTL.vt);
    return out;
  }
}
async function vtLookupIp(ip) {
  const cacheKey = `vt:ip:${ip}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  try {
    const res = await fetchTimeout(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, { headers: {"x-apikey": VT_KEY} }, 10000);
    if (!res.ok) return { error:true, reason:`VT ip ${res.status}` };
    const data = await res.json();
    cacheSet(cacheKey,data,TTL.vt);
    return data;
  } catch(e){ return { error:true, reason:"vt ip error", detail:e.message }; }
}
async function vtLookupDomain(domain) {
  const cacheKey = `vt:domain:${domain}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  try {
    const res = await fetchTimeout(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, { headers: {"x-apikey": VT_KEY} }, 10000);
    if (!res.ok) return { error:true, reason:`VT domain ${res.status}` };
    const data = await res.json();
    cacheSet(cacheKey,data,TTL.vt);
    return data;
  } catch(e){ return { error:true, reason:"vt domain error", detail:e.message }; }
}
async function vtLookupHash(hash) {
  const cacheKey = `vt:hash:${hash}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  try {
    const res = await fetchTimeout(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: {"x-apikey": VT_KEY} }, 10000);
    if (!res.ok) return { error:true, reason:`VT files ${res.status}` };
    const data = await res.json();
    cacheSet(cacheKey,data,TTL.vt);
    return data;
  } catch(e){ return { error:true, reason:"vt hash error", detail:e.message }; }
}

// urlscan: submit+poll and return minimal result + full raw under technical_summary
async function urlscanScan(urlToScan) {
  const cacheKey = `urlscan:${urlToScan}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  if (!URLSCAN_KEY) return { error:true, reason:"no urlscan key" };
  try {
    const submit = await fetchTimeout("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": URLSCAN_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlToScan, visibility: "public" })
    }, 10000);
    if (!submit.ok) return { error:true, reason:`urlscan submit ${submit.status}`, detail: await submit.text().catch(()=>"") };
    const submitJson = await submit.json();
    const uuid = submitJson.uuid;
    for (let i=0;i<10;i++){
      await new Promise(r=>setTimeout(r,1500));
      const r = await fetchTimeout(`https://urlscan.io/api/v1/result/${uuid}/`, { headers: { "API-Key": URLSCAN_KEY }},8000);
      if (r.ok) {
        const data = await r.json();
        const minimal = {
          page: {
            url: data.page?.url,
            ip: data.page?.ip,
            server: data.page?.server,
            status: data.page?.status,
            tlsIssuer: data.page?.tlsIssuer,
            domainAgeDays: data.page?.domainAgeDays,
            title: data.page?.title,
            language: data.page?.language,
            redirected: data.page?.redirected
          },
          verdicts: data.verdicts,
          lists: data.lists || {}
        };
        const out = { minimal, raw: data };
        cacheSet(cacheKey,out,TTL.urlscan);
        return out;
      }
    }
    return { error:true, reason:"urlscan timeout", partial: submitJson };
  } catch(e){ return { error:true, reason:"urlscan error", detail:e.message }; }
}

// AbuseIPDB
async function abuseIpLookup(ip) {
  const cacheKey = `abuse:${ip}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  try {
    const r = await fetchTimeout(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { "Key": ABUSEIPDB_KEY, "Accept": "application/json" }
    },8000);
    if (!r.ok) return { error:true, reason:`AbuseIPDB ${r.status}`, detail: await r.text().catch(()=>"") };
    const data = await r.json();
    cacheSet(cacheKey,data,TTL.abuse);
    return data;
  } catch(e){ return { error:true, reason:"abuse error", detail:e.message }; }
}

// OTX
async function otxDomain(domain) {
  const cacheKey = `otx:${domain}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  try {
    const r = await fetchTimeout(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`, {
      headers: {"X-OTX-API-KEY": OTX_KEY}
    },8000);
    if (!r.ok) return { error:true, reason:`OTX ${r.status}`, detail: await r.text().catch(()=>"") };
    const data = await r.json();
    cacheSet(cacheKey,data,TTL.otx);
    return data;
  } catch(e){ return { error:true, reason:"otx error", detail:e.message }; }
}

// Google Safe / WebRisk
async function googleSafeLookup(urlToCheck) {
  const cacheKey = `google:${urlToCheck}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  try {
    const body = {
      client: { clientId: "soc-analyzer", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE","SOCIAL_ENGINEERING","POTENTIALLY_HARMFUL_APPLICATION","UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: urlToCheck }]
      }
    };
    const r = await fetchTimeout(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_KEY}`, {
      method:"POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify(body)
    },8000);
    if (!r.ok) return { error:true, reason:`GoogleSafe ${r.status}`, detail: await r.text().catch(()=>"") };
    const data = await r.json();
    cacheSet(cacheKey,data,TTL.google);
    return data;
  } catch(e){ return { error:true, reason:"google safe error", detail:e.message }; }
}

// Shodan (compatível com conta FREE)
async function shodanHost(ip) {
  const cacheKey = `shodan:${ip}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  if (!SHODAN_KEY) {
    const err = { error: true, reason: "missing shodan key" };
    cacheSet(cacheKey, err, TTL.shodan);
    return err;
  }

  try {
    // FREE endpoint: search by query
    const url = `https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=ip:${ip}`;
    const r = await fetchTimeout(url, {}, 8000);

    const txt = await r.text().catch(() => "");

    if (!r.ok) {
      const err = { error: true, reason: `Shodan ${r.status}`, detail: txt };
      cacheSet(cacheKey, err, TTL.shodan);
      return err;
    }

    const json = JSON.parse(txt);

    // simplified output
    const out = {
      matches: json.matches?.length || 0,
      data: json.matches || [],
      raw: json
    };

    cacheSet(cacheKey, out, TTL.shodan);
    return out;

  } catch (e) {
    const err = { error: true, reason: "shodan error", detail: e.message };
    cacheSet(cacheKey, err, TTL.shodan);
    return err;
  }
}


// DNS/Geo helpers
async function dnsInfo(hostname) {
  const cacheKey = `dns:${hostname}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  const out = {};
  try { out.A = await dns.resolve4(hostname).catch(e=>({error:e.message})); } catch(e){ out.A={error:e.message} }
  try { out.AAAA = await dns.resolve6(hostname).catch(e=>({error:e.message})); } catch(e){ out.AAAA={error:e.message} }
  try { out.MX = await dns.resolveMx(hostname).catch(e=>({error:e.message})); } catch(e){ out.MX={error:e.message} }
  try { out.NS = await dns.resolveNs(hostname).catch(e=>({error:e.message})); } catch(e){ out.NS={error:e.message} }
  try { out.TXT = await dns.resolveTxt(hostname).catch(e=>({error:e.message})); } catch(e){ out.TXT={error:e.message} }
  cacheSet(cacheKey,out,TTL.dns); return out;
}
async function geoIp(ip) {
  const cacheKey = `geo:${ip}`; const cached = cacheGet(cacheKey); if (cached) return cached;
  try {
    const r = await fetchTimeout(`http://ip-api.com/json/${encodeURIComponent(ip)}`, {},6000);
    if (!r.ok) return { error:true, reason:`ip-api ${r.status}` };
    const data = await r.json();
    cacheSet(cacheKey,data,TTL.geo);
    return data;
  } catch(e){ return { error:true, reason:"geo error", detail:e.message }; }
}

// ---------------- Risk engine normalization (same as earlier) ----------------
function normalizeVT(vt) {
  try {
    if (!vt || vt.error) return 0;
    // attempt to find stats in multiple possible shapes
    const stats = vt.analysis?.data?.attributes?.stats || vt.url_obj?.data?.attributes?.last_analysis_stats || vt?.data?.attributes?.last_analysis_stats || {};
    const mal = stats.malicious || 0;
    const sus = stats.suspicious || 0;
    if (mal === 0 && sus === 0) return 0;
    if (mal <= 2) return Math.min(40, mal * 30 + sus * 10);
    if (mal <= 5) return 60 + Math.min(20, (mal - 2) * 8 + sus * 4);
    return 90 + Math.min(10, (mal - 5) * 2);
  } catch(e){ return 0; }
}
function normalizeWebRisk(google) {
  try {
    if (!google || google.error) return 0;
    const matches = google.matches || google.data?.matches || [];
    if (!matches || !matches.length) return 0;
    let score = 0;
    for (const m of matches) {
      const t = (m.threatType || "").toUpperCase();
      if (t.includes("MALWARE")) score = Math.max(score,95);
      else if (t.includes("SOCIAL_ENGINEERING") || t.includes("PHISH")) score = Math.max(score,70);
      else score = Math.max(score,40);
    }
    return score;
  } catch(e){ return 0; }
}
function normalizeUrlscan(urlscan) {
  try {
    if (!urlscan || urlscan.error) return 0;
    const v = urlscan.minimal?.verdicts?.overall || urlscan.verdicts?.overall;
    if (v && (v.malicious || v.score > 80)) return 90;
    const page = (urlscan.minimal && urlscan.minimal.page) || urlscan.page || {};
    if (page.redirected && page.redirected !== "no") return 50;
    if ((page.domainAgeDays || 99999) < 30) return 20;
    return 0;
  } catch(e){ return 0; }
}
function normalizeAbuse(abuse) {
  try {
    const s = abuse?.data?.data?.abuseConfidenceScore || 0;
    if (s <= 10) return 0;
    if (s <= 40) return 20;
    if (s <= 70) return 50;
    if (s <= 90) return 75;
    return 90;
  } catch(e){ return 0; }
}
function normalizeOTX(otx) {
  try {
    const pulses = otx?.pulse_info?.count || otx?.data?.pulse_info?.count || 0;
    if (pulses === 0) return 0;
    if (pulses === 1) return 40;
    if (pulses <= 3) return 60;
    return 80;
  } catch(e){ return 0; }
}
function normalizeShodan(shodan) {
  try {
    const ports = shodan?.data?.ports || [];
    if (!ports || !ports.length) return 0;
    const critical = ports.filter(p => [3389,5900,23,445].includes(p)).length;
    return Math.min(80, (ports.length * 5) + (critical * 10));
  } catch(e){ return 0; }
}

const WEIGHTS = { vt:0.5, urlscan:0.2, abuse:0.15, webrisk:0.1, otx:0.05, shodan:0.05 };
function computeScoreOptimized(evidence, type='url') {
  const reasons = [];
  const vtScore = normalizeVT(evidence.vt);
  const webriskScore = normalizeWebRisk(evidence.google);
  const urlscanScore = normalizeUrlscan(evidence.urlscan);
  const abuseScore = normalizeAbuse(evidence.abuse);
  const otxScore = normalizeOTX(evidence.otx);
  const shodanScore = normalizeShodan(evidence.shodan);
  if (vtScore>0) reasons.push(`VT ${vtScore}`);
  if (webriskScore>0) reasons.push(`WebRisk ${webriskScore}`);
  if (urlscanScore>0) reasons.push(`urlscan ${urlscanScore}`);
  if (abuseScore>0) reasons.push(`AbuseIPDB ${abuseScore}`);
  if (otxScore>0) reasons.push(`OTX ${otxScore}`);
  if (shodanScore>0) reasons.push(`Shodan ${shodanScore}`);

  let final = 0;
  final += (vtScore||0)*WEIGHTS.vt;
  final += (urlscanScore||0)*WEIGHTS.urlscan;
  final += (abuseScore||0)*WEIGHTS.abuse;
  final += (webriskScore||0)*WEIGHTS.webrisk;
  final += (otxScore||0)*WEIGHTS.otx;
  if (type==='ip' || (evidence.urlscan && evidence.urlscan.minimal && evidence.urlscan.minimal.page && evidence.urlscan.minimal.page.ip)) {
    final += (shodanScore||0)*WEIGHTS.shodan;
  }
  final = Math.round(Math.max(0, Math.min(100, final)));

  if (evidence.google && (evidence.google.matches && evidence.google.matches.some(m=> (m.threatType||'').toUpperCase().includes('MALWARE')))) {
    return { score:95, classification:'HIGH', reasons:['WebRisk: MALWARE'] };
  }

  const reputables = ['kaspersky','bitdefender','microsoft','trendmicro','eset','symantec','mcafee'];
  if (evidence.vt && ((evidence.vt.analysis && evidence.vt.analysis.data) || (evidence.vt.url_obj && evidence.vt.url_obj.data))) {
    // find reputable engines in analysis or url_obj
    const res = evidence.vt.analysis?.data?.attributes?.results || evidence.vt.url_obj?.data?.attributes?.last_analysis_results || {};
    const found = Object.keys(res).find(k => reputables.some(r => k.toLowerCase().includes(r)));
    if (found && final<90) { reasons.push('VT reputable engine flagged'); final = Math.min(100, final+15); }
  }
  if (evidence.abuse && evidence.abuse.data && evidence.abuse.data.data && evidence.abuse.data.data.abuseConfidenceScore >=95 && final<90) {
    reasons.push('AbuseIPDB very high'); final = Math.min(100, final+10);
  }
  const finalClass = final>=80 ? 'HIGH' : final>=50 ? 'MEDIUM' : 'LOW';
  return { score: final, classification: finalClass, reasons };
}

// ---------------- Build aiPayload (optimized) and technical summary (complete) ----------------
function buildAiPayload(evidence) {
  // include only essential condensed fields for the AI
  return {
    vt: {
      malicious: evidence.vt.analysis?.data?.attributes?.stats?.malicious || evidence.vt.url_obj?.data?.attributes?.last_analysis_stats?.malicious || 0,
      suspicious: evidence.vt.analysis?.data?.attributes?.stats?.suspicious || evidence.vt.url_obj?.data?.attributes?.last_analysis_stats?.suspicious || 0,
      malicious_engines: (() => {
        const res = evidence.vt.analysis?.data?.attributes?.results || evidence.vt.url_obj?.data?.attributes?.last_analysis_results || {};
        return Object.entries(res).filter(([,v]) => (v.result||v.category||'').toLowerCase().includes('malicious') || (v.result||'').toLowerCase().includes('suspicious')).map(([k,v])=>({engine:k,result:v.result||v.category}));
      })()
    },
    urlscan: {
      status: evidence.urlscan?.minimal?.page?.status || evidence.urlscan?.page?.status || null,
      ip: evidence.urlscan?.minimal?.page?.ip || evidence.urlscan?.page?.ip || null,
      domainAgeDays: evidence.urlscan?.minimal?.page?.domainAgeDays || evidence.urlscan?.page?.domainAgeDays || null,
      verdict_score: (evidence.urlscan?.minimal?.verdicts?.overall?.score) || (evidence.urlscan?.verdicts?.overall?.score) || 0
    },
    abuse: { score: evidence.abuse?.data?.data?.abuseConfidenceScore || 0 },
    webrisk: { matches: evidence.google?.data?.matches || evidence.google?.matches || [] },
    otx: { pulses: evidence.otx?.data?.pulse_info?.count || evidence.otx?.pulse_info?.count || 0 }
  };
}

async function geminiAnalyze(aiPayload) {
  // IA is mandatory; use cache to reduce repeated costs
  const cacheKey = `ia:${aiPayload.vt.malicious}:${aiPayload.urlscan.ip || aiPayload.urlscan.status || ''}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;
  if (!GEMINI_API_KEY) return { error:true, reason:"no gemini key" };
  try {
    const ai = new (require("@google/genai").GoogleGenAI)({ apiKey: GEMINI_API_KEY });
    const prompt = `Analise o IOC abaixo e produza um resumo técnico objetivo (3-5 frases) em pt-BR. Dê também recomendações curtas.\n\n${JSON.stringify(aiPayload, null, 2)}`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: { temperature: 0.1 }
    });

    const out = { data: (response.text || response.output || response) };
    cacheSet(cacheKey,out,TTL.ia);
    return out;
  } catch(e){ return { error:true, reason:"gemini error", detail:e.message }; }
}

// ---------------- Analyze item ----------------
async function analyzeItem(type, value) {
  const summary = { vt:null, urlscan:null, abuse:null, otx:null, google:null, shodan:null, dns:null, geo:null };
  // determine hostname
  let hostname = null;
  if (type==='url') {
    try { hostname = (new URL(value)).hostname; } catch(e) { try { hostname = (new URL('http://'+value)).hostname } catch(e) { hostname = null; } }
  } else if (type==='domain' || type==='dominio') hostname = value;

  // DNS + geo
  if (hostname) {
    summary.dns = await dnsInfo(hostname).catch(e=>({error:e.message}));
  }

  // VT
  try {
    if (type==='url') summary.vt = await vtAnalyzeUrl(value);
    else if (type==='ip') summary.vt = await vtLookupIp(value);
    else if (type==='hash') summary.vt = await vtLookupHash(value);
    else if (type==='domain' || type==='dominio') summary.vt = await vtLookupDomain(value);
  } catch(e){ summary.vt = { error:true, detail:e.message }; }

  // Abuse (if ip)
  try {
    const ipToCheck = (type==='ip') ? value : (summary.dns && Array.isArray(summary.dns.A) && summary.dns.A[0] ? summary.dns.A[0] : null);
    if (ipToCheck) summary.abuse = await abuseIpLookup(ipToCheck);
  } catch(e){ summary.abuse = { error:true, detail:e.message }; }

  // OTX (domain)
  try { if (hostname) summary.otx = await otxDomain(hostname); } catch(e){ summary.otx = { error:true, detail:e.message }; }

  // urlscan
  try { if (type==='url') summary.urlscan = await urlscanScan(value); } catch(e){ summary.urlscan = { error:true, detail:e.message }; }

  // Google Safe
  try { if (type==='url') summary.google = await googleSafeLookup(value); } catch(e){ summary.google = { error:true, detail:e.message }; }

  // Shodan
  try {
    const ipToCheck = (type==='ip') ? value : (summary.dns && Array.isArray(summary.dns.A) && summary.dns.A[0] ? summary.dns.A[0] : null);
    if (ipToCheck) summary.shodan = await shodanHost(ipToCheck);
  } catch(e){ summary.shodan = { error:true, detail:e.message }; }

  // geo (if ip available)
  try {
    const geoIpAddr = (type==='ip') ? value : (summary.dns && Array.isArray(summary.dns.A) && summary.dns.A[0] ? summary.dns.A[0] : null);
    if (geoIpAddr) summary.geo = await geoIp(geoIpAddr);
  } catch(e){ summary.geo = { error:true, detail:e.message }; }

  // Compute score
  const score = computeScoreOptimized(summary, type);

  // build aiPayload (optimized)
  const aiPayload = buildAiPayload(summary);

  // call IA (mandatory) with optimized payload
  const ia = await geminiAnalyze(aiPayload);

  // build final output: include ai_summary (ai), score, and technical_summary (all tools and their raw/condensed responses)
  const final = {
    success: true,
    timestamp: new Date().toISOString(),
    type, query: value,
    score,
    ai_summary: ia,
    technical_summary: summary
  };
  return final;
}

// ---------------- Routes ----------------

// === NEW: Import modular routes (sempre antes de usar) ===
const authRoutes = require("./routes/authRoutes");
const plansRoutes = require("./routes/plansRoutes");
const quotaRoutes = require("./routes/quotaRoutes");
const historyRoutes = require("./routes/historyRoutes");
const profileRoutes = require("./routes/profileRoutes");

// === NEW: Activate modular routes ===
app.use("/auth", authRoutes);
app.use("/plans", plansRoutes);
app.use("/quota", quotaRoutes);
app.use("/history", historyRoutes);
app.use("/profile", profileRoutes);

const path = require("path");

// === Existing routes (mantidas) ===
app.get("/", (req,res)=> 
  res.sendFile(path.join(__dirname,"public","login.html"))
);
app.get("/analisar", async (req, res) => {
  const db = require("./db/dbmanager");

  const tipoRaw = (req.query.tipo || "").toLowerCase();
  const valor = req.query.valor || req.query.value;

  if (!valor) return res.status(400).json({ error: "Missing 'valor' parameter" });

  let tipo = "url";
  if (tipoRaw.includes("hash")) tipo = "hash";
  else if (tipoRaw.includes("ip")) tipo = "ip";
  else if (tipoRaw.includes("dom") || tipoRaw.includes("domain")) tipo = "domain";
  else if (tipoRaw.includes("text") || tipoRaw.includes("texto") || tipoRaw === "")
    tipo = (valor.length > 80 && valor.includes(" ")) ? "texto" : tipo;
  else tipo = tipoRaw;

  try {
    const out = await analyzeItem(tipo, valor);

    // =================================================
    // FIX: accept signed OR unsigned cookie (compat)
    // =================================================
    const userId = (req.signedCookies && req.signedCookies.user_id) || (req.cookies && req.cookies.user_id) || null;

    if (userId) {
      // SALVAR HISTÓRICO
      await new Promise((resolve, reject) => {
        db.addHistory(userId, valor, tipo, JSON.stringify(out), (err) => {
          if (err) {
            console.error("Erro ao salvar histórico:", err);
            reject(err);
          } else resolve();
        });
      });

      // CONSUMIR QUOTA
      await new Promise((resolve, reject) => {
        db.incrementQuota(userId, (err) => {
          if (err) {
            console.error("Erro ao incrementar quota:", err);
            reject(err);
          } else resolve();
        });
      });
    } else {
      // opcional: log para debug
      console.log("analisar: usuário não autenticado — não salvando histórico/quota");
    }

    res.json(out);

  } catch (e) {
    console.error("Erro em /analisar:", e);
    res.status(500).json({ error: "internal", detail: e.message });
  }
});

app.use(express.static(path.join(__dirname,"public")));

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`Server running on http://localhost:${PORT}`));
