// by Alex Silva - 2025
// server.js - Updated: separates AI payload and Technical Summary, IA always called.
// Keys by env

// ---------------------- LOAD ENV ----------------------
require('dotenv').config();

// ---------------------- REQUIRES ----------------------
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const dns = require("dns").promises;
const { URL } = require("url");
const path = require("path");
const fs = require("fs");
const winston = require("winston");

// ---------------------- LOGGER WINSTON ----------------------
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({ filename: "logs/app.log" }),
    new winston.transports.Console()
  ]
});

// Teste de arranque
logger.info("🔥 Logger iniciado com sucesso — arquivo logs/app.log gerado");

// Helpers para logs padronizados:
function logStart(action, value = "") {
  logger.info(`[START] ${action} → ${value}`);
}
function logSuccess(action, value = "") {
  logger.info(`[SUCCESS] ${action} → ${value}`);
}
function logCacheHit(action, value = "") {
  logger.info(`[CACHE HIT] ${action} → ${value}`);
}
function logError(action, error = "") {
  logger.error(`[ERROR] ${action} → ${error}`);
}

// === NEW: Cookie parser (necessário para login) ===
const cookieParser = require("cookie-parser");

// Lê o COOKIE_SECRET do arquivo .env
const COOKIE_SECRET = process.env.COOKIE_SECRET;

const app = express();
app.use(express.json());
app.use(cors());
app.use(cookieParser(COOKIE_SECRET));   // cookie parser DEVE vir antes das rotas

// ---------------- CONFIG (kept as in your project - DO NOT CHANGE unless you want to) ----------------
// Lê as chaves de API do arquivo .env
const VT_KEY = process.env.VT_KEY;
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY;
const OTX_KEY = process.env.OTX_KEY;
const URLSCAN_KEY = process.env.URLSCAN_KEY;
const GOOGLE_SAFE_KEY = process.env.GOOGLE_SAFE_KEY;
const SHODAN_KEY = process.env.SHODAN_KEY;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
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
  // Só armazene se o valor não for um erro
  if (value && value.error) {
    console.log(`🚫 Não armazenando erro no cache: ${key}`);
    return;
  }

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

// VirusTotal: Full Analysis

async function vtAnalyzeUrl(urlToScan) {
  logStart("VT ANALYZE", urlToScan);

  const cacheKey = `vt:url:${urlToScan}`;
  const cached = cacheGet(cacheKey);
  if (cached) {
    logCacheHit("VT", urlToScan);
    return cached;
  }

  try {
    // 1) POST to request VT analysis
    const params = new URLSearchParams();
    params.append("url", urlToScan);

    const post = await fetchTimeout("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": VT_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params.toString()
    }, 12000);

    if (!post.ok) {
      const text = await post.text().catch(() => "");
      const out = { error: true, reason: `VT POST ${post.status}`, detail: text };
      logError("VT POST", `${post.status} → ${text}`);
      cacheSet(cacheKey, out, TTL.vt);
      return out;
    }

    const postJson = await post.json();
    const analysisId = postJson?.data?.id;
    if (!analysisId) {
      const out = { error: true, reason: "VT missing analysisId" };
      cacheSet(cacheKey, out, TTL.vt);
      return out;
    }

    // -----------------------------
    // 2) GET loop with retries (modo máximo)
    // -----------------------------
    let analysisJson = null;

    for (let attempt = 1; attempt <= 6; attempt++) {
      const get = await fetchTimeout(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { "x-apikey": VT_KEY } },
        12000
      );

      if (!get.ok) {
        const text = await get.text().catch(() => "");
        logError("VT GET", `${get.status} → ${text}`);
        if (attempt === 6) {
          const out = { error: true, reason: `VT GET ${get.status}`, detail: text };
          cacheSet(cacheKey, out, TTL.vt);
          return out;
        }
      } else {
        analysisJson = await get.json();

        const status = analysisJson?.data?.attributes?.status;
        if (status === "completed") {
          break;
        }
      }

      logStart("VT RETRY", `Attempt ${attempt}/6 still queued... waiting 5s`);
      await new Promise(r => setTimeout(r, 5000));
    }

    if (!analysisJson) {
      const out = { error: true, reason: "VT no analysisJson after retries" };
      cacheSet(cacheKey, out, TTL.vt);
      return out;
    }

    // -----------------------------
    // 3) Fallback for complete engines
    // -----------------------------
    let urlObj = null;
    const base64 = Buffer.from(urlToScan).toString("base64").replace(/=+$/, "");

    try {
      // FIRST fallback fetch
      let uget = await fetchTimeout(
        `https://www.virustotal.com/api/v3/urls/${base64}`,
        { headers: { "x-apikey": VT_KEY } },
        12000
      );

      if (uget.ok) urlObj = await uget.json();

      // Check if engines exist; if not, fallback again after 5 seconds
      const results =
        urlObj?.data?.attributes?.last_analysis_results ||
        analysisJson?.data?.attributes?.results ||
        null;

      if (!results || Object.keys(results).length === 0) {
        logStart("VT FALLBACK", "Results incomplete — trying 2nd fallback in 5s...");
        await new Promise(r => setTimeout(r, 5000));

        uget = await fetchTimeout(
          `https://www.virustotal.com/api/v3/urls/${base64}`,
          { headers: { "x-apikey": VT_KEY } },
          12000
        );

        if (uget.ok) urlObj = await uget.json();
      }
    } catch (e) {
      logError("VT FALLBACK ERROR", e.message);
    }

    // -----------------------------
    // 4) Final output
    // -----------------------------
    const out = {
      analysis: analysisJson,
      url_obj: urlObj
    };

    cacheSet(cacheKey, out, TTL.vt);
    logSuccess("VT ANALYSIS COMPLETE", urlToScan);
    return out;

  } catch (err) {
    logError("VT FATAL", err.message);
    const out = { error: true, reason: "VT request failed", detail: err.message };
    cacheSet(cacheKey, out, TTL.vt);
    return out;
  }
}


// urlscan: submit+poll and return minimal result + full raw under technical_summary
async function urlscanScan(urlToScan) {
  logStart("URLSCAN", urlToScan);

  const cacheKey = `urlscan:${urlToScan}`; 
  const cached = cacheGet(cacheKey); 
  if (cached) {
    logCacheHit("URLSCAN", urlToScan);
    return cached;
  }

  if (!URLSCAN_KEY) {
    logError("URLSCAN", "missing key");
    return { error:true, reason:"no urlscan key" };
  }

  try {
    const submit = await fetchTimeout("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": URLSCAN_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlToScan, visibility: "public" })
    }, 10000);

    if (!submit.ok) {
      const txt = await submit.text().catch(() => "");
      logError("URLSCAN SUBMIT", `${submit.status} → ${txt}`);
      return { error:true, reason:`urlscan submit ${submit.status}`, detail: txt };
    }

    const submitJson = await submit.json();
    const uuid = submitJson.uuid;

    for (let i=0;i<25;i++){
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
        logSuccess("URLSCAN COMPLETE", urlToScan);
        return out;
      }
    }

    logError("URLSCAN TIMEOUT", urlToScan);
    return { error:true, reason:"urlscan timeout", partial: submitJson };

  } catch(e){ 
    logError("URLSCAN FATAL", e.message);
    return { error:true, reason:"urlscan error", detail:e.message }; 
  }
}

// AbuseIPDB
async function abuseIpLookup(ip) {
  logStart("ABUSEIPDB", ip);

  const cacheKey = `abuse:${ip}`; 
  const cached = cacheGet(cacheKey); 
  if (cached) {
    logCacheHit("ABUSEIPDB", ip);
    return cached;
  }

  try {
    const r = await fetchTimeout(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { "Key": ABUSEIPDB_KEY, "Accept": "application/json" }
    },8000);

    if (!r.ok) {
      const txt = await r.text().catch(()=>"");
      logError("ABUSEIPDB", `${r.status} → ${txt}`);
      return { error:true, reason:`AbuseIPDB ${r.status}`, detail: txt };
    }

    const data = await r.json();
    cacheSet(cacheKey,data,TTL.abuse);
    logSuccess("ABUSEIPDB COMPLETE", ip);
    return data;

  } catch(e){ 
    logError("ABUSEIPDB FATAL", e.message);
    return { error:true, reason:"abuse error", detail:e.message }; 
  }
}

// OTX
async function otxDomain(domain) {
  logStart("OTX", domain);

  const cacheKey = `otx:${domain}`; 
  const cached = cacheGet(cacheKey); 
  if (cached) {
    logCacheHit("OTX", domain);
    return cached;
  }

  try {
    const r = await fetchTimeout(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`, {
      headers: {"X-OTX-API-KEY": OTX_KEY}
    },8000);

    if (!r.ok) {
      const txt = await r.text().catch(()=>"");
      logError("OTX", `${r.status} → ${txt}`);
      return { error:true, reason:`OTX ${r.status}`, detail: txt };
    }

    const data = await r.json();
    cacheSet(cacheKey,data,TTL.otx);
    logSuccess("OTX COMPLETE", domain);
    return data;

  } catch(e){ 
    logError("OTX FATAL", e.message);
    return { error:true, reason:"otx error", detail:e.message }; 
  }
}

// Google Safe / WebRisk
async function googleSafeLookup(urlToCheck) {
  logStart("GOOGLE SAFE", urlToCheck);

  const cacheKey = `google:${urlToCheck}`; 
  const cached = cacheGet(cacheKey); 
  if (cached) {
    logCacheHit("GOOGLE SAFE", urlToCheck);
    return cached;
  }

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

    if (!r.ok) {
      const txt = await r.text().catch(()=>"");
      logError("GOOGLE SAFE", `${r.status} → ${txt}`);
      return { error:true, reason:`GoogleSafe ${r.status}`, detail: txt };
    }

    const data = await r.json();
    cacheSet(cacheKey,data,TTL.google);
    logSuccess("GOOGLE SAFE COMPLETE", urlToCheck);
    return data;

  } catch(e){ 
    logError("GOOGLE SAFE FATAL", e.message);
    return { error:true, reason:"google safe error", detail:e.message }; 
  }
}

// Shodan (compatível com conta FREE)
async function shodanHost(ip) {
  logStart("SHODAN", ip);

  const cacheKey = `shodan:${ip}`;
  const cached = cacheGet(cacheKey);
  if (cached) {
    logCacheHit("SHODAN", ip);
    return cached;
  }

  if (!SHODAN_KEY) {
    logError("SHODAN", "missing key");
    const err = { error: true, reason: "missing shodan key" };
    cacheSet(cacheKey, err, TTL.shodan);
    return err;
  }

  try {
    const url = `https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=ip:${ip}`;
    const r = await fetchTimeout(url, {}, 8000);

    const txt = await r.text().catch(() => "");

    if (!r.ok) {
      logError("SHODAN", `${r.status} → ${txt}`);
      const err = { error: true, reason: `Shodan ${r.status}`, detail: txt };
      cacheSet(cacheKey, err, TTL.shodan);
      return err;
    }

    const json = JSON.parse(txt);

    const matches = json.matches || [];
    const ports = matches.flatMap(match => match.ports || []);

    const out = {
      matches: matches.length,
      ports: ports,
      data: matches,
      raw: json
    };

    cacheSet(cacheKey, out, TTL.shodan);
    logSuccess("SHODAN COMPLETE", ip);
    return out;

  } catch (e) {
    logError("SHODAN FATAL", e.message);
    const err = { error: true, reason: "shodan error", detail: e.message };
    cacheSet(cacheKey, err, TTL.shodan);
    return err;
  }
}


// DNS/Geo helpers
async function dnsInfo(hostname) {
  logStart("DNS", hostname);

  const cacheKey = `dns:${hostname}`; 
  const cached = cacheGet(cacheKey); 
  if (cached) {
    logCacheHit("DNS", hostname);
    return cached;
  }

  const out = {};
  try { out.A = await dns.resolve4(hostname).catch(e=>({error:e.message})); } catch(e){ out.A={error:e.message} }
  try { out.AAAA = await dns.resolve6(hostname).catch(e=>({error:e.message})); } catch(e){ out.AAAA={error:e.message} }
  try { out.MX = await dns.resolveMx(hostname).catch(e=>({error:e.message})); } catch(e){ out.MX={error:e.message} }
  try { out.NS = await dns.resolveNs(hostname).catch(e=>({error:e.message})); } catch(e){ out.NS={error:e.message} }
  try { out.TXT = await dns.resolveTxt(hostname).catch(e=>({error:e.message})); } catch(e){ out.TXT={error:e.message} }

  cacheSet(cacheKey,out,TTL.dns); 
  logSuccess("DNS COMPLETE", hostname);
  return out;
}

async function geoIp(ip) {
  logStart("GEOIP", ip);

  const cacheKey = `geo:${ip}`; 
  const cached = cacheGet(cacheKey); 
  if (cached) {
    logCacheHit("GEOIP", ip);
    return cached;
  }

  try {
    const r = await fetchTimeout(`http://ip-api.com/json/${encodeURIComponent(ip)}`, {},6000);
    if (!r.ok) {
      logError("GEOIP", `${r.status}`);
      return { error:true, reason:`ip-api ${r.status}` };
    }

    const data = await r.json();
    cacheSet(cacheKey,data,TTL.geo);
    logSuccess("GEOIP COMPLETE", ip);
    return data;

  } catch(e){ 
    logError("GEOIP FATAL", e.message);
    return { error:true, reason:"geo error", detail:e.message }; 
  }
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
      if (t.includes("MALWARE")) score = Math.max(score,95);  // Prioriza malware
      else if (t.includes("SOCIAL_ENGINEERING") || t.includes("PHISH")) score = Math.max(score,90);  // Prioriza phishing
      else score = Math.max(score,40);  // Outros tipos de ameaça têm menor impacto
    }
    return score;
  } catch(e){ return 0; }
}

function normalizeUrlscan(urlscan) {
  try {
    if (!urlscan || urlscan.error) return 0;
    const v = urlscan.minimal?.verdicts?.overall || urlscan.verdicts?.overall;
    if (v && (v.malicious || v.score > 80)) return 90;  // Major risk for malicious URLs
    const page = (urlscan.minimal && urlscan.minimal.page) || urlscan.page || {};
    if (page.redirected && page.redirected !== "no") return 50;  // Risco médio se houver redirecionamento
    if ((page.domainAgeDays || 99999) < 30) return 20;  // Sites novos têm menor confiança
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
    return 90;  // Score muito alto para confiança de abuso
  } catch(e){ return 0; }
}

function normalizeOTX(otx) {
  try {
    const pulses = otx?.pulse_info?.count || otx?.data?.pulse_info?.count || 0;
    if (pulses === 0) return 0;
    if (pulses === 1) return 40;
    if (pulses <= 3) return 60;
    return 80;  // Melhorar pontuação se houver mais de 3 pulsos
  } catch(e){ return 0; }
}

function normalizeShodan(shodan) {
  try {
    const ports = shodan?.data?.ports || [];
    if (!ports || !ports.length) return 0;
    const critical = ports.filter(p => [3389,5900,23,445].includes(p)).length;
    return Math.min(80, (ports.length * 5) + (critical * 15));  // Ajuste para portas críticas
  } catch(e){ return 0; }
}

// ---------------- Adjusted WEIGHTS for Dynamic Impact ----------------
const WEIGHTS = { 
  vt: 0.7,   // Aumentando o peso do VT para 70%
  urlscan: 0.15,  // Menor peso para o Urlscan
  abuse: 0.1,     // Peso reduzido para AbuseIPDB
  webrisk: 0.05,   // Peso reduzido para WebRisk
  otx: 0.05,      // Peso reduzido para OTX
  shodan: 0.05     // Peso reduzido para Shodan
};

// ---------------- Compute Score ----------------
function computeScoreOptimized(evidence, type='url') {
  const reasons = [];
  const vtScore = normalizeVT(evidence.vt);
  const webriskScore = normalizeWebRisk(evidence.google);
  const urlscanScore = normalizeUrlscan(evidence.urlscan);
  const abuseScore = normalizeAbuse(evidence.abuse);
  const otxScore = normalizeOTX(evidence.otx);
  const shodanScore = normalizeShodan(evidence.shodan);

  if (vtScore > 0) reasons.push(`VT ${vtScore}`);
  if (webriskScore > 0) reasons.push(`WebRisk ${webriskScore}`);
  if (urlscanScore > 0) reasons.push(`urlscan ${urlscanScore}`);
  if (abuseScore > 0) reasons.push(`AbuseIPDB ${abuseScore}`);
  if (otxScore > 0) reasons.push(`OTX ${otxScore}`);
  if (shodanScore > 0) reasons.push(`Shodan ${shodanScore}`);

  let final = 0;
  
  // Adicionando peso maior para VirusTotal se estiver indicando risco
  final += (vtScore || 0) * WEIGHTS.vt;
  final += (urlscanScore || 0) * WEIGHTS.urlscan;
  final += (abuseScore || 0) * WEIGHTS.abuse;
  final += (webriskScore || 0) * WEIGHTS.webrisk;
  final += (otxScore || 0) * WEIGHTS.otx;
  if (type === 'ip' || (evidence.urlscan && evidence.urlscan.minimal && evidence.urlscan.minimal.page && evidence.urlscan.minimal.page.ip)) {
    final += (shodanScore || 0) * WEIGHTS.shodan;
  }

  // Ajuste para discrepâncias: aumenta o score se VirusTotal indicar risco
  if (vtScore >= 60 && !reasons.some(r => r.includes("WebRisk") || r.includes("urlscan"))) {
    final += 10;  // Aumenta a pontuação se VT indicar risco alto e outras fontes não reportarem risco
    reasons.push("Ajuste devido ao alto risco no VirusTotal (6 motores maliciosos)");
  }

  final = Math.round(Math.max(0, Math.min(100, final)));

  // Classificação final
  const finalClass = final >= 80 ? 'HIGH' : final >= 50 ? 'MEDIUM' : 'LOW';

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
        return Object.entries(res).filter(([, v]) => (v.result || v.category || '').toLowerCase().includes('malicious') || (v.result || '').toLowerCase().includes('suspicious')).map(([k, v]) => ({ engine: k, result: v.result || v.category }));
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

// Função para validar a resposta da IA (Google Gemini)
function validateAiResponse(response) {
  if (!response || !response.text) {
    console.log("🚫 Resposta inválida ou vazia da IA");
    return { error: true, reason: "Resposta inválida da IA" };
  }
  return { data: response.text };
}

// Função otimizada para chamar a IA (Google Gemini)
async function geminiAnalyze(aiPayload) {
  const cacheKey = `ia:${aiPayload.vt.malicious}:${aiPayload.urlscan.ip || aiPayload.urlscan.status || ''}`;
  
  // Verificar cache primeiro
  const cached = cacheGet(cacheKey);
  if (cached) {
    console.log(`⚡ CACHE HIT para IA: ${cacheKey}`);
    return cached;
  }

  if (!GEMINI_API_KEY) {
    console.log("❌ Falha: API Key do Gemini não encontrada");
    return { error: true, reason: "no gemini key" };
  }

  try {
    console.log("🔄 Chamando a IA (Gemini)...");

    const ai = new (require("@google/genai").GoogleGenAI)({ apiKey: GEMINI_API_KEY });
    const prompt = `Analise o IOC abaixo e produza um resumo técnico objetivo (3-5 frases) em pt-BR. Dê também recomendações curtas.\n\n${JSON.stringify(aiPayload, null, 2)}`;

    // Requisição à IA
    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      config: { temperature: 0.1 }
    });

    // Validar resposta
    const validResponse = validateAiResponse(response);
    if (validResponse.error) {
      console.log("🚫 Erro na resposta da IA");
      return validResponse;
    }

    // Armazenar no cache com TTL
    cacheSet(cacheKey, validResponse, TTL.ia);
    console.log("✅ Resposta da IA processada com sucesso");
    return validResponse;

  } catch (e) {
    console.error("❌ Erro ao chamar Gemini:", e);
    return { error: true, reason: "gemini error", detail: e.message };
  }
}

// Helper function to get IP from DNS
function getIpFromDns(dns) {
  return (dns && Array.isArray(dns.A) && dns.A[0]) || null;
}
// ------------------------------------------------------
// fetchTimeout (necessário para o health check funcionar)
// ------------------------------------------------------
async function fetchTimeout(resource, options = {}, timeout = 5000) {
  return Promise.race([
    fetch(resource, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), timeout)
    )
  ]);
}

// =====================
// HEALTH CHECK (com cache de 5 minutos)
// =====================

let lastHealthStatus = null;
let lastHealthTime = 0;
const HEALTH_TTL_MS = 5 * 60 * 1000; // 5 minutos

// Testa apenas se a URL responde 200-399
async function checkApi(name, url) {
  try {
    const r = await fetchTimeout(
      url,
      {
        method: "GET",
        redirect: "follow",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
      },
      5000
    );

    const ok = r.ok || (r.status >= 200 && r.status < 400);

    return { ok, status: r.status };
  } catch (err) {
    return { ok: false, status: "OFFLINE", error: err.message };
  }
}

async function healthCheckAllApis() {
  const now = Date.now();

  // ---------- CACHE VÁLIDO ----------
  if (lastHealthStatus && (now - lastHealthTime) < HEALTH_TTL_MS) {
    console.log("🔵 [HEALTH] usando cache (válido)");
    return lastHealthStatus;
  }

  console.log("🟠 [HEALTH] cache expirado → realizando health check real...");

  // ---------- TESTE REAL ----------
  const results = {
    vt:      await checkApi("vt",      "https://www.virustotal.com/"),
    urlscan: await checkApi("urlscan", "https://urlscan.io/"),
    google:  await checkApi("google",  "https://safebrowsing.googleapis.com/"),
    shodan:  await checkApi("shodan",  "https://api.shodan.io/"),
    abuse:   await checkApi("abuse",   "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8"),
    geo:     await checkApi("geo",     "http://ip-api.com/json/")
  };

  // Salva no cache
  lastHealthStatus = results;
  lastHealthTime = now;

  console.log("🟢 [HEALTH] atualizado:", results);

  return results;
}

// ------------------------------------------------------
// Helper function to safely call async functions
// ------------------------------------------------------
async function safeAsyncCall(fn) {
  try {
    return await fn();
  } catch (e) {
    return { error: true, detail: e.message };
  }
}

// ------------------------------------------------------
// ANALYZE ITEM — COM HEALTH CHECK + FAIL-SAFE + CACHE
// ------------------------------------------------------

// ---------------- Analyze item ----------------
async function analyzeItem(type, value) {

  const summary = { vt:null, urlscan:null, abuse:null, otx:null, google:null, shodan:null, dns:null, geo:null };

  // ---------------- HEALTH CHECK DAS APIS (com cache) ----------------
  const apiStatus = await healthCheckAllApis();
  console.log("[API STATUS]", apiStatus);

  // ---------------- DNS + GEO ----------------
  let hostname = null;
  if (type === 'url') {
    try { 
      hostname = (new URL(value)).hostname; 
    } catch(e) {
      try { hostname = (new URL('http://' + value)).hostname; }
      catch(e) { hostname = null; }
    }
  } else if (type === 'domain' || type === 'dominio') {
    hostname = value;
  }

  if (hostname) {
    summary.dns = await dnsInfo(hostname).catch(e => ({ error: e.message }));
  }

  // ---------------- ANÁLISES EM PARALELO ----------------
  const [
    vtResponse,
    abuseResponse,
    urlscanResponse,
    googleResponse,
    shodanResponse,
    geoResponse
  ] = await Promise.all([

    // ---- VIRUSTOTAL ----
    safeAsyncCall(() => {
      if (!apiStatus.vt.ok) {
        console.warn("[VT] Ignorando → API Offline");
        return { error: true, reason: "VT Offline" };
      }
      if (type === 'url') return vtAnalyzeUrl(value);
      if (type === 'ip') return vtLookupIp(value);
      if (type === 'hash') return vtLookupHash(value);
      if (type === 'domain' || type === 'dominio') return vtLookupDomain(value);
      return null;
    }),

    // ---- ABUSEIPDB ----
    safeAsyncCall(() => {
      if (!apiStatus.abuse.ok) {
        console.warn("[ABUSEIPDB] Ignorando → API Offline");
        return { error: true, reason: "AbuseIPDB Offline" };
      }
      return type === "ip" ? abuseIpLookup(value) : null;
    }),

    // ---- URLSCAN ----
    safeAsyncCall(() => {
      if (!apiStatus.urlscan.ok) {
        console.warn("[URLSCAN] Ignorando → API Offline");
        return { error: true, reason: "URLScan Offline" };
      }
      return type === "url" ? urlscanScan(value) : null;
    }),

    // ---- GOOGLE SAFE BROWSING ----
    safeAsyncCall(() => {
      if (!apiStatus.google.ok) {
        console.warn("[GOOGLE SAFE] Ignorando → API Offline");
        return { error: true, reason: "Google SafeBrowsing Offline" };
      }
      return type === "url" ? googleSafeLookup(value) : null;
    }),

    // ---- SHODAN ----
    safeAsyncCall(() => {
      const ipToCheck = (type === 'ip') ? value : getIpFromDns(summary.dns);
      if (!ipToCheck) return null;

      if (!apiStatus.shodan.ok) {
        console.warn("[SHODAN] Ignorando → API Offline");
        return { error: true, reason: "Shodan Offline" };
      }
      return shodanHost(ipToCheck);
    }),

    // ---- GEOIP ----
    safeAsyncCall(() => {
      const geoIpAddr = (type === 'ip') ? value : getIpFromDns(summary.dns);
      if (!geoIpAddr) return null;

      if (!apiStatus.geo.ok) {
        console.warn("[GEOIP] Ignorando → API Offline");
        return { error: true, reason: "GeoIP Offline" };
      }
      return geoIp(geoIpAddr);
    })
  ]);

  // ---------------- PREENCHER RESULTADOS ----------------
  summary.vt = vtResponse;
  summary.abuse = abuseResponse;
  summary.urlscan = urlscanResponse;
  summary.google = googleResponse;
  summary.shodan = shodanResponse;
  summary.geo = geoResponse;

  // ---------------- SCORE / IA ----------------
  const score = computeScoreOptimized(summary, type);
  const aiPayload = buildAiPayload(summary);
  const ia = await geminiAnalyze(aiPayload);

  // ---------------- OUTPUT FINAL ----------------
  return {
    success: true,
    timestamp: new Date().toISOString(),
    type,
    query: value,
    score,
    ai_summary: ia,
    technical_summary: summary
  };
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

//const path = require("path");

// === Redirecionamento para login se não autenticado ===
app.get('/index.html', (req, res) => {
  // Verificar se o usuário está autenticado (verificando o cookie ou sessão)
  if (!req.cookies.user_id) { // Ou qualquer outra lógica de autenticação que você use
    return res.redirect('/login.html'); // Redireciona para a página de login
  }
  // Se estiver autenticado, envia o arquivo index.html
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// === Existing routes (mantidas) ===
app.get("/", (req,res)=> 
  res.sendFile(path.join(__dirname,"public","login.html"))
);

// Restante das suas rotas já existentes
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
