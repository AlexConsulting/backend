// app.js - Versão completa, compatível com server.js atualizado
// - Proteções contra elementos nulos
// - Suporta: score, ai_summary, technical_summary, iocs
// - Mantém modais, gráficos e relatórios

(function () {
  "use strict";

  // Utility: safe get element
  function $id(id) {
    return document.getElementById(id);
  }

  // Wait DOM ready
  document.addEventListener("DOMContentLoaded", () => {
    // --- Elements (may be null if layout missing; code tolerates it) ---
    const btnAnalyze = $id("btnAnalyze");
    const analysisType = $id("analysisType");
    const inputValue = $id("inputValue");
    const resultGrid = $id("resultGrid");
    const scoreBox = $id("riskScoreDisplay");
    const classBox = $id("classification");
    const evidenceBox = $id("evidence");
    const abuseBox = $id("abuse");
    const detailsBox = $id("details");
    const securityAnalysisBox = $id("securityAnalysis");
    const aiAnalysisBox = $id("aiAnalysis");
    const technicalSummaryBox = $id("technicalSummary");
    const reportContentBox = $id("reportContent");
    const reportQuery = $id("reportQuery");
    const reportDate = $id("reportDate");
    const btnModalDetails = $id("btnModalDetails");
    const analysisModal = $id("analysisModal");
    const scoreCanvas = $id("scoreChart");

    // Chart.js instance holder
    let scoreChartInstance = null;

    // Safe setter helpers (do nothing if element missing)
    function safeSetInnerHTML(el, html) {
      if (!el) return;
      el.innerHTML = html;
    }
    function safeSetText(el, text) {
      if (!el) return;
      el.textContent = text;
    }
    function safeEnable(el, yes) {
      if (!el) return;
      el.disabled = !yes;
    }

    // Render risk donut chart
    function renderScoreChart(score) {
      if (!scoreCanvas) return;
      const ctx = scoreCanvas.getContext("2d");
      const normalizedScore = Math.max(0, Math.min(100, Number(score) || 0));
      const remain = 100 - normalizedScore;
      const color = normalizedScore >= 70 ? "#e74c3c" : normalizedScore >= 40 ? "#f39c12" : "#2ecc71";

      // Destroy previous
      if (scoreChartInstance && typeof scoreChartInstance.destroy === "function") {
        try { scoreChartInstance.destroy(); } catch (e) { /* ignore */ }
        scoreChartInstance = null;
      }

      // create new
      try {
        scoreChartInstance = new Chart(ctx, {
          type: "doughnut",
          data: {
            labels: ["Risco", "Restante"],
            datasets: [{
              data: [normalizedScore, remain],
              backgroundColor: [color, "#e0e0e0"],
              hoverOffset: 4
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "70%",
            plugins: { legend: { display: false } }
          }
        });
      } catch (err) {
        // Chart may not be available; ignore silently
        console.warn("Chart render failed:", err && err.message);
      }
    }

    // Compact line generator for technical summary
    function compactLine(name, obj) {
      if (!obj) return `<div><strong>${escapeHtml(name)}:</strong> not queried</div>`;
      if (obj.error) {
        const reason = obj.reason || obj.detail || JSON.stringify(obj);
        return `<div><strong>${escapeHtml(name)}:</strong> ERROR - ${escapeHtml(String(reason))}</div>`;
      }

      switch (name) {
        case "vt": {
          const mal = obj.analysis?.data?.attributes?.last_analysis_stats?.malicious
                    || obj.url_obj?.data?.attributes?.last_analysis_stats?.malicious
                    || obj?.data?.attributes?.last_analysis_stats?.malicious
                    || 0;
          const sus = obj.analysis?.data?.attributes?.last_analysis_stats?.suspicious
                    || obj.url_obj?.data?.attributes?.last_analysis_stats?.suspicious
                    || obj?.data?.attributes?.last_analysis_stats?.suspicious
                    || 0;
          return `<div><strong>VirusTotal:</strong> malicious=${mal}, suspicious=${sus}</div>`;
        }
        case "urlscan": {
          const page = obj.minimal?.page || obj.page || {};
          return `<div><strong>urlscan:</strong> status ${escapeHtml(page.status || "N/A")}, ip ${escapeHtml(page.ip || "N/A")}, domainAge ${escapeHtml(page.domainAgeDays || "N/A")}</div>`;
        }
        case "google": {
          const matches = (obj.data && obj.data.matches) ? obj.data.matches.length : (obj.matches ? obj.matches.length : 0);
          return `<div><strong>WebRisk:</strong> matches ${matches}</div>`;
        }
        case "abuse": {
          // Accept multiple shapes
          const inner = obj.data?.data || obj.data || obj;
          const score = inner?.abuseConfidenceScore ?? (inner?.data?.abuseConfidenceScore) ?? "N/A";
          const reports = inner?.totalReports ?? inner?.data?.totalReports ?? "N/A";
          return `<div><strong>AbuseIPDB:</strong> score ${escapeHtml(String(score))}, reports ${escapeHtml(String(reports))}</div>`;
        }
        case "otx": {
          const pulses = obj.pulse_info?.count ?? obj.data?.pulse_info?.count ?? 0;
          return `<div><strong>OTX:</strong> pulses ${pulses}</div>`;
        }
        case "shodan": {
          if (obj.error) return `<div><strong>Shodan:</strong> error ${escapeHtml(obj.reason || obj.detail || "N/A")}</div>`;
          const ports = Array.isArray(obj?.data?.ports) ? obj.data.ports.length : (Array.isArray(obj?.ports) ? obj.ports.length : "N/A");
          return `<div><strong>Shodan:</strong> ports ${escapeHtml(String(ports))}</div>`;
        }
        case "dns": {
          try {
            const keys = Object.keys(obj).filter(k => Array.isArray(obj[k]) ? obj[k].length : !!obj[k]);
            return `<div><strong>DNS:</strong> ${keys.length ? keys.join(", ") : "no records"}</div>`;
          } catch (e) { return `<div><strong>DNS:</strong> N/A</div>`; }
        }
        default:
          return `<div><strong>${escapeHtml(name)}:</strong> ${escapeHtml(JSON.stringify(obj))}</div>`;
      }
    }

    // Escape html basic
    function escapeHtml(s) {
      if (s === null || s === undefined) return "";
      return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    }

    // Create report content (modal)
    function createReportContent(data) {
      const scoreObj = data.score || {};
      const scoreValue = (scoreObj.score !== undefined) ? scoreObj.score : (scoreObj || 0);
      const classification = scoreObj.classification || "N/A";
      const reasons = Array.isArray(scoreObj.reasons) ? scoreObj.reasons.join(", ") : (scoreObj.reasons || "Nenhum");

      let html = "";
      html += `<div class="report-section">
        <h3>Resultado Resumido</h3>
        <p><strong>Score Geral de Risco:</strong> ${escapeHtml(String(scoreValue))} / 100</p>
        <p><strong>Classificação Final:</strong> ${escapeHtml(classification)}</p>
        <p><strong>Motivos Chave (Risk Engine):</strong> ${escapeHtml(reasons)}</p>
      </div>`;

      // AI summary
      const ia = data.ai_summary;
      let iaHtml = "<p>IA: indisponível</p>";
      if (ia) {
        if (ia.error) iaHtml = `<p>🤖 IA erro: ${escapeHtml(ia.reason || ia.detail || ia.error)}</p>`;
        else if (ia.data) iaHtml = `<pre style="white-space:pre-wrap">${escapeHtml(ia.data)}</pre>`;
        else iaHtml = `<pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(ia))}</pre>`;
      }
      html += `<div class="report-section"><h3>🤖 Resumo da IA</h3>${iaHtml}</div>`;

      // Technical summary compact (vt/urlscan/abuse/otx/google/shodan/dns/geo)
      const ts = data.technical_summary || {};
      html += `<div class="report-section"><h3>Resumo Técnico (cada fonte consultada)</h3>`;
      html += compactLine("vt", ts.vt);
      html += compactLine("urlscan", ts.urlscan);
      html += compactLine("google", ts.google);
      html += compactLine("abuse", ts.abuse);
      html += compactLine("otx", ts.otx);
      html += compactLine("shodan", ts.shodan);
      html += compactLine("dns", ts.dns);
      html += `<div><strong>geo:</strong> ${escapeHtml(ts.geo?.country ?? ts.geo?.status ?? JSON.stringify(ts.geo ?? {}))}</div>`;
      html += `</div>`;

      // Evidence summary
      const ev = {
        vt: ts.vt ? (ts.vt.analysis?.data?.attributes?.last_analysis_stats || ts.vt.url_obj?.data?.attributes?.last_analysis_stats || ts.vt.data?.attributes?.last_analysis_stats) : {},
        urlscan: ts.urlscan ? (ts.urlscan.minimal?.page || ts.urlscan.page) : {},
        abuse: ts.abuse ? (ts.abuse.data || ts.abuse) : {},
        google: ts.google ? (ts.google.data || ts.google) : {}
      };

      html += `<div class="report-section"><h3>Evidências (resumidas)</h3><pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(ev, null, 2))}</pre></div>`;

      return html;
    }

    // Build ai-friendly payload (light)
    function buildAiPayload(evidence) {
      return {
        vt: {
          malicious: evidence.vt?.analysis?.data?.attributes?.last_analysis_stats?.malicious
                    || evidence.vt?.url_obj?.data?.attributes?.last_analysis_stats?.malicious
                    || 0,
          suspicious: evidence.vt?.analysis?.data?.attributes?.last_analysis_stats?.suspicious
                    || evidence.vt?.url_obj?.data?.attributes?.last_analysis_stats?.suspicious
                    || 0,
          malicious_engines: (() => {
            const res = evidence.vt?.analysis?.data?.attributes?.results
                      || evidence.vt?.url_obj?.data?.attributes?.last_analysis_results
                      || evidence.vt?.data?.attributes?.last_analysis_results
                      || {};
            return Object.entries(res)
                     .filter(([, v]) => {
                       const r = String(v?.result || v?.category || "").toLowerCase();
                       return r.includes("malicious") || r.includes("suspicious");
                     })
                     .map(([k, v]) => ({ engine: k, result: v?.result || v?.category || null }));
          })()
        },
        urlscan: {
          status: evidence.urlscan?.minimal?.page?.status || evidence.urlscan?.page?.status || null,
          ip: evidence.urlscan?.minimal?.page?.ip || evidence.urlscan?.page?.ip || null,
          domainAgeDays: evidence.urlscan?.minimal?.page?.domainAgeDays || evidence.urlscan?.page?.domainAgeDays || null,
          verdict_score: evidence.urlscan?.minimal?.verdicts?.overall?.score || evidence.urlscan?.verdicts?.overall?.score || 0
        },
        abuse: { score: evidence.abuse?.data?.data?.abuseConfidenceScore || 0 },
        webrisk: { matches: evidence.google?.data?.matches || evidence.google?.matches || [] },
        otx: { pulses: evidence.otx?.data?.pulse_info?.count || evidence.otx?.pulse_info?.count || 0 }
      };
    }

    // Call AI (server already calls Gemini server-side; here we just display) - placeholder if needed
    // Note: In current architecture the server calls Gemini and returns ai_summary, so client does not call Gemini.

    // Main analyze action (button)
    async function handleAnalyze() {
      if (!btnAnalyze) return;
      const tipo = analysisType ? analysisType.value : "url";
      const valor = inputValue ? inputValue.value.trim() : "";
      if (!valor) { alert("Digite um valor para analisar"); return; }

      // UI: prepare
      safeEnable(btnAnalyze, false);
      btnAnalyze.textContent = "⚙️ Analisando...";
      if (resultGrid) resultGrid.style.display = "grid";
      safeSetText(scoreBox, "Aguarde...");
      safeSetText(classBox, "Carregando...");
      safeSetInnerHTML(evidenceBox, "Consultando serviços...");
      safeSetInnerHTML(abuseBox, "<p>Carregando...</p>");
      safeSetInnerHTML(detailsBox, "<p>Carregando...</p>");
      safeSetInnerHTML(securityAnalysisBox, "<p>Carregando...</p>");
      safeSetInnerHTML(aiAnalysisBox, "<p>🤖 Gerando resumo de IA...</p>");
      safeSetInnerHTML(technicalSummaryBox, "<p>Resumo técnico em construção...</p>");
      safeEnable(btnModalDetails, true);

      renderScoreChart(0);

      try {
        const queryUrl = `/analisar?tipo=${encodeURIComponent(tipo)}&valor=${encodeURIComponent(valor)}`;
        const resp = await fetch(queryUrl);
        if (!resp.ok) {
          const err = await resp.json().catch(()=>({ error: `HTTP ${resp.status}` }));
          throw new Error(err.detail || err.error || `HTTP ${resp.status}`);
        }
        const data = await resp.json();

        // Validate shape
        if (!data) throw new Error("Resposta vazia do servidor");

        // Score handling
        const scoreObj = data.score || {};
        const scoreValue = (scoreObj.score !== undefined) ? scoreObj.score : (typeof scoreObj === "number" ? scoreObj : 0);
		const classification = scoreObj.classification || (scoreValue >= 70 ? "LOW" : scoreValue >= 40 ? "MEDIUM" :  "HIGH");
        //const classification = scoreObj.classification || (scoreValue >= 80 ? "HIGH" : scoreValue >= 50 ? "MEDIUM" : "LOW");
        renderScoreChart(scoreValue);
        safeSetText(scoreBox, `${scoreValue} / 100`);
        safeSetText(classBox, classification.replace("LOW","BAIXO RISCO").replace("MEDIUM","RISCO MÉDIO").replace("HIGH","ALTO RISCO"));
        classBox && (classBox.className = `classification-display ${String(classification).toLowerCase()}-risk`);

        // Technical summary compact
        const ts = data.technical_summary || {};
        let compactHtml = "";
        compactHtml += compactLine("vt", ts.vt);
        compactHtml += compactLine("urlscan", ts.urlscan);
        compactHtml += compactLine("google", ts.google);
        compactHtml += compactLine("abuse", ts.abuse);
        compactHtml += compactLine("otx", ts.otx);
        compactHtml += compactLine("shodan", ts.shodan);
        compactHtml += compactLine("dns", ts.dns);
        compactHtml += `<div><strong>geo:</strong> ${escapeHtml(ts.geo?.country ?? ts.geo?.status ?? JSON.stringify(ts.geo ?? {}))}</div>`;
        safeSetInnerHTML(technicalSummaryBox, compactHtml);

        // Abuse summary
        try {
          const a = ts.abuse?.data?.data || ts.abuse?.data || ts.abuse;
          if (a) {
            const score = a.abuseConfidenceScore ?? a.data?.abuseConfidenceScore ?? "N/A";
            const total = a.totalReports ?? a.data?.totalReports ?? "N/A";
            const isp = a.isp ?? a.org ?? a.data?.data?.isp ?? "N/A";
            safeSetInnerHTML(abuseBox, `<p><strong>Score de Confiança:</strong> ${escapeHtml(String(score))}%</p>
              <p><strong>Total de Relatórios:</strong> ${escapeHtml(String(total))}</p>
              <p><strong>ISP:</strong> ${escapeHtml(String(isp))}</p>`);
          } else {
            safeSetInnerHTML(abuseBox, `<p>Sem dados de AbuseIPDB ou não aplicável.</p>`);
          }
        } catch (e) {
          safeSetInnerHTML(abuseBox, `<p>Erro ao processar AbuseIPDB.</p>`);
        }

        // Details / Geo
        try {
          const geo = ts.geo;
          const dns = ts.dns;
          const dnsA = dns && Array.isArray(dns.A) && dns.A[0] ? dns.A[0] : null;
          let detailsHtml = "";
          if (geo && !geo.error && (geo.status === "success" || geo.country)) {
            detailsHtml += `<p><strong>IP Primário (DNS A):</strong> ${escapeHtml(dnsA || "N/A")}</p>
              <p><strong>Organização:</strong> ${escapeHtml(geo.org || "N/A")}</p>
              <p><strong>Local:</strong> ${escapeHtml(geo.city || "N/A")}, ${escapeHtml(geo.regionName || "N/A")}, ${escapeHtml(geo.country || "N/A")}</p>`;
          } else {
            detailsHtml += `<p>Sem dados de GeoIP.</p>`;
            if (dns && !dns.error) {
              const present = Object.keys(dns).filter(k => Array.isArray(dns[k]) && dns[k].length).join(", ") || "Nenhum";
              detailsHtml += `<p><strong>Registros DNS:</strong> ${escapeHtml(present)}</p>`;
            }
          }
          safeSetInnerHTML(detailsBox, detailsHtml);
        } catch (e) {
          safeSetInnerHTML(detailsBox, `<p>Erro ao montar detalhes.</p>`);
        }

        // Security summary and evidence list
        try {
          let summaryText = "";
          if (classification === "HIGH") summaryText = "🚨 ALERTA: Score alto. Investigue e bloqueie se aplicável.";
          else if (classification === "MEDIUM") summaryText = "⚠️ Risco médio. Recomendado aprofundar investigação.";
          else summaryText = "✅ Baixo risco detectado.";

          let evidenceList = "<ul>";
          // VT
          try {
            const vtObj = ts.vt || {};
            const mal = vtObj.analysis?.data?.attributes?.last_analysis_stats?.malicious
                      || vtObj.url_obj?.data?.attributes?.last_analysis_stats?.malicious || 0;
            const sus = vtObj.analysis?.data?.attributes?.last_analysis_stats?.suspicious
                      || vtObj.url_obj?.data?.attributes?.last_analysis_stats?.suspicious || 0;
            evidenceList += `<li><strong>VT:</strong> malicious=${mal}, suspicious=${sus}</li>`;

            const engines = vtObj.analysis?.data?.attributes?.results || vtObj.url_obj?.data?.attributes?.last_analysis_results || {};
            const positives = Object.entries(engines || {})
                      .filter(([, v]) => (String(v?.result || v?.category || "").toLowerCase().includes("malicious") || String(v?.result||"").toLowerCase().includes("suspicious")))
                      .map(([k]) => k);
            if (positives.length) evidenceList += `<li><strong>VT engines:</strong> ${escapeHtml(positives.join(", "))}</li>`;
          } catch (e) { /* ignore vt parse error */ }

          // WebRisk
          try {
            const matches = ts.google?.data?.matches || ts.google?.matches || [];
            if (Array.isArray(matches) && matches.length) {
              evidenceList += `<li><strong>WebRisk:</strong> ${escapeHtml(matches.map(m => m.threatType || m).join(", "))}</li>`;
            }
          } catch (e) {}

          // urlscan
          try {
            if (ts.urlscan) {
              const page = ts.urlscan.minimal?.page || ts.urlscan.page || {};
              evidenceList += `<li><strong>urlscan:</strong> status ${escapeHtml(page.status || "N/A")}, ip ${escapeHtml(page.ip || "N/A")}</li>`;
            }
          } catch (e) {}

          // abuse
          try {
            const a = ts.abuse?.data?.data || ts.abuse?.data || ts.abuse;
            if (a) evidenceList += `<li><strong>AbuseIPDB:</strong> ${escapeHtml(String(a.abuseConfidenceScore || 0))}%</li>`;
          } catch (e) {}

          evidenceList += "</ul>";
          safeSetInnerHTML(securityAnalysisBox, `<p>${escapeHtml(summaryText)}</p><p><strong>Evidências:</strong></p>${evidenceList}`);
        } catch (e) {
          safeSetInnerHTML(securityAnalysisBox, `<p>Erro ao montar resumo de segurança.</p>`);
        }

        // AI box
        try {
          const ia = data.ai_summary;
          if (!ia) safeSetInnerHTML(aiAnalysisBox, `<p>🤖 Resumo IA indisponível</p>`);
          else if (ia.error) safeSetInnerHTML(aiAnalysisBox, `<p>🤖 Erro IA: ${escapeHtml(ia.reason || ia.detail || ia.error)}</p>`);
          else if (ia.data) safeSetInnerHTML(aiAnalysisBox, `<pre style="white-space:pre-wrap">${escapeHtml(ia.data)}</pre>`);
          else safeSetInnerHTML(aiAnalysisBox, `<pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(ia))}</pre>`);
        } catch (e) {
          safeSetInnerHTML(aiAnalysisBox, `<p>🤖 Erro ao exibir IA</p>`);
        }

        // Raw technical summary for evidence panel
        try {
          safeSetInnerHTML(evidenceBox, `<pre style="white-space:pre-wrap">${escapeHtml(JSON.stringify(ts, null, 2))}</pre>`);
        } catch (e) {
          safeSetInnerHTML(evidenceBox, `<p>Erro ao mostrar evidências</p>`);
        }

        // Report modal
		try {
			if (reportQuery) reportQuery.textContent = `${escapeHtml(data.query || "")} (${escapeHtml(data.type || "")})`;
			if (reportDate) reportDate.textContent = new Date((data.timestamp || Date.now())).toLocaleString("pt-BR");
			if (reportContentBox) reportContentBox.innerHTML = createReportContent(data);
			safeEnable(btnModalDetails, true);
		}   catch (e) {
		// ignore
}

		// 🔵 SINAL FINAL: avisa o index.html que a análise terminou
		document.dispatchEvent(new Event("analysisComplete"));

      } catch (err) {
        console.error("Analyze error:", err);
        safeSetInnerHTML(aiAnalysisBox, `<p>Erro: ${escapeHtml(err.message || String(err))}</p>`);
        safeSetInnerHTML(evidenceBox, "");
        safeSetInnerHTML(technicalSummaryBox, "");
      } finally {
        safeEnable(btnAnalyze, true);
        btnAnalyze && (btnAnalyze.textContent = "🚀 Iniciar Análise");
      }
    }

    // Bind events
    if (btnAnalyze) btnAnalyze.addEventListener("click", handleAnalyze);

    // Modal handlers (if elements present)
    if (btnModalDetails && analysisModal) {
      btnModalDetails.addEventListener("click", () => { analysisModal.style.display = "block"; });
    }
    // closeBtn block removed because element does not exist);
   
	window.addEventListener("click", (ev) => {
	if (analysisModal && ev.target === analysisModal) {
	  analysisModal.style.display = "none";
	}
	});

    // Optional: pre-fill sample input from query string (convenience)
    try {
      const qs = new URLSearchParams(window.location.search);
      const v = qs.get("valor") || qs.get("value");
      const t = qs.get("tipo") || qs.get("type");
      if (v && inputValue) inputValue.value = v;
      if (t && analysisType) analysisType.value = t;
    } catch (e) { /* ignore */ }

    // Expose some debug helpers on window for console
    window.__soc_ui = {
      analyze: handleAnalyze,
      renderScoreChart,
      buildAiPayload
    };
  }); // DOMContentLoaded end
})(); // IIFE end
