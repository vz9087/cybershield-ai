(function () {
  if (window.__cybershield_injected) return;
  window.__cybershield_injected = true;

  const WARNING_THRESHOLD = 31;
  const BLOCK_THRESHOLD = 51;

  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function buildOverlay(url, result) {
    const overlay = document.createElement("div");
    overlay.className = "cybershield-overlay";
    overlay.id = "cybershield-overlay";

    const riskClass = result.riskScore >= 71 ? "critical" : result.riskScore >= 51 ? "high" : "medium";
    const symbol = result.riskScore >= 71 ? "⛔" : result.riskScore >= 51 ? "⚠️" : "🔔";

    overlay.innerHTML = `
      <div class="cybershield-modal ${riskClass}">
        <div class="cs-header">
          <span class="cs-logo">🛡️</span>
          <span class="cs-brand">CyberShield AI</span>
          <button class="cs-close" aria-label="Close">×</button>
        </div>
        <div class="cs-body">
          <div class="cs-symbol">${symbol}</div>
          <div class="cs-risk">${result.riskLevel.toUpperCase()} RISK · ${result.riskScore}%</div>
          <h2 class="cs-title">${result.threatType || "Suspicious content detected"}</h2>
          <p class="cs-url">${url.length > 80 ? url.slice(0, 80) + "…" : url}</p>
          <div class="cs-recommendation">${result.recommendation || "Proceed with caution."}</div>
          <details class="cs-details">
            <summary>Why this result</summary>
            <ul>${(result.reasons || []).slice(0, 8).map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
          </details>
        </div>
        <div class="cs-actions">
          <button class="cs-btn-secondary cs-cancel">Go back (safe)</button>
          <button class="cs-btn-danger cs-proceed">Proceed anyway</button>
        </div>
      </div>
    `;
    document.documentElement.appendChild(overlay);
    document.body.style.overflow = "hidden";
    return overlay;
  }

  function showOverlay(url, result) {
    document.getElementById("cybershield-overlay")?.remove();
    const overlay = buildOverlay(url, result);
    const dismiss = () => {
      overlay.remove();
      document.body.style.overflow = "";
    };
    overlay.querySelector(".cs-close").addEventListener("click", dismiss);
    overlay.querySelector(".cs-cancel").addEventListener("click", () => { dismiss(); history.back(); });
    overlay.querySelector(".cs-proceed").addEventListener("click", dismiss);
  }

  function showBanner(url, result) {
    document.getElementById("cybershield-banner")?.remove();
    const banner = document.createElement("div");
    banner.className = "cybershield-banner";
    banner.id = "cybershield-banner";
    banner.innerHTML = `
      <span class="cs-banner-icon">🔔</span>
      <span class="cs-banner-text"><strong>CyberShield AI:</strong> ${result.riskLevel} risk (${result.riskScore}%) — ${result.threatType || "suspicious indicators"}</span>
      <button class="cs-banner-close" aria-label="Dismiss">×</button>
    `;
    document.documentElement.appendChild(banner);
    banner.querySelector(".cs-banner-close").addEventListener("click", () => banner.remove());
    setTimeout(() => banner.remove(), 12000);
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SCAN_RESULT") {
      const { url, result } = message;
      if (!result) return;
      const score = result.riskScore ?? 0;
      if (score >= BLOCK_THRESHOLD) showOverlay(url, result);
      else if (score >= WARNING_THRESHOLD) showBanner(url, result);
      sendResponse({ ok: true });
    }
    if (message.type === "SHOW_WARNING") {
      const { url, result } = message;
      if (result && result.riskScore >= BLOCK_THRESHOLD) showOverlay(url, result);
      else if (result && result.riskScore >= WARNING_THRESHOLD) showBanner(url, result);
      sendResponse({ ok: true });
    }
  });

  document.addEventListener("click", async (event) => {
    const link = event.target.closest("a");
    if (!link || !link.href) return;
    if (link.href.startsWith("javascript:") || link.href.startsWith("#")) return;
    if (link.target === "_blank") return;

    try {
      const dest = new URL(link.href);
      const current = new URL(window.location.href);
      if (dest.hostname === current.hostname && dest.pathname === current.pathname) return;
    } catch { return; }

    event.preventDefault();
    event.stopPropagation();

    try {
      const response = await chrome.runtime.sendMessage({ type: "SCAN_REQUEST", url: link.href });
      const result = response?.result;
      if (result && result.riskScore >= BLOCK_THRESHOLD) {
        showOverlay(link.href, result);
        return;
      }
      if (result && result.riskScore >= WARNING_THRESHOLD) {
        showBanner(link.href, result);
      }
      window.location.href = link.href;
    } catch {
      window.location.href = link.href;
    }
  }, true);
})();