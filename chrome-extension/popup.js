const content = document.getElementById("content");
const autoScanToggle = document.getElementById("autoScan");

function getRiskClass(score) {
  if (score >= 71) return "high";
  if (score >= 51) return "high";
  if (score >= 31) return "medium";
  return "low";
}

function renderLoading() { content.innerHTML = `<div class="loading">Scanning current page…</div>`; }
function renderError(msg) { content.innerHTML = `<div class="error">${msg}</div>`; }

function renderResult(url, result) {
  const score = result.riskScore ?? 0;
  const cls = getRiskClass(score);
  content.innerHTML = `
    <div class="url">${url.length > 60 ? url.slice(0, 60) + "…" : url}</div>
    <div class="status ${cls}">
      <div class="score ${cls}">${score}%</div>
      <div class="level">${(result.riskLevel || "Unknown").toUpperCase()}</div>
      <div class="threat">${result.threatType || "No threat type"}</div>
    </div>
    <button class="button" id="rescan">Rescan this page</button>
  `;
  document.getElementById("rescan").addEventListener("click", scanCurrentTab);
}

async function scanCurrentTab() {
  renderLoading();
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) { renderError("Could not read the current tab."); return; }
    // Skip truly internal pages
    if (
      tab.url.startsWith("chrome://") ||
      tab.url.startsWith("chrome-extension://") ||
      tab.url.startsWith("chrome-error://") ||
      tab.url.startsWith("edge://") ||
      tab.url.startsWith("about:")
    ) {
      renderError("Cannot scan Chrome internal pages.");
      return;
    }

    // Chrome error pages don't expose the typed URL via tab.url.
    // Fall back to reading the address bar via chrome.scripting or scan history.
    // For now, ask the user to open the URL in a new tab where Chrome tries to load it.
    const response = await chrome.runtime.sendMessage({ type: "SCAN_REQUEST", url: tab.url });
    if (!response || !response.result) {
      renderError("Scan failed. Is the CyberShield API running at localhost:3000?");
      return;
    }
    renderResult(tab.url, response.result);
  } catch (err) {
    renderError("Error: " + err.message);
  }
}

(async () => {
  const { value } = await chrome.runtime.sendMessage({ type: "GET_SETTING", key: "autoScan", fallback: true });
  autoScanToggle.checked = value;
})();

autoScanToggle.addEventListener("change", async () => {
  await chrome.runtime.sendMessage({ type: "SET_SETTING", key: "autoScan", value: autoScanToggle.checked });
});

scanCurrentTab();