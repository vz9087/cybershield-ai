const API_URL = "http://localhost:3000/api/trpc/scan.run";
const CACHE_TTL_MS = 5 * 60 * 1000;
const cache = new Map();

console.log("[CyberShield] background started");

async function getSetting(key, fallback) {
  const data = await chrome.storage.local.get(key);
  return data[key] ?? fallback;
}

async function setSetting(key, value) {
  await chrome.storage.local.set({ [key]: value });
}

async function scanUrl(url) {
  const cached = cache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.result;
  }

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        json: { scanType: "url", content: url }
      }),
    });

    if (!response.ok) {
      console.warn("[CyberShield] API error:", response.status);
      return null;
    }

    const data = await response.json();

    // tRPC v11 wraps the payload as: { result: { data: { json: {...}, meta: {...} } } }
    // Unwrap to the actual scan result.
    let result = data?.result?.data;
    if (result && typeof result === "object" && "json" in result && result.json !== null) {
      result = result.json;
    }

    if (result) {
      cache.set(url, { result, timestamp: Date.now() });
    }
    console.log("[CyberShield] scan result:", result?.riskScore, result?.riskLevel);
    return result;
  } catch (err) {
    console.warn("[CyberShield] scan failed:", err.message);
    return null;
  }
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;
  if (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://")) return;

  const autoScan = await getSetting("autoScan", true);
  if (!autoScan) return;

  const result = await scanUrl(tab.url);
  if (!result) return;

  try {
    await chrome.tabs.sendMessage(tabId, { type: "SCAN_RESULT", url: tab.url, result });
  } catch { }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_REQUEST") {
    scanUrl(message.url).then(result => sendResponse({ result }));
    return true;
  }
  if (message.type === "GET_SETTING") {
    getSetting(message.key, message.fallback).then(value => sendResponse({ value }));
    return true;
  }
  if (message.type === "SET_SETTING") {
    setSetting(message.key, message.value).then(() => sendResponse({ ok: true }));
    return true;
  }
});

