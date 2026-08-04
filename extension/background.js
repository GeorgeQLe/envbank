"use strict";
importScripts("core.js");

const sessions = new Map();
const bridge = new EnvBankCore.NativeBridge(chrome.runtime, cancelAll);

function cancel(tabId, reason) {
  const session = sessions.get(tabId);
  if (!session) return;
  sessions.delete(tabId);
  chrome.tabs.sendMessage(tabId, { type: "envbank-cancel", token: session.token, reason }).catch(() => {});
}
function cancelAll() { for (const tabId of sessions.keys()) cancel(tabId, "native-disconnect"); }
function randomToken() {
  const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}
async function currentOrigin(tabId) {
  const tab = await chrome.tabs.get(tabId);
  return EnvBankCore.originFromURL(tab.url || "");
}
async function armFill(tabId, name, origin) {
  if (await currentOrigin(tabId) !== origin) throw new Error("The tab origin changed; reopen EnvBank");
  cancel(tabId, "replaced");
  const token = randomToken();
  const expires = Date.now() + 30000;
  sessions.set(tabId, { name, origin, token, expires });
  await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ["content.js"] });
  await chrome.tabs.sendMessage(tabId, { type: "envbank-arm", token, expires });
  setTimeout(() => cancel(tabId, "timeout"), 30000);
  return { armed: true };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message.type === "list") return bridge.request("list_for_origin", { origin: message.origin });
    if (message.type === "allow") {
      if (await currentOrigin(message.tabId) !== message.origin) throw new Error("The tab origin changed; approval cancelled");
      return bridge.request("allow_origin", { name: message.name, origin: message.origin });
    }
    if (message.type === "arm") return armFill(message.tabId, message.name, message.origin);
    if (message.type === "cancel-selection" && sender.tab) { cancel(sender.tab.id, message.reason || "cancelled"); return {}; }
    if (message.type === "field-selected") {
      if (!sender.tab || sender.frameId !== 0) throw new Error("Only the top frame may request a fill");
      const session = sessions.get(sender.tab.id);
      sessions.delete(sender.tab.id);
      if (!session || session.token !== message.token || Date.now() > session.expires) throw new Error("Field selection expired");
      if (await currentOrigin(sender.tab.id) !== session.origin) throw new Error("The tab origin changed; fill cancelled");
      return bridge.request("get_for_fill", { name: session.name, origin: session.origin });
    }
    if (message.type === "lock") {
      cancelAll();
      try { await bridge.request("lock"); } finally { if (bridge.port) bridge.port.disconnect(); }
      return { locked: true };
    }
    throw new Error("Unknown extension request");
  })().then(sendResponse, (error) => sendResponse({ __error: error.message }));
  return true;
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => { if (changeInfo.url) cancel(tabId, "navigation"); });
chrome.tabs.onRemoved.addListener((tabId) => cancel(tabId, "tab-closed"));
