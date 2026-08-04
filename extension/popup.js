"use strict";
let tab, origin, records = [], pendingAllow = null;
const statusNode = document.querySelector("#status");
const recordsNode = document.querySelector("#records");

async function request(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (response && response.__error) throw new Error(response.__error);
  return response;
}
function render() {
  const query = document.querySelector("#search").value.trim().toLowerCase();
  recordsNode.replaceChildren();
  for (const record of records.filter((item) => item.name.toLowerCase().includes(query))) {
    const row = document.createElement("div"); row.className = `record ${record.allowed ? "" : "blocked"}`;
    const name = document.createElement("span"); name.textContent = record.name;
    const button = document.createElement("button"); button.textContent = record.allowed ? "Choose" : "Allow…";
    const meta = document.createElement("span"); meta.className = `meta ${record.due ? "due" : ""}`;
    meta.textContent = record.due ? "Rotation due" : record.rotate_every_days > 0 ? `Rotates every ${record.rotate_every_days} days` : "No rotation schedule";
    button.addEventListener("click", () => record.allowed ? choose(record.name) : confirmAllow(record.name));
    row.append(name, button, meta); recordsNode.append(row);
  }
}
async function choose(name) {
  try { await request({ type: "arm", tabId: tab.id, name, origin }); window.close(); }
  catch (error) { statusNode.textContent = error.message; }
}
function confirmAllow(name) {
  pendingAllow = name;
  document.querySelector("#confirm-text").textContent = `Allow ${name} to be filled only on ${origin}?`;
  document.querySelector("#confirm").showModal();
}
document.querySelector("#confirm").addEventListener("close", async (event) => {
  if (event.target.returnValue !== "default" || !pendingAllow) { pendingAllow = null; return; }
  const name = pendingAllow; pendingAllow = null;
  try { await request({ type: "allow", tabId: tab.id, name, origin }); records = await request({ type: "list", origin }); render(); }
  catch (error) { statusNode.textContent = error.message; }
});
document.querySelector("#search").addEventListener("input", render);
document.querySelector("#lock").addEventListener("click", async () => { try { await request({ type: "lock" }); } finally { window.close(); } });

(async () => {
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    origin = EnvBankCore.originFromURL(tab && tab.url || "");
    if (!origin) throw new Error("This page is not an eligible HTTPS or loopback HTTP origin");
    document.querySelector("#origin").textContent = origin;
    records = await request({ type: "list", origin });
    statusNode.textContent = records.length ? "" : "No variables found"; render();
  } catch (error) { statusNode.textContent = error.message; }
})();
