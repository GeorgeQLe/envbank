(() => {
  "use strict";
  if (window.top !== window || globalThis.__envbankFillLoaded) return;
  globalThis.__envbankFillLoaded = true;
  let token = null;
  let timer = null;
  let indicator = null;

  function cleanup() {
    clearTimeout(timer); timer = null; token = null;
    document.removeEventListener("click", onClick, true);
    document.removeEventListener("keydown", onKey, true);
    chrome.runtime.onMessage.removeListener(onMessage);
    if (indicator) indicator.remove(); indicator = null;
    delete globalThis.__envbankFillLoaded;
  }
  function cancel(reason) { chrome.runtime.sendMessage({ type: "cancel-selection", reason }).catch(() => {}); cleanup(); }
  function eligible(element) {
    if (element instanceof HTMLTextAreaElement) return !element.disabled && !element.readOnly;
    if (!(element instanceof HTMLInputElement)) return false;
    return (element.type === "text" || element.type === "password") && !element.disabled && !element.readOnly;
  }
  function setNativeValue(element, value) {
    const prototype = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, "value").set;
    setter.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    element.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  }
  async function onClick(event) {
    if (!token) return;
    event.preventDefault(); event.stopImmediatePropagation();
    const element = event.target;
    if (!eligible(element)) { cancel("unsupported-field"); return; }
    const selectedToken = token;
    try {
      let response = await chrome.runtime.sendMessage({ type: "field-selected", token: selectedToken });
      if (!response || response.__error || typeof response.value !== "string") throw new Error("Fill failed");
      let value = response.value;
      response = null;
      setNativeValue(element, value);
      value = null;
    } finally { cleanup(); }
  }
  function onKey(event) { if (event.key === "Escape") cancel("escape"); }
  function onMessage(message) {
    if (message.type === "envbank-arm") {
      token = message.token;
      indicator = document.createElement("div");
      indicator.textContent = "EnvBank: click a text or password field · Esc to cancel";
      Object.assign(indicator.style, { position: "fixed", zIndex: "2147483647", top: "12px", left: "50%", transform: "translateX(-50%)", padding: "9px 13px", borderRadius: "8px", background: "#172032", color: "#fff", font: "13px system-ui", boxShadow: "0 3px 16px #0006" });
      document.documentElement.appendChild(indicator);
      document.addEventListener("click", onClick, true);
      document.addEventListener("keydown", onKey, true);
      timer = setTimeout(() => cancel("timeout"), Math.max(0, message.expires - Date.now()));
    } else if (message.type === "envbank-cancel" && (!message.token || message.token === token)) cleanup();
  }
  chrome.runtime.onMessage.addListener(onMessage);
})();
