(() => {
  "use strict";
  if (window.top !== window || globalThis.__envbankProtectedLoaded) return;
  globalThis.__envbankProtectedLoaded = true;
  let token, timer, indicator, input, fieldHandle, selectedForm;
  const opaque = () => {
    const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  };
  function cleanup() {
    clearTimeout(timer); token = null;
    document.removeEventListener("click", click, true);
    document.removeEventListener("keydown", key, true);
    window.removeEventListener("pagehide", leave);
    chrome.runtime.onMessage.removeListener(message);
    if (indicator) indicator.remove(); indicator = null;
    delete globalThis.__envbankProtectedLoaded;
  }
  function cancel() {
    void chrome.runtime.sendMessage({ type: "cancel-selection", reason: "protected-selection-cancelled" }).catch(() => {});
    delete globalThis.__envbankProtectedTarget; cleanup();
  }
  function key(event) { if (event.key === "Escape") cancel(); }
  function leave() { delete globalThis.__envbankProtectedTarget; cancel(); }
  function eligible(form, submit) {
    if (!(form instanceof HTMLFormElement) || form.method.toLowerCase() !== "post" || (form.target && form.target !== "_self")) return false;
    const action = new URL(form.action, location.href);
    if (action.origin !== location.origin || action.username || action.password || action.search || action.hash) return false;
    if (submit && (submit.form !== form || submit.disabled || submit.formTarget && submit.formTarget !== "_self" ||
        submit.hasAttribute("formaction") || submit.hasAttribute("formmethod"))) return false;
    return true;
  }
  async function click(event) {
    if (!token) return;
    if (!event.isTrusted) { cancel(); return; }
    event.preventDefault(); event.stopImmediatePropagation();
    if (!input) {
      const node = event.target;
      if (!(node instanceof HTMLInputElement) || node.type !== "password" || node.disabled || node.readOnly ||
          node.value !== "" || !node.getClientRects().length || !eligible(node.form)) { cancel(); return; }
      input = node; selectedForm = node.form; fieldHandle = opaque();
      indicator.textContent = "EnvBank: choose the submit button · Esc to cancel";
      return;
    }
    const button = event.target.closest && event.target.closest("button, input[type=submit]");
    if (!button || button.type !== "submit" || !input.isConnected || input.form !== selectedForm || input.type !== "password" || input.disabled || input.readOnly || input.value !== "" || !button.getClientRects().length || !eligible(selectedForm,button)) { cancel(); return; }
    const selected = token, submitHandle = opaque();
    // This registry lives in the extension's ISOLATED world. It never contains
    // a value and is not an authorization proof. A trusted Driver resolves the
    // handles and revalidates the document/form after closing the host gate.
    globalThis.__envbankProtectedTarget = { token:selected, fieldHandle, submitHandle, input, button, form:input.form };
    cleanup();
    try {
      await chrome.runtime.sendMessage({ type: "protected-target-selected", token:selected, field:fieldHandle, submit:submitHandle });
    } catch (_) { /* Only the host may decide recovery and observation resume. */ }
    finally { delete globalThis.__envbankProtectedTarget; }
  }
  function message(value) {
    if (value.type === "envbank-arm") {
      token=value.token;
      indicator=document.createElement("div");
      indicator.textContent="EnvBank: choose the empty password field · Esc to cancel";
      Object.assign(indicator.style,{position:"fixed",zIndex:"2147483647",top:"12px",left:"12px",padding:"10px",background:"#172032",color:"white",font:"13px system-ui",pointerEvents:"none"});
      document.documentElement.appendChild(indicator);
      document.addEventListener("click",click,true); document.addEventListener("keydown",key,true);
      window.addEventListener("pagehide",leave,{once:true});
      timer=setTimeout(cancel,Math.max(0,value.expires-Date.now()));
    } else if (value.type === "envbank-cancel" && (!value.token || value.token===token)) cancel();
  }
  chrome.runtime.onMessage.addListener(message);
})();
