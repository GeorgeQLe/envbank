(function (root) {
  "use strict";

  function originFromURL(raw) {
    try {
      const url = new URL(raw);
      if (url.protocol === "https:") return url.origin;
      if (url.protocol !== "http:") return null;
      const host = url.hostname.toLowerCase();
      if (host === "localhost" || host.endsWith(".localhost") || host.startsWith("127.") || host === "[::1]") return url.origin;
      return null;
    } catch (_) { return null; }
  }

  class NativeBridge {
    constructor(runtime, onDisconnect, timeoutMs) {
      this.runtime = runtime;
      this.onDisconnect = onDisconnect;
      // User-presence prompts can legitimately take longer than an ordinary
      // native request. Keep the bridge bounded while allowing enough time for
      // a human to approve Touch ID or the macOS Keychain sheet.
      this.timeoutMs = timeoutMs || 300000;
      this.port = null;
      this.pending = new Map();
      this.sequence = 0;
    }
    connect() {
      if (this.port) return;
      const port = this.runtime.connectNative("com.envbank.native");
      this.port = port;
      port.onMessage.addListener((message) => {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        clearTimeout(pending.timer);
        message.ok ? pending.resolve(message.result) : pending.reject(new Error(message.error || "Native request failed"));
      });
      port.onDisconnect.addListener(() => {
        const error = new Error("EnvBank native host disconnected");
        for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
        this.pending.clear(); this.port = null;
        if (this.onDisconnect) this.onDisconnect();
      });
    }
    request(action, fields) {
      this.connect();
      const id = `${Date.now().toString(36)}-${++this.sequence}`;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          if (!this.pending.delete(id)) return;
          reject(new Error("EnvBank native host timed out"));
          if (this.port) { this.port.disconnect(); this.port = null; }
        }, this.timeoutMs);
        this.pending.set(id, { resolve, reject, timer });
        this.port.postMessage(Object.assign({ version: 1, id, action }, fields || {}));
      });
    }
  }

  root.EnvBankCore = { originFromURL, NativeBridge };
  if (typeof module !== "undefined") module.exports = root.EnvBankCore;
})(globalThis);
