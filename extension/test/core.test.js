"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { originFromURL, NativeBridge } = require("../core.js");

test("origin eligibility rejects ordinary HTTP and browser pages", () => {
  assert.equal(originFromURL("https://EXAMPLE.com/path"), "https://example.com");
  assert.equal(originFromURL("http://localhost:3000/a"), "http://localhost:3000");
  assert.equal(originFromURL("http://example.com"), null);
  assert.equal(originFromURL("chrome://settings"), null);
});

test("native bridge correlates replies and rejects pending calls on disconnect", async () => {
  let messageListener, disconnectListener;
  const port = { posted: [], postMessage(value) { this.posted.push(value); }, onMessage: { addListener(fn) { messageListener = fn; } }, onDisconnect: { addListener(fn) { disconnectListener = fn; } } };
  const bridge = new NativeBridge({ connectNative(name) { assert.equal(name, "com.envbank.native"); return port; } });
  const first = bridge.request("list_for_origin", { origin: "https://example.com" });
  messageListener({ id: port.posted[0].id, ok: true, result: ["ok"] });
  assert.deepEqual(await first, ["ok"]);
  const second = bridge.request("get_for_fill", { name: "TOKEN", origin: "https://example.com" });
  disconnectListener();
  await assert.rejects(second, /disconnected/);
});

test("extension never invokes persistence or clipboard APIs", () => {
  for (const file of ["background.js", "content.js", "popup.js", "core.js"]) {
    const source = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
    assert.doesNotMatch(source, /chrome\.storage|clipboard|console\./);
  }
});

function backgroundHarness(tabURL, onNativeRequest) {
  let listener;
  let currentTabURL = tabURL;
  const nativeRequests = [], sent = [], timers = [];
  class FakeBridge {
    request(action, fields) {
      nativeRequests.push({ action, ...fields });
      return onNativeRequest ? Promise.resolve(onNativeRequest(action, fields, (url) => { currentTabURL = url; })) : Promise.resolve({});
    }
  }
  const context = {
    EnvBankCore: { NativeBridge: FakeBridge, originFromURL },
    importScripts() {},
    crypto: { getRandomValues(value) { value.fill(7); } },
    setTimeout(fn) { timers.push(fn); },
    chrome: {
      runtime: { onMessage: { addListener(fn) { listener = fn; } } },
      tabs: {
        get: async () => ({ url: currentTabURL }),
        sendMessage: async (tabId, message) => { sent.push({ tabId, message }); },
        onUpdated: { addListener() {} }, onRemoved: { addListener() {} }
      },
      scripting: { executeScript: async () => {} }
    }
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "..", "background.js"), "utf8"), context);
  const message = (value, sender = {}) => new Promise((resolve) => listener(value, sender, resolve));
  return { message, nativeRequests, sent, timers };
}

test("approval rejects an origin change before contacting the native host", async () => {
  const harness = backgroundHarness("https://other.example/path");
  const response = await harness.message({ type: "allow", tabId: 5, name: "TOKEN", origin: "https://example.com" });
  assert.match(response.__error, /origin changed/);
  assert.equal(harness.nativeRequests.length, 0);
});

test("selection timeout cancels the injected top-frame script", async () => {
  const harness = backgroundHarness("https://example.com/form");
  await harness.message({ type: "arm", tabId: 5, name: "TOKEN", origin: "https://example.com" });
  assert.equal(harness.timers.length, 1);
  harness.timers[0]();
  assert.equal(harness.sent.at(-1).message.reason, "timeout");
});

test("blocked-variable approval has a dedicated exact-origin confirmation", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "popup.html"), "utf8");
  const source = fs.readFileSync(path.join(__dirname, "..", "popup.js"), "utf8");
  assert.match(html, /<dialog id="confirm">/);
  assert.match(source, /Allow \$\{name\} to be filled only on \$\{origin\}/);
  assert.match(source, /dialog\.returnValue = ""/);
  assert.match(source, /returnValue !== "default"/);
});

test("generation revalidates origin and forwards replacement revision and policy", async () => {
  const harness = backgroundHarness("https://example.com/form");
  const policy = { length: 24, lowercase: true, uppercase: true, digits: true, symbols: true };
  const response = await harness.message({ type: "generate", tabId: 5, name: "PASSWORD", origin: "https://example.com", policy, expectedRevision: 9 });
  assert.equal(response.armed, true);
  assert.deepEqual(harness.nativeRequests[0], { action: "generate_password", name: "PASSWORD", origin: "https://example.com", policy, expected_revision: 9 });
  assert.equal(harness.sent.at(-1).message.type, "envbank-arm");
});

test("generation refuses an origin change before storing", async () => {
  const harness = backgroundHarness("https://other.example/form");
  const response = await harness.message({ type: "generate", tabId: 5, name: "PASSWORD", origin: "https://example.com", policy: { length: 24 }, expectedRevision: 0 });
  assert.match(response.__error, /generation cancelled/);
  assert.equal(harness.nativeRequests.length, 0);
});

test("navigation after storage reports that password remains stored", async () => {
  const harness = backgroundHarness("https://example.com/form", (action, fields, navigate) => {
    if (action === "generate_password") navigate("https://other.example/form");
    return { name: fields.name, revision: 1 };
  });
  const response = await harness.message({ type: "generate", tabId: 5, name: "PASSWORD", origin: "https://example.com", policy: { length: 24, lowercase: true }, expectedRevision: 0 });
  assert.match(response.__error, /remains stored and authorized/);
  assert.equal(harness.nativeRequests[0].action, "generate_password");
  assert.equal(harness.sent.length, 0);
});

test("generator confirmation describes native storage, exact origin, and replacement revision", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "popup.html"), "utf8");
  const source = fs.readFileSync(path.join(__dirname, "..", "popup.js"), "utf8");
  assert.match(html, /<dialog id="confirm-generate">/);
  assert.match(source, /generate the password inside its native host/);
  assert.match(source, /preserve the record's existing exact-origin authorizations/);
  assert.match(source, /This replaces revision \$\{existing\.revision\}/);
  assert.match(source, /dialog\.returnValue = ""/);
  assert.match(source, /expectedRevision: existing \? existing\.revision : 0/);
});
