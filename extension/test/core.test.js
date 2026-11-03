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
  for (const file of ["background.js", "content.js", "protected-content.js", "popup.js", "core.js"]) {
    const source = fs.readFileSync(path.join(__dirname, "..", file), "utf8");
    assert.doesNotMatch(source, /chrome\.storage|clipboard|console\./);
  }
});

function backgroundHarness(tabURL, onNativeRequest) {
  let listener;
  let currentTabURL = tabURL;
  let entropy = 0;
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
    crypto: { getRandomValues(value) { value.fill(++entropy); } },
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

test("native bridge bounds a silent host request", async () => {
  let timeout;
  const originalSetTimeout = global.setTimeout;
  const originalClearTimeout = global.clearTimeout;
  global.setTimeout = (fn) => { timeout = fn; return 7; };
  global.clearTimeout = () => {};
  try {
    const port = { postMessage() {}, disconnect() {}, onMessage: { addListener() {} }, onDisconnect: { addListener() {} } };
    const bridge = new NativeBridge({ connectNative() { return port; } }, null, 25);
    const request = bridge.request("list_for_origin", { origin: "https://example.com" });
    timeout();
    await assert.rejects(request, /timed out/);
  } finally {
    global.setTimeout = originalSetTimeout;
    global.clearTimeout = originalClearTimeout;
  }
});

test("native bridge allows a bounded five-minute user-presence window by default", async () => {
  let delay;
  const originalSetTimeout = global.setTimeout;
  const originalClearTimeout = global.clearTimeout;
  global.setTimeout = (_fn, milliseconds) => { delay = milliseconds; return 7; };
  global.clearTimeout = () => {};
  try {
    const port = { postMessage() {}, disconnect() {}, onMessage: { addListener() {} }, onDisconnect: { addListener() {} } };
    const bridge = new NativeBridge({ connectNative() { return port; } });
    void bridge.request("list_for_origin", { origin: "https://example.com" });
    assert.equal(delay, 300000);
  } finally {
    global.setTimeout = originalSetTimeout;
    global.clearTimeout = originalClearTimeout;
  }
});

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

test("protected fill refuses a missing controller before arming or value release", async () => {
  const harness = backgroundHarness("https://example.com/form", () => ({ available: false }));
  const result = await harness.message({ type: "protected-arm", tabId: 5, name: "PASSWORD", origin: "https://example.com" });
  assert.match(result.__error, /observation-controlling host/);
  assert.deepEqual(harness.nativeRequests.map(r => r.action), ["protected_status"]);
  assert.equal(harness.sent.length, 0);
});

test("protected selection binds document and strips arbitrary native response fields", async () => {
  const marker = "DISPOSABLE_NATIVE_REPLY_MARKER";
  const harness = backgroundHarness("https://example.com/form", action => action === "protected_status"
    ? { available: true } : { status: "SUBMISSION_ATTEMPTED_CONTEXT_CLOSED", value: marker, diagnostics: marker });
  await harness.message({ type: "protected-arm", tabId: 5, name: "PASSWORD", origin: "https://example.com" });
  const token = harness.sent.at(-1).message.token;
  const result = await harness.message({ type: "protected-target-selected", token, field: "field_1", submit: "submit_1" },
    { tab: { id: 5 }, frameId: 0, documentId: "doc_1", url: "https://example.com/form" });
  assert.deepEqual(JSON.parse(JSON.stringify(result)), { status: "SUBMISSION_ATTEMPTED_CONTEXT_CLOSED" });
  assert.equal(JSON.stringify(result).includes(marker), false);
  const execution = harness.nativeRequests.find(r => r.action === "protected_execute");
  assert.deepEqual(JSON.parse(JSON.stringify(execution.target)), { record: "PASSWORD", context: "tab_5", document: "doc_1", field: "field_1", submit: "submit_1", origin: "https://example.com" });
  assert.equal(harness.nativeRequests.some(r => r.action === "get_for_fill"), false);
  const replay = await harness.message({ type: "protected-target-selected", token, field: "field_1", submit: "submit_1" },
    { tab: { id: 5 }, frameId: 0, documentId: "doc_1", url: "https://example.com/form" });
  assert.match(replay.__error, /expired/);
});

test("protected sessions cannot downgrade to legacy value responses", async () => {
  const harness = backgroundHarness("https://example.com/form", () => ({ available: true }));
  await harness.message({ type: "protected-arm", tabId: 5, name: "PASSWORD", origin: "https://example.com" });
  const result = await harness.message({ type: "field-selected", token: harness.sent.at(-1).message.token }, { tab: { id: 5 }, frameId: 0 });
  assert.match(result.__error, /expired/);
  assert.equal(harness.nativeRequests.some(r => r.action === "get_for_fill"), false);
});

test("protected selection rejects frames and missing or changed document origins", async () => {
  for (const sender of [
    { tab: { id: 5 }, frameId: 1, documentId: "doc_1", url: "https://example.com/form" },
    { tab: { id: 5 }, frameId: 0, url: "https://example.com/form" },
    { tab: { id: 5 }, frameId: 0, documentId: "doc_1", url: "https://other.example/form" },
  ]) {
    const harness = backgroundHarness("https://example.com/form", () => ({ available: true }));
    await harness.message({ type: "protected-arm", tabId: 5, name: "PASSWORD", origin: "https://example.com" });
    const result = await harness.message({ type: "protected-target-selected", token: harness.sent.at(-1).message.token, field: "field_1", submit: "submit_1" }, sender);
    assert.ok(result.__error);
    assert.equal(harness.nativeRequests.some(r => r.action === "protected_execute"), false);
  }
});


test("old selection expiry cannot cancel a newly armed operation", async () => {
  const harness = backgroundHarness("https://example.com/form");
  await harness.message({ type: "arm", tabId: 5, name: "FIRST", origin: "https://example.com" });
  await harness.message({ type: "arm", tabId: 5, name: "SECOND", origin: "https://example.com" });
  const count=harness.sent.length;
  harness.timers[0]();
  assert.equal(harness.sent.length,count);
  harness.timers[1]();
  assert.equal(harness.sent.at(-1).message.reason,"timeout");
});
