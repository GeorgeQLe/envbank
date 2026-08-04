"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function contentHarness({ topFrame = true, fillValue = "filled-secret" } = {}) {
  const documentListeners = new Map(), runtimeListeners = [], messages = [];
  class FakeEvent { constructor(type, options) { this.type = type; Object.assign(this, options); } }
  class FakeElement {
    constructor() { this.disabled = false; this.readOnly = false; this.events = []; this.dataset = {}; }
    dispatchEvent(event) { this.events.push(event); return true; }
  }
  class FakeInput extends FakeElement { constructor(type = "text") { super(); this.type = type; this._value = ""; } }
  class FakeTextarea extends FakeElement { constructor() { super(); this._value = ""; } }
  Object.defineProperty(FakeInput.prototype, "value", { get() { return this._value; }, set(value) { this._value = value; } });
  Object.defineProperty(FakeTextarea.prototype, "value", { get() { return this._value; }, set(value) { this._value = value; } });
  const frame = {}, top = topFrame ? frame : {};
  const context = {
    window: Object.assign(frame, { top }),
    HTMLInputElement: FakeInput,
    HTMLTextAreaElement: FakeTextarea,
    Event: FakeEvent,
    setTimeout() { return 1; }, clearTimeout() {},
    document: {
      addEventListener(type, listener) { documentListeners.set(type, listener); },
      removeEventListener(type) { documentListeners.delete(type); },
      createElement() { return { style: {}, remove() {} }; },
      documentElement: { appendChild() {} }
    },
    chrome: { runtime: {
      onMessage: { addListener(listener) { runtimeListeners.push(listener); }, removeListener(listener) { const index = runtimeListeners.indexOf(listener); if (index >= 0) runtimeListeners.splice(index, 1); } },
      async sendMessage(message) { messages.push(message); return message.type === "field-selected" ? { value: fillValue } : {}; }
    }}
  };
  context.globalThis = context;
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "..", "content.js"), "utf8"), context);
  return { context, documentListeners, runtimeListeners, messages, FakeInput, FakeTextarea };
}

function arm(harness) {
  assert.equal(harness.runtimeListeners.length, 1);
  harness.runtimeListeners[0]({ type: "envbank-arm", token: "one-time-token", expires: Date.now() + 30000 });
}

test("actual content script fills text and textarea targets with framework events", async () => {
  for (const kind of ["input", "textarea"]) {
    const harness = contentHarness(); arm(harness);
    const element = kind === "input" ? new harness.FakeInput("text") : new harness.FakeTextarea();
    await harness.documentListeners.get("click")({ target: element, preventDefault() {}, stopImmediatePropagation() {} });
    assert.equal(element.value, "filled-secret");
    assert.deepEqual(element.events.map((event) => event.type), ["input", "change"]);
    assert.equal(harness.messages.filter((message) => message.type === "field-selected").length, 1);
  }
});

test("unsupported fields cancel without requesting a value", async () => {
  const harness = contentHarness(); arm(harness);
  const file = new harness.FakeInput("file");
  await harness.documentListeners.get("click")({ target: file, preventDefault() {}, stopImmediatePropagation() {} });
  assert.deepEqual(harness.messages.map((message) => message.type), ["cancel-selection"]);
  assert.equal(file.value, "");
});

test("content script refuses iframe execution", () => {
  const harness = contentHarness({ topFrame: false });
  assert.equal(harness.runtimeListeners.length, 0);
  assert.equal(harness.documentListeners.size, 0);
});
