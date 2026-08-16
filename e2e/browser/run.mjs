import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { chromium } from "playwright";

const [repo, userDataDir, nativeHost, artifactDir] = process.argv.slice(2);
assert.ok(repo && userDataDir && nativeHost && artifactDir, "browser harness paths are required");
const extensionSource = path.join(repo, "extension");
const extensionPath = path.join(path.dirname(userDataDir), "extension");
fs.cpSync(extensionSource, extensionPath, { recursive: true });
const extensionManifestPath = path.join(extensionPath, "manifest.json");
const extensionManifest = JSON.parse(fs.readFileSync(extensionManifestPath, "utf8"));
const backgroundPath = path.join(extensionPath, "background.js");
const backgroundSource = fs.readFileSync(backgroundPath, "utf8");
const testBackgroundSource = backgroundSource.replace(
  "new EnvBankCore.NativeBridge(chrome.runtime, cancelAll)",
  "new EnvBankCore.NativeBridge(chrome.runtime, cancelAll, 10000)",
);
assert.notEqual(testBackgroundSource, backgroundSource, "test bridge timeout injection point not found");
fs.writeFileSync(backgroundPath, testBackgroundSource, { mode: 0o600 });
// activeTab is normally granted by the user's toolbar click. Automation loads
// an isolated copy with loopback-only host access so it can exercise the same
// production scripts without synthesizing a trusted browser UI gesture. The
// copied background also uses a ten-second timeout so the failure case remains
// fast while production retains its five-minute user-presence window.
extensionManifest.host_permissions = ["http://127.0.0.1/*", "http://localhost/*"];
fs.writeFileSync(extensionManifestPath, JSON.stringify(extensionManifest, null, 2), { mode: 0o600 });
const marker = "ENVBANK_E2E_SECRET_DO_NOT_LEAK";
const html = `<!doctype html><title>EnvBank E2E</title>
<input id=text type=text><input id=password type=password><textarea id=textarea></textarea>
<input id=hidden type=hidden><input id=file type=file><iframe srcdoc="<input id=framed>"></iframe>`;
const server = http.createServer((request, response) => {
  response.writeHead(200, { "content-type": "text/html", "cache-control": "no-store" }); response.end(html);
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
const origin = `http://127.0.0.1:${port}`;
const consoleLines = [];

const manifest = JSON.stringify({
  name: "com.envbank.native", description: "EnvBank disposable E2E host", path: nativeHost,
  type: "stdio", allowed_origins: ["chrome-extension://pgbpmecaapiknpejgdkpaifpjcnckcnk/"]
});
const homes = [path.join(userDataDir, "NativeMessagingHosts"), ...(os.platform() === "darwin"
  ? [path.join(process.env.HOME, "Library/Application Support/Google/Chrome/NativeMessagingHosts"), path.join(process.env.HOME, "Library/Application Support/Google/ChromeForTesting/NativeMessagingHosts")]
  : [path.join(process.env.HOME, ".config/chromium/NativeMessagingHosts"), path.join(process.env.HOME, ".config/google-chrome/NativeMessagingHosts"), path.join(process.env.HOME, ".config/google-chrome-for-testing/NativeMessagingHosts")])];
for (const directory of homes) { fs.mkdirSync(directory, { recursive: true, mode: 0o700 }); fs.writeFileSync(path.join(directory, "com.envbank.native.json"), manifest, { mode: 0o600 }); }

let context;
try {
  context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    env: { ...process.env, HOME: process.env.HOME },
    args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
  });
  const fixture = context.pages()[0] ?? await context.newPage();
  const watchConsole = (target) => target.on("console", (message) => consoleLines.push(message.text()));
  for (const page of context.pages()) watchConsole(page);
  context.on("page", watchConsole);
  await fixture.goto(origin);
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker");
  watchConsole(worker);
  const tabs = await worker.evaluate(() => new Promise((resolve) => chrome.tabs.query({}, resolve)));
  const fixtureTab = tabs.find((tab) => tab.url?.startsWith("http://127.0.0.1:"));
  assert.ok(fixtureTab, "fixture tab not found");
  const extensionPage = await context.newPage();
  await extensionPage.goto("chrome-extension://pgbpmecaapiknpejgdkpaifpjcnckcnk/popup.html");
  const send = (message) => extensionPage.evaluate((value) => chrome.runtime.sendMessage(value), message);
  const listed = await send({ type: "list", origin });
  assert.equal(listed.length, 3);
  assert.equal(listed.some((record) => Object.hasOwn(record, "value")), false);

  for (const selector of ["#text", "#password", "#textarea"]) {
    const armed = await send({ type: "arm", tabId: fixtureTab.id, name: "E2E_VALUE", origin });
    assert.equal(armed.armed, true);
    await fixture.bringToFront();
    await fixture.click(selector);
    await fixture.waitForFunction((target) => document.querySelector(target).value.length > 0, selector);
    assert.equal(await fixture.$eval(selector, (node) => node.value.length > 0), true);
  }

  for (const selector of ["#hidden", "#file"]) {
    await send({ type: "arm", tabId: fixtureTab.id, name: "E2E_VALUE", origin });
    await fixture.bringToFront();
    await fixture.dispatchEvent(selector, "click");
    assert.equal(await fixture.$eval(selector, (node) => node.value === ""), true);
  }
  await send({ type: "arm", tabId: fixtureTab.id, name: "E2E_VALUE", origin });
  await fixture.frames()[1].click("#framed");
  assert.equal(await fixture.frames()[1].evaluate(() => document.querySelector("#framed").value === ""), true);

  await fixture.goto(`http://localhost:${port}`);
  const rejected = await send({ type: "arm", tabId: fixtureTab.id, name: "E2E_VALUE", origin });
  assert.match(rejected.__error, /origin changed/);
  await fixture.goto(origin);

  for (const name of ["DISCONNECT", "TIMEOUT"]) {
    await fixture.$eval("#text", (node) => { node.value = ""; });
    await send({ type: "arm", tabId: fixtureTab.id, name, origin });
    await fixture.bringToFront();
    await fixture.click("#text");
    await fixture.waitForTimeout(name === "TIMEOUT" ? 10500 : 500);
    assert.equal(await fixture.$eval("#text", (node) => node.value === ""), true);
  }

  const generated = await send({ type: "generate", tabId: fixtureTab.id, name: "E2E_VALUE", origin,
    policy: { length: 24, lowercase: true, uppercase: true, digits: true, symbols: true }, expectedRevision: 1 });
  assert.equal(generated.record.revision, 2);
  assert.equal(Object.hasOwn(generated.record, "value"), false);

  const observableClean = await fixture.evaluate(async (needle) => {
    const storage = JSON.stringify({ ...localStorage, ...sessionStorage });
    let clipboard = "";
    try { clipboard = await Promise.race([navigator.clipboard.readText(), new Promise((resolve) => setTimeout(() => resolve(""), 500))]); } catch {}
    return !storage.includes(needle) && !clipboard.includes(needle);
  }, marker);
  assert.equal(observableClean, true);
  assert.equal(consoleLines.some((line) => line.includes(marker)), false);
  await fixture.evaluate(() => { for (const node of document.querySelectorAll("input, textarea")) { if (node.type !== "file") node.value = ""; } });
  await fixture.screenshot({ path: path.join(artifactDir, "browser.png") });
  assert.equal(fs.readFileSync(path.join(artifactDir, "browser.png")).includes(Buffer.from(marker)), false);
  process.stdout.write("e2e-browser: RESULT=PASS\n");
} finally {
  if (context) await context.close();
  await new Promise((resolve) => server.close(resolve));
}
