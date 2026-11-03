// DOM integration tests, NOT proof of native observation-host integration.
// Injects the production selection script into disposable pages with a metadata-
// only runtime fixture. No native host, vault, login or real secrets are used.
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const html = `<!doctype html><title>Disposable protected selection</title>
<form id="login" method="post" action="/submit"><input id="password" type="password" autocomplete="current-password">
<input id="text"><textarea id="textarea"></textarea><input id="readonly" type="password" readonly>
<button id="submit" type="submit"><span>Save</span></button></form>
<form method="post" action="/submit"><button id="other" type="submit">Other</button></form>
<iframe srcdoc="<input type=password>"></iframe>`;
let submissions = 0;
const server = http.createServer((request,response) => {
  if (request.method === "POST") submissions++;
  response.writeHead(200,{"Content-Type":"text/html","Cache-Control":"no-store"}); response.end(html);
});
await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
const origin=`http://127.0.0.1:${server.address().port}`;
let browser, passed=0;
try {
  browser=await chromium.launch({headless:true});
  async function fixture(run) {
    const context=await browser.newContext();
    try {
      const page=await context.newPage(); await page.goto(origin);
      await page.evaluate(()=>{
        globalThis.fixtureBridge={listeners:[],requests:[]};
        globalThis.chrome={runtime:{
          onMessage:{addListener(fn){fixtureBridge.listeners.push(fn)},removeListener(fn){fixtureBridge.listeners=fixtureBridge.listeners.filter(f=>f!==fn)}},
          async sendMessage(value){fixtureBridge.requests.push(value);return {status:"HOST_PROTECTION_UNAVAILABLE"}}
        }};
      });
      await page.addScriptTag({path:path.join(repo,"extension/protected-content.js")});
      await page.evaluate(()=>fixtureBridge.listeners[0]({type:"envbank-arm",token:"disposable-operation",expires:Date.now()+30000}));
      await run(page);
      assert.equal(await page.locator("#password").inputValue(), "");
      assert.equal(submissions,0,"selection submitted without the trusted controller");
      passed++;
    } finally { await context.close(); }
  }

  await fixture(async page=>{
    await page.click("#password"); await page.click("#submit span");
    const requests=await page.evaluate(()=>fixtureBridge.requests);
    const selected=requests.find(r=>r.type==="protected-target-selected");
    assert.ok(selected); assert.match(selected.field,/^[a-f0-9]{32}$/); assert.match(selected.submit,/^[a-f0-9]{32}$/);
    assert.equal(Object.hasOwn(selected,"value"),false);
    assert.equal(await page.evaluate(()=>Boolean(globalThis.__envbankProtectedTarget)),false);
  });

  for(const selector of ["#text","#textarea","#readonly"]) await fixture(async page=>{
    await page.click(selector);
    assert.equal(await page.evaluate(()=>fixtureBridge.requests.some(r=>r.type==="protected-target-selected")),false);
    assert.equal(await page.evaluate(()=>fixtureBridge.requests.at(-1)?.type),"cancel-selection");
  });

  for (const opacity of ["input", "ancestor"]) await fixture(async page=>{
    await page.evaluate(which=>{document.querySelector(which === "input" ? "#password" : "#login").style.opacity="0"},opacity);
    await page.click("#password");
    assert.equal(await page.evaluate(()=>fixtureBridge.requests.some(r=>r.type==="protected-target-selected")),false);
    assert.equal(await page.evaluate(()=>fixtureBridge.requests.at(-1)?.type),"cancel-selection");
  });

  for(const mutation of ["get","cross-origin","other-form","rerender","override","filled","script-click"]) await fixture(async page=>{
    if(mutation==="get") await page.evaluate(()=>document.querySelector("#login").method="get");
    if(mutation==="script-click") await page.evaluate(()=>document.querySelector("#password").click());
    else await page.click("#password");
    if(mutation==="cross-origin") await page.evaluate(()=>document.querySelector("#login").action="https://invalid.example/submit");
    if(mutation==="rerender") await page.evaluate(()=>{const old=document.querySelector("#password");old.replaceWith(old.cloneNode())});
    if(mutation==="override") await page.evaluate(()=>document.querySelector("#submit").setAttribute("formaction","/other"));
    if(mutation==="filled") await page.evaluate(()=>document.querySelector("#password").value="disposable-existing-input");
    if(mutation!=="get"&&mutation!=="script-click") await page.click(mutation==="other-form"?"#other":"#submit");
    assert.equal(await page.evaluate(()=>fixtureBridge.requests.some(r=>r.type==="protected-target-selected")),false,mutation);
    await page.evaluate(()=>document.querySelector("#password").value="");
  });

  await fixture(async page=>{
    await page.click("#password"); await page.keyboard.press("Escape");
    assert.equal(await page.evaluate(()=>Boolean(globalThis.__envbankProtectedLoaded)),false);
    assert.equal(await page.evaluate(()=>fixtureBridge.requests.at(-1).type),"cancel-selection");
  });
  // Exercise the actual popup controls with public metadata fixtures. This is
  // not an installed-extension or native-controller acceptance test.
  const popupHTML=fs.readFileSync(path.join(repo,"extension/popup.html"),"utf8");
  for(const mode of ["missing-host","protected-ready","older-human-host"]) {
    const context=await browser.newContext();
    try {
      const page=await context.newPage(); await page.goto(origin);
      await page.evaluate(source=>{
        const fixture = new DOMParser().parseFromString(source, "text/html");
        fixture.querySelectorAll("script, link").forEach(node=>node.remove());
        document.replaceChild(document.importNode(fixture.documentElement, true), document.documentElement);
      }, popupHTML);
      await page.evaluate(mode=>{
        globalThis.fixtureRequests=[];
        globalThis.chrome={tabs:{async query(){return [{id:5,url:location.href}]}},runtime:{async sendMessage(value){
          fixtureRequests.push(value);
          if(value.type==="protected-status") {
            if(mode==="older-human-host")return {__error:"unknown native action"};
            return {available:mode==="protected-ready",computer_use:true};
          }
          if(value.type==="list")return [{name:"DISPOSABLE_PASSWORD",allowed:true,revision:1}];
          return {armed:true};
        }}};
      },mode);
      await page.addScriptTag({path:path.join(repo,"extension/core.js")});
      await page.addScriptTag({path:path.join(repo,"extension/popup.js")});
      if(mode==="missing-host") {
        await page.waitForFunction(()=>document.querySelector("#status").textContent.includes("observation-controlling host"));
        assert.equal(await page.evaluate(()=>fixtureRequests.some(r=>r.type==="list")),false,"unavailable protection unnecessarily opened the vault");
        assert.equal(await page.locator("#records button").count(),0);
      } else if(mode==="protected-ready") {
        await page.getByRole("button",{name:"Protected fill",exact:true}).waitFor();
        assert.equal(await page.getByRole("button",{name:"Choose",exact:true}).count(),0);
        assert.equal(await page.locator("#generator").isVisible(),false);
        await page.getByRole("button",{name:"Protected fill",exact:true}).click();
        assert.equal(await page.evaluate(()=>fixtureRequests.at(-1).type),"protected-arm");
        assert.equal(await page.evaluate(()=>fixtureRequests.some(r=>r.type==="arm")),false);
      } else {
        await page.getByRole("button",{name:"Choose",exact:true}).waitFor();
        assert.equal(await page.getByRole("button",{name:"Protected fill",exact:true}).isDisabled(),true);
      }
      passed++;
    } finally {await context.close();}
  }
  process.stdout.write(`protected-selection: PASS ${passed} disposable DOM cases; no value release, host enforcement unqualified\n`);
} finally {
  if(browser) await browser.close();
  await new Promise(resolve=>server.close(resolve));
}
