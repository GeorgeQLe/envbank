import assert from "node:assert/strict";
import test from "node:test";
import { signatureMessage } from "./protocol.ts";

test("signature message matches the Go v1 golden vector", async () => {
  const message = await signatureMessage(
    "GET",
    "/v1/vaults/vault/records?limit=1",
    "2026-08-16T20:00:00Z",
    "AAAAAAAAAAAAAAAAAAAAAAAA",
    new Uint8Array(),
  );
  assert.equal(new TextDecoder().decode(message), [
    "envbank.request.v1",
    "GET",
    "/v1/vaults/vault/records?limit=1",
    "2026-08-16T20:00:00Z",
    "AAAAAAAAAAAAAAAAAAAAAAAA",
    "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
  ].join("\n"));
});
