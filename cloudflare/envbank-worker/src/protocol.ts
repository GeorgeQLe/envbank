export function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export async function signatureMessage(
  method: string,
  pathAndQuery: string,
  timestamp: string,
  nonce: string,
  body: Uint8Array,
): Promise<Uint8Array> {
  const source = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", source));
  return new TextEncoder().encode([
    "envbank.request.v1",
    method,
    pathAndQuery,
    timestamp,
    nonce,
    encodeBase64url(digest),
  ].join("\n"));
}
