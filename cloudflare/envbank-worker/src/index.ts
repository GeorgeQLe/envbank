import { DurableObject } from "cloudflare:workers";
import { encodeBase64url, signatureMessage } from "./protocol";

export interface Env {
  VAULTS: DurableObjectNamespace<VaultDurableObject>;
}

type Json = Record<string, any>;
type Blob = { version: number; nonce: string; ciphertext: string };
type PublicDevice = {
  id: string;
  name: string;
  signing_public: string;
  wrapping_public: string;
  fingerprint: string;
  created_at: string;
};

const MAX_BODY = 1 << 20;
const EVENT_MAX_AGE_MS = 90 * 24 * 60 * 60_000;
const MAX_VERIFIED_EVENTS = 10_000;
const MAX_UNVERIFIED_EVENTS = 2_000;
const AUTH_HEADERS = {
  device: "X-EnvBank-Device",
  timestamp: "X-EnvBank-Timestamp",
  nonce: "X-EnvBank-Nonce",
  signature: "X-EnvBank-Signature",
} as const;

const responseHeaders = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function json(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), { status, headers: responseHeaders });
}

function failure(status: number, error: string): Response {
  return json(status, { error });
}

function randomID(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  return base64url(bytes);
}

function base64url(bytes: Uint8Array): string {
  return encodeBase64url(bytes);
}

function decodeBase64url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
    const decoded = atob(padded);
    const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    return base64url(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function canonicalSecond(date = new Date()): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function fingerprint(signing: string, wrapping: string): Promise<string> {
  const input = new TextEncoder().encode(`envbank.device.fingerprint.v1\0${signing}\0${wrapping}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  return [...digest.slice(0, 8)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validPublicKeys(signing: unknown, wrapping: unknown): boolean {
  if (typeof signing !== "string" || typeof wrapping !== "string") return false;
  return decodeBase64url(signing)?.length === 32 && decodeBase64url(wrapping)?.length === 32;
}

function bytesBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function validBlob(value: unknown): value is Blob {
  if (!value || typeof value !== "object") return false;
  const blob = value as Partial<Blob>;
  return blob.version === 1 && typeof blob.nonce === "string" && typeof blob.ciphertext === "string" &&
    decodeBase64url(blob.nonce)?.length === 12 && (decodeBase64url(blob.ciphertext)?.length ?? 0) >= 16;
}

async function readJSON(request: Request): Promise<{ body: Uint8Array; value: Json } | Response> {
  const body = await readBody(request);
  if (body instanceof Response) return body;
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(body));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return { body, value: value as Json };
  } catch {
    return failure(400, "invalid JSON request");
  }
}

async function readBody(request: Request): Promise<Uint8Array | Response> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY)) {
    return failure(413, "request body too large");
  }
  const body = new Uint8Array(await request.arrayBuffer());
  return body.length > MAX_BODY ? failure(413, "request body too large") : body;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") return json(200, { status: "ok" });
    if (request.method === "POST" && url.pathname === "/v1/vaults") {
      const parsed = await readJSON(request);
      if (parsed instanceof Response) return parsed;
      const device = parsed.value.device as Json | undefined;
      if (typeof parsed.value.name !== "string" || parsed.value.name === "" || !device ||
          typeof device.name !== "string" || device.name === "" ||
          !validPublicKeys(device.signing_public, device.wrapping_public)) {
        return failure(400, "vault and device fields are required");
      }
      const vaultID = randomID();
      const stub = env.VAULTS.get(env.VAULTS.idFromName(vaultID));
      const forwarded = new Request(new URL("/_initialize", request.url), {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-EnvBank-Vault": vaultID },
        body: JSON.stringify(parsed.value),
      });
      return stub.fetch(forwarded);
    }
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 3 || parts[0] !== "v1" || parts[1] !== "vaults") return failure(404, "not found");
    const vaultID = parts[2];
    const stub = env.VAULTS.get(env.VAULTS.idFromName(vaultID));
    const headers = new Headers(request.headers);
    headers.set("X-EnvBank-Vault", vaultID);
    return stub.fetch(new Request(request, { headers }));
  },
} satisfies ExportedHandler<Env>;

type Auth = { identityID: string; timestamp: string; nonce: string };
type DeviceRow = PublicDevice & { revoked_at: string | null };
class ReplayError extends Error {}
class IdentityChangedError extends Error {}

export class VaultDurableObject extends DurableObject<Env> {
  private readonly sql: SqlStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    state.blockConcurrencyWhile(async () => this.migrate());
  }

  private migrate(): void {
    this.sql.exec(`CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, signing_public TEXT NOT NULL,
 wrapping_public TEXT NOT NULL, fingerprint TEXT NOT NULL, created_at TEXT NOT NULL,
 revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS enrollments (
 device_id TEXT PRIMARY KEY, name TEXT NOT NULL, signing_public TEXT NOT NULL,
 wrapping_public TEXT NOT NULL, fingerprint TEXT NOT NULL, created_at TEXT NOT NULL,
 approved INTEGER NOT NULL DEFAULT 0, envelope TEXT, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS records (
 id TEXT PRIMARY KEY, revision INTEGER NOT NULL, blob TEXT NOT NULL, modified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_objects (
 id TEXT PRIMARY KEY, revision INTEGER NOT NULL, blob TEXT NOT NULL, modified_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
 device_id TEXT NOT NULL, nonce TEXT NOT NULL, created_at TEXT NOT NULL,
 PRIMARY KEY(device_id, nonce)
);
CREATE INDEX IF NOT EXISTS nonces_created_at ON nonces(created_at);
CREATE TABLE IF NOT EXISTS access_events (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL,
 identity_id TEXT, identity_verified INTEGER NOT NULL, target_identity_id TEXT,
 operation TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT
);
CREATE INDEX IF NOT EXISTS access_events_sequence ON access_events(sequence DESC);
CREATE TABLE IF NOT EXISTS invitations (
 device_id TEXT PRIMARY KEY, protocol_version INTEGER NOT NULL, state TEXT NOT NULL,
 expires_at TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0,
 terminal_at TEXT, terminal_actor TEXT
);`);
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const vaultID = request.headers.get("X-EnvBank-Vault") ?? "";
      if (url.pathname === "/_initialize" && request.method === "POST") return this.initialize(request, vaultID);
      if (!this.exists()) return failure(404, "vault not found");
      const parts = url.pathname.split("/").filter(Boolean);
      const resource = parts[3] ?? "";
      const itemID = parts[4] ?? "";
      const action = parts[5] ?? "";
      const exactInvitation = parts.length === 4 && (request.method === "GET" || request.method === "POST") ||
        parts.length === 5 && request.method === "GET" ||
        parts.length === 6 && request.method === "POST" && ["approve", "reject", "cancel"].includes(action);
      if (resource === "invitations" && exactInvitation) return this.invitations(request, vaultID, itemID, action);
      const exactEnrollment = parts.length === 4 && (request.method === "GET" || request.method === "POST") ||
        parts.length === 5 && (request.method === "GET" || request.method === "POST");
      if (resource === "enrollments" && exactEnrollment) return this.enrollments(request, vaultID, itemID);
      if (resource === "devices" && (parts.length === 4 && request.method === "GET" ||
          parts.length === 5 && request.method === "DELETE")) return this.devices(request, vaultID, itemID);
      if (resource === "records" && (parts.length === 4 && request.method === "GET" ||
          parts.length === 5 && request.method === "PUT")) return this.records(request, vaultID, itemID);
      if (resource === "objects" && (parts.length === 4 && request.method === "GET" ||
          parts.length === 5 && ["GET", "PUT", "DELETE"].includes(request.method))) {
        return this.objects(request, vaultID, itemID);
      }
      if (resource === "access-events" && parts.length === 4 && request.method === "GET") {
        return this.events(request, vaultID);
      }
      return failure(404, "not found");
    } catch (error) {
      if (error instanceof ReplayError) return failure(401, "request nonce already used");
      if (error instanceof IdentityChangedError) return failure(401, "device is no longer active");
      return failure(500, "server state could not be persisted");
    }
  }

  private exists(): boolean {
    return first(this.sql.exec<{ value: string }>("SELECT value FROM metadata WHERE key = 'vault_id'"))?.value !== undefined;
  }

  private async initialize(request: Request, vaultID: string): Promise<Response> {
    const parsed = await readJSON(request);
    if (parsed instanceof Response) return parsed;
    if (this.exists()) return failure(409, "vault already exists");
    const source = parsed.value.device as Json;
    const deviceID = randomID();
    const now = canonicalSecond();
    const device: PublicDevice = {
      id: deviceID,
      name: source.name as string,
      signing_public: source.signing_public as string,
      wrapping_public: source.wrapping_public as string,
      fingerprint: await fingerprint(source.signing_public as string, source.wrapping_public as string),
      created_at: now,
    };
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO metadata(key,value) VALUES ('vault_id',?),('name',?),('created_at',?)",
        vaultID, parsed.value.name as string, now);
      this.sql.exec(`INSERT INTO devices(id,name,signing_public,wrapping_public,fingerprint,created_at)
        VALUES (?,?,?,?,?,?)`, device.id, device.name, device.signing_public, device.wrapping_public,
        device.fingerprint, device.created_at);
    });
    return json(201, { vault_id: vaultID, device_id: deviceID });
  }

  private device(id: string): DeviceRow | null {
    return first(this.sql.exec<DeviceRow>(`SELECT id,name,signing_public,wrapping_public,fingerprint,
      created_at,revoked_at FROM devices WHERE id = ?`, id)) ?? null;
  }

  private pendingDevice(id: string): DeviceRow | null {
    return first(this.sql.exec<DeviceRow>(`SELECT device_id AS id,name,signing_public,wrapping_public,
      fingerprint,created_at,revoked_at FROM enrollments WHERE device_id = ?`, id)) ?? null;
  }

  private async authenticate(request: Request, body: Uint8Array, allowPending = false): Promise<Auth | Response> {
    const identityID = request.headers.get(AUTH_HEADERS.device) ?? "";
    const timestamp = request.headers.get(AUTH_HEADERS.timestamp) ?? "";
    const nonce = request.headers.get(AUTH_HEADERS.nonce) ?? "";
    const signature = request.headers.get(AUTH_HEADERS.signature) ?? "";
    const device = this.device(identityID) ?? (allowPending ? this.pendingDevice(identityID) : null);
    if (!device) return failure(401, "unknown device");
    if (device.revoked_at) return failure(401, "device revoked");
    const nonceBytes = decodeBase64url(nonce);
    const parsedTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(timestamp) ? Date.parse(timestamp) : NaN;
    if (!nonceBytes || nonceBytes.length !== 18) return failure(401, "invalid request nonce");
    if (!Number.isFinite(parsedTime) || Math.abs(Date.now() - parsedTime) > 5 * 60_000) {
      return failure(401, "invalid request timestamp");
    }
    const requestURL = new URL(request.url);
    const message = await signatureMessage(request.method, requestURL.pathname + requestURL.search,
      timestamp, nonce, body);
    const publicBytes = decodeBase64url(device.signing_public);
    const signatureBytes = decodeBase64url(signature);
    if (!publicBytes || !signatureBytes) return failure(401, "invalid request signature");
    try {
      const key = await crypto.subtle.importKey("raw", bytesBuffer(publicBytes), { name: "Ed25519" }, false, ["verify"]);
      if (!await crypto.subtle.verify("Ed25519", key, bytesBuffer(signatureBytes), bytesBuffer(message))) {
        return failure(401, "invalid request signature");
      }
    } catch {
      return failure(401, "invalid request signature");
    }
    return { identityID, timestamp, nonce };
  }

  private reserve(auth: Auth): void {
    const current = this.device(auth.identityID) ?? this.pendingDevice(auth.identityID);
    if (!current || current.revoked_at) throw new IdentityChangedError();
    this.sql.exec("DELETE FROM nonces WHERE created_at < ?", canonicalSecond(new Date(Date.now() - 10 * 60_000)));
    if (first(this.sql.exec<{ found: number }>("SELECT 1 AS found FROM nonces WHERE device_id=? AND nonce=?",
        auth.identityID, auth.nonce))?.found === 1) throw new ReplayError();
    this.sql.exec("INSERT INTO nonces(device_id,nonce,created_at) VALUES (?,?,?)",
      auth.identityID, auth.nonce, canonicalSecond());
  }

  private audit(auth: Auth | null, operation: string, outcome = "succeeded", target = "", reason = ""): void {
    this.sql.exec(`INSERT INTO access_events(id,timestamp,identity_id,identity_verified,target_identity_id,
      operation,outcome,reason) VALUES (?,?,?,?,?,?,?,?)`, randomID(), new Date().toISOString(),
      auth?.identityID ?? null, auth ? 1 : 0, target || null, operation, outcome, reason || null);
    this.sql.exec("DELETE FROM access_events WHERE timestamp < ?",
      new Date(Date.now() - EVENT_MAX_AGE_MS).toISOString());
    for (const [verified, limit] of [[1, MAX_VERIFIED_EVENTS], [0, MAX_UNVERIFIED_EVENTS]] as const) {
      this.sql.exec(`DELETE FROM access_events WHERE identity_verified=? AND sequence NOT IN (
        SELECT sequence FROM access_events WHERE identity_verified=? ORDER BY sequence DESC LIMIT ?
      )`, verified, verified, limit);
    }
  }

  private async enrollments(request: Request, _vaultID: string, deviceID: string): Promise<Response> {
    if (request.method === "POST" && !deviceID) {
      const parsed = await readJSON(request);
      if (parsed instanceof Response) return parsed;
      const value = parsed.value;
      if (typeof value.name !== "string" || value.name === "" ||
          !validPublicKeys(value.signing_public, value.wrapping_public)) return failure(400, "device fields are required");
	  const signing = value.signing_public as string;
	  const wrapping = value.wrapping_public as string;
      const id = randomID();
      const created = canonicalSecond();
      const device: PublicDevice = { id, name: value.name, signing_public: signing,
        wrapping_public: wrapping, fingerprint: await fingerprint(signing, wrapping),
        created_at: created };
      this.ctx.storage.transactionSync(() => {
        this.sql.exec(`INSERT INTO enrollments(device_id,name,signing_public,wrapping_public,fingerprint,created_at)
          VALUES (?,?,?,?,?,?)`, id, device.name, device.signing_public, device.wrapping_public, device.fingerprint, created);
        this.audit(null, "enrollment_request", "succeeded", id);
      });
      return json(201, { device, approved: false });
    }
    const read = request.method === "GET" ? new Uint8Array() : await readBody(request);
    if (read instanceof Response) return read;
    const body = read;
    const auth = await this.authenticate(request, body, request.method === "GET" && !!deviceID);
    if (auth instanceof Response) return auth;
    if (request.method === "GET" && !deviceID) {
      const rows = [...this.sql.exec<Json>(`SELECT device_id AS id,name,signing_public,wrapping_public,fingerprint,
        created_at,approved,envelope,revoked_at FROM enrollments ORDER BY created_at,device_id`)];
      this.ctx.storage.transactionSync(() => { this.reserve(auth); this.audit(auth, "enrollment_list"); });
      return json(200, rows.map(enrollmentJSON));
    }
    if (request.method === "GET" && deviceID) {
      const row = first(this.sql.exec<Json>(`SELECT device_id AS id,name,signing_public,wrapping_public,fingerprint,
        created_at,approved,envelope,revoked_at FROM enrollments WHERE device_id=?`, deviceID));
      if (!row) return failure(404, "enrollment not found");
      if (!this.device(auth.identityID) && auth.identityID !== deviceID) return failure(401, "device cannot inspect enrollment");
      this.ctx.storage.transactionSync(() => { this.reserve(auth); this.audit(auth, "enrollment_status", "succeeded", deviceID); });
      return json(200, enrollmentJSON(row));
    }
    if (request.method === "POST" && deviceID) {
      let value: Json;
      try { value = JSON.parse(new TextDecoder().decode(body)) as Json; } catch { return failure(400, "invalid JSON request"); }
      const envelope = value.envelope as Json | undefined;
      if (!envelope || envelope.version !== 1 || decodeBase64url(envelope.ephemeral_key as string)?.length !== 32 ||
          !validBlob(envelope.blob)) return failure(400, "invalid wrapped envelope");
      const row = first(this.sql.exec<Json>(`SELECT device_id AS id,name,signing_public,wrapping_public,
        fingerprint,created_at,approved,envelope,revoked_at FROM enrollments WHERE device_id=?`, deviceID));
      if (!row) return failure(404, "enrollment not found");
      if (row.approved === 1) return failure(409, "enrollment already approved");
      if (this.invitationRow(deviceID)) return failure(409, "invitation must use versioned approval endpoint");
      this.ctx.storage.transactionSync(() => {
        this.reserve(auth);
        const result = this.sql.exec("UPDATE enrollments SET approved=1,envelope=? WHERE device_id=? AND approved=0",
          JSON.stringify(envelope), deviceID);
        if (result.rowsWritten !== 1) throw new Error("already approved");
        this.sql.exec(`INSERT INTO devices(id,name,signing_public,wrapping_public,fingerprint,created_at)
          VALUES (?,?,?,?,?,?)`, row.id, row.name, row.signing_public, row.wrapping_public, row.fingerprint, row.created_at);
        this.audit(auth, "enrollment_approval", "succeeded", deviceID);
      });
      return json(200, { device: publicDevice(row), approved: true });
    }
    return failure(404, "not found");
  }

  private expireInvitations(deviceID = ""): void {
    const now = canonicalSecond();
    const query = deviceID
      ? "SELECT device_id FROM invitations WHERE state='pending' AND expires_at<=? AND device_id=?"
      : "SELECT device_id FROM invitations WHERE state='pending' AND expires_at<=?";
    const rows = deviceID
      ? [...this.sql.exec<{ device_id: string }>(query, now, deviceID)]
      : [...this.sql.exec<{ device_id: string }>(query, now)];
    for (const row of rows) {
      this.sql.exec(`UPDATE invitations SET state='expired',terminal_at=?,terminal_actor='server'
        WHERE device_id=? AND state='pending'`, now, row.device_id);
      this.audit(null, "invitation_expiry", "succeeded", row.device_id, "expired");
    }
  }

  private invitationRow(deviceID: string): Json | null {
    return first(this.sql.exec<Json>(`SELECT i.device_id AS id,e.name,e.signing_public,e.wrapping_public,
      e.fingerprint,e.created_at,i.protocol_version,i.state,i.expires_at,i.failed_attempts,
      i.terminal_at,i.terminal_actor,e.envelope FROM invitations i JOIN enrollments e
      ON e.device_id=i.device_id WHERE i.device_id=?`, deviceID)) ?? null;
  }

  private async invitations(request: Request, _vaultID: string, deviceID: string, action: string): Promise<Response> {
    if (request.method === "POST" && !deviceID) {
      const parsed = await readJSON(request);
      if (parsed instanceof Response) return parsed;
      const value = parsed.value;
      const name = typeof value.name === "string" ? value.name.trim() : "";
      if (value.version !== 1) {
        this.ctx.storage.transactionSync(() => this.audit(null, "invitation_creation", "rejected", "", "unsupported_version"));
        return failure(400, "unsupported invitation version");
      }
      if (!name || name.length > 64 || /[\u0000-\u001f\u007f]/.test(name) ||
          !validPublicKeys(value.signing_public, value.wrapping_public)) {
        this.ctx.storage.transactionSync(() => this.audit(null, "invitation_creation", "rejected", "", "invalid_request"));
        return failure(400, "device fields are required");
      }
      const signing = value.signing_public as string;
      const wrapping = value.wrapping_public as string;
      const id = randomID();
      const created = canonicalSecond();
      const expires = canonicalSecond(new Date(Date.now() + 10 * 60_000));
      const device: PublicDevice = { id, name, signing_public: signing, wrapping_public: wrapping,
        fingerprint: await fingerprint(signing, wrapping), created_at: created };
      this.ctx.storage.transactionSync(() => {
        this.sql.exec(`INSERT INTO enrollments(device_id,name,signing_public,wrapping_public,fingerprint,created_at)
          VALUES (?,?,?,?,?,?)`, id, name, signing, wrapping, device.fingerprint, created);
        this.sql.exec(`INSERT INTO invitations(device_id,protocol_version,state,expires_at)
          VALUES (?,1,'pending',?)`, id, expires);
        this.audit(null, "invitation_creation", "succeeded", id);
      });
      return json(201, { version: 1, device, state: "pending", expires_at: expires, attempts_remaining: 5 });
    }

    const read = request.method === "GET" ? new Uint8Array() : await readBody(request);
    if (read instanceof Response) return read;
    const body = read;
    const auth = await this.authenticate(request, body, !!deviceID);
    if (auth instanceof Response) return auth;
    if (request.method === "GET" && !deviceID) {
      let rows: Json[] = [];
      this.ctx.storage.transactionSync(() => {
        this.reserve(auth);
        this.expireInvitations();
        rows = [...this.sql.exec<Json>(`SELECT i.device_id AS id,e.name,e.signing_public,e.wrapping_public,
          e.fingerprint,e.created_at,i.protocol_version,i.state,i.expires_at,i.failed_attempts,
          i.terminal_at,i.terminal_actor,e.envelope FROM invitations i JOIN enrollments e
          ON e.device_id=i.device_id ORDER BY e.created_at,i.device_id`)];
        this.audit(auth, "invitation_list");
      });
      return json(200, rows.map((row) => invitationJSON(row, false)));
    }
    if (request.method === "GET" && deviceID) {
      let row: Json | null = null;
      this.ctx.storage.transactionSync(() => {
        this.reserve(auth);
        this.expireInvitations(deviceID);
        row = this.invitationRow(deviceID);
        this.audit(auth, "invitation_status", row ? "succeeded" : "rejected", deviceID, row ? "" : "not_found");
      });
      if (!row) return failure(404, "invitation not found");
      if (!this.device(auth.identityID) && auth.identityID !== deviceID) return failure(401, "device cannot inspect invitation");
      return json(200, invitationJSON(row, auth.identityID === deviceID));
    }
    if (request.method !== "POST" || !deviceID || !["approve", "reject", "cancel"].includes(action)) {
      return failure(404, "not found");
    }
    let value: Json;
    try { value = JSON.parse(new TextDecoder().decode(body)) as Json; } catch { value = {}; }
    let row = this.invitationRow(deviceID);
    if (!row) return failure(404, "invitation not found");
    this.ctx.storage.transactionSync(() => this.expireInvitations(deviceID));
    row = this.invitationRow(deviceID);
    if (!row || row.state !== "pending") return failure(409, `invitation is ${row?.state ?? "missing"}`);
    const active = this.device(auth.identityID)?.revoked_at == null && this.device(auth.identityID) !== null;
    const roleOK = action === "cancel" ? auth.identityID === deviceID && !active : active;
    const bindingOK = value.version === row.protocol_version && value.device_id === deviceID &&
      value.fingerprint === row.fingerprint;
    const envelope = value.envelope as Json | undefined;
    const envelopeOK = action !== "approve" || (!!envelope && envelope.version === 1 &&
      decodeBase64url(envelope.ephemeral_key as string)?.length === 32 && validBlob(envelope.blob));
    if (!roleOK || !bindingOK || !envelopeOK) {
      let exhausted = false;
      this.ctx.storage.transactionSync(() => {
        this.reserve(auth);
        const attempts = (row!.failed_attempts as number) + 1;
        exhausted = attempts >= 5;
        this.sql.exec(`UPDATE invitations SET failed_attempts=?,state=?,terminal_at=?,terminal_actor=?
          WHERE device_id=? AND state='pending'`, attempts, exhausted ? "attempts_exhausted" : "pending",
          exhausted ? canonicalSecond() : null, exhausted ? auth.identityID : null, deviceID);
        this.audit(auth, invitationOperation(action), "rejected", deviceID,
          exhausted ? "attempt_exhaustion" : roleOK ? "binding_mismatch" : "incorrect_actor");
      });
      return failure(exhausted ? 409 : 400, exhausted ? "invitation attempts exhausted" :
        roleOK ? "invitation transition binding mismatch" : "device cannot perform invitation transition");
    }
    const next = action === "approve" ? "approved" : action === "reject" ? "rejected" : "cancelled";
    const terminal = canonicalSecond();
    this.ctx.storage.transactionSync(() => {
      this.reserve(auth);
      this.sql.exec(`UPDATE invitations SET state=?,terminal_at=?,terminal_actor=?
        WHERE device_id=? AND state='pending'`, next, terminal, auth.identityID, deviceID);
      if (action === "approve") {
        this.sql.exec("UPDATE enrollments SET approved=1,envelope=? WHERE device_id=? AND approved=0",
          JSON.stringify(envelope), deviceID);
        this.sql.exec(`INSERT INTO devices(id,name,signing_public,wrapping_public,fingerprint,created_at)
          VALUES (?,?,?,?,?,?)`, row!.id, row!.name, row!.signing_public, row!.wrapping_public,
          row!.fingerprint, row!.created_at);
      }
      this.audit(auth, invitationOperation(action), "succeeded", deviceID);
    });
    return json(200, invitationJSON({ ...row, state: next, terminal_at: terminal,
      envelope: action === "approve" ? JSON.stringify(envelope) : row.envelope }, false));
  }

  private async devices(request: Request, vaultID: string, deviceID: string): Promise<Response> {
    const read = await readBody(request);
    if (read instanceof Response) return read;
    const body = read;
    const auth = await this.authenticate(request, body);
    if (auth instanceof Response) return auth;
    if (request.method === "GET" && !deviceID) {
      const devices = [...this.sql.exec<DeviceRow>(`SELECT id,name,signing_public,wrapping_public,fingerprint,
        created_at,revoked_at FROM devices ORDER BY created_at,id`)].map(deviceStatus);
      this.ctx.storage.transactionSync(() => { this.reserve(auth); this.audit(auth, "device_list"); });
      return json(200, devices);
    }
    if (request.method === "DELETE" && deviceID) {
      const target = this.device(deviceID);
      if (!target) return failure(404, "device not found");
      if (target.revoked_at) return failure(409, "device already revoked");
      const active = first(this.sql.exec<{ count: number }>("SELECT count(*) AS count FROM devices WHERE revoked_at IS NULL"))!.count;
      if (active <= 1) return failure(409, "cannot revoke final active device");
      const revoked = canonicalSecond();
      this.ctx.storage.transactionSync(() => {
        this.reserve(auth);
        this.sql.exec("UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL", revoked, deviceID);
        this.audit(auth, "device_revocation", "succeeded", deviceID);
      });
      return json(200, deviceStatus({ ...target, revoked_at: revoked }));
    }
    return failure(404, "not found");
  }

  private async records(request: Request, _vaultID: string, recordID: string): Promise<Response> {
    const read = await readBody(request);
    if (read instanceof Response) return read;
    const body = read;
    const auth = await this.authenticate(request, body);
    if (auth instanceof Response) return auth;
    if (request.method === "GET" && !recordID) {
      const records = [...this.sql.exec<Json>("SELECT id,revision,blob,modified_at FROM records ORDER BY id")]
        .map(storedJSON);
      this.ctx.storage.transactionSync(() => { this.reserve(auth); this.audit(auth, "record_list"); });
      return json(200, records);
    }
    if (request.method === "PUT" && recordID) {
      let value: Json;
      try { value = JSON.parse(new TextDecoder().decode(body)) as Json; } catch { return failure(400, "invalid JSON request"); }
      if (!Number.isSafeInteger(value.expected_revision) || (value.expected_revision as number) < 0 || !validBlob(value.blob)) {
        return failure(400, "invalid record update");
      }
      const current = first(this.sql.exec<{ revision: number }>("SELECT revision FROM records WHERE id=?", recordID));
      if ((current?.revision ?? 0) !== value.expected_revision) return failure(409, "record revision conflict");
      const revision = (value.expected_revision as number) + 1;
      const modified = canonicalSecond();
      this.ctx.storage.transactionSync(() => {
        this.reserve(auth);
        this.sql.exec(`INSERT INTO records(id,revision,blob,modified_at) VALUES (?,?,?,?)
          ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,blob=excluded.blob,modified_at=excluded.modified_at
          WHERE records.revision=?`, recordID, revision, JSON.stringify(value.blob), modified, value.expected_revision as number);
        this.audit(auth, "record_update", "succeeded", recordID);
      });
      return json(200, { id: recordID, revision, blob: value.blob, modified_at: modified });
    }
    return failure(404, "not found");
  }

  private async objects(request: Request, _vaultID: string, objectID: string): Promise<Response> {
    const read = await readBody(request);
    if (read instanceof Response) return read;
    const body = read;
    const auth = await this.authenticate(request, body);
    if (auth instanceof Response) return auth;
    if (request.method === "GET") {
      const rows = objectID
        ? [...this.sql.exec<Json>("SELECT id,revision,blob,modified_at FROM vault_objects WHERE id=?", objectID)]
        : [...this.sql.exec<Json>("SELECT id,revision,blob,modified_at FROM vault_objects ORDER BY id")];
      if (objectID && rows.length === 0) return failure(404, "vault object not found");
      this.ctx.storage.transactionSync(() => { this.reserve(auth); this.audit(auth, objectID ? "object_read" : "object_list", "succeeded", objectID); });
      return json(200, objectID ? storedJSON(rows[0]) : rows.map(storedJSON));
    }
    let value: Json;
    try { value = JSON.parse(new TextDecoder().decode(body)) as Json; } catch { return failure(400, "invalid JSON request"); }
    const current = first(this.sql.exec<{ revision: number }>("SELECT revision FROM vault_objects WHERE id=?", objectID));
    if (!Number.isSafeInteger(value.expected_revision) || (current?.revision ?? 0) !== value.expected_revision) {
      return failure(409, "vault object revision conflict");
    }
    if (request.method === "DELETE") {
      this.ctx.storage.transactionSync(() => {
        this.reserve(auth);
        this.sql.exec("DELETE FROM vault_objects WHERE id=? AND revision=?", objectID, value.expected_revision as number);
        this.audit(auth, "object_delete", "succeeded", objectID);
      });
      return new Response(null, { status: 204, headers: responseHeaders });
    }
    if (request.method === "PUT" && validBlob(value.blob) && typeof value.modified_at === "string") {
      const revision = (value.expected_revision as number) + 1;
      this.ctx.storage.transactionSync(() => {
        this.reserve(auth);
        this.sql.exec(`INSERT INTO vault_objects(id,revision,blob,modified_at) VALUES (?,?,?,?)
          ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,blob=excluded.blob,modified_at=excluded.modified_at
          WHERE vault_objects.revision=?`, objectID, revision, JSON.stringify(value.blob), value.modified_at as string,
          value.expected_revision as number);
        this.audit(auth, "object_update", "succeeded", objectID);
      });
      return json(200, { id: objectID, revision, blob: value.blob, modified_at: value.modified_at });
    }
    return failure(400, "invalid vault object update");
  }

  private async events(request: Request, vaultID: string): Promise<Response> {
    if (request.method !== "GET") return failure(404, "not found");
    const auth = await this.authenticate(request, new Uint8Array());
    if (auth instanceof Response) return auth;
    const url = new URL(request.url);
    const limitText = url.searchParams.get("limit");
    const limit = limitText === null ? 100 : Number(limitText);
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) return failure(400, "limit must be between 1 and 500");
    const beforeText = url.searchParams.get("before");
    const before = beforeText === null ? null : decodeCursor(beforeText);
    if (beforeText !== null && before === null) return failure(400, "invalid cursor");
    const rows = before === null
      ? [...this.sql.exec<Json>(`SELECT sequence,id,timestamp,identity_id,identity_verified,
          target_identity_id,operation,outcome,reason FROM access_events ORDER BY sequence DESC LIMIT ?`, limit + 1)]
      : [...this.sql.exec<Json>(`SELECT sequence,id,timestamp,identity_id,identity_verified,
          target_identity_id,operation,outcome,reason FROM access_events WHERE sequence<?
          ORDER BY sequence DESC LIMIT ?`, before, limit + 1)];
    const page = rows.slice(0, limit).map((row) => eventJSON(row, vaultID));
    this.ctx.storage.transactionSync(() => { this.reserve(auth); this.audit(auth, "event_list"); });
    const result: Json = { events: page };
    if (rows.length > limit) result.next_cursor = cursor(rows[limit - 1].sequence as number);
    return json(200, result);
  }
}

function enrollmentJSON(row: Json): Json {
  const result: Json = {
    device: publicDevice(row),
    approved: row.approved === 1,
  };
  if (row.envelope) result.envelope = JSON.parse(row.envelope as string);
  if (row.revoked_at) result.revoked_at = row.revoked_at;
  return result;
}

function publicDevice(row: Json): PublicDevice {
  return { id: row.id as string, name: row.name as string, signing_public: row.signing_public as string,
    wrapping_public: row.wrapping_public as string, fingerprint: row.fingerprint as string,
    created_at: row.created_at as string };
}

function invitationOperation(action: string): string {
  return action === "approve" ? "invitation_approval" :
    action === "reject" ? "invitation_rejection" : "invitation_cancellation";
}

function invitationJSON(row: Json, includeEnvelope: boolean): Json {
  const result: Json = {
    version: row.protocol_version,
    device: { id: row.id, name: row.name, signing_public: row.signing_public,
      wrapping_public: row.wrapping_public, fingerprint: row.fingerprint, created_at: row.created_at },
    state: row.state,
    expires_at: row.expires_at,
    attempts_remaining: 5 - (row.failed_attempts as number),
  };
  if (row.terminal_at) result.terminal_at = row.terminal_at;
  if (includeEnvelope && row.state === "approved" && row.envelope) {
    result.envelope = JSON.parse(row.envelope as string);
  }
  return result;
}

function deviceStatus(row: DeviceRow): Json {
  const result: Json = { device: { id: row.id, name: row.name, signing_public: row.signing_public,
    wrapping_public: row.wrapping_public, fingerprint: row.fingerprint, created_at: row.created_at } };
  if (row.revoked_at) result.revoked_at = row.revoked_at;
  return result;
}

function storedJSON(row: Json): Json {
  return { id: row.id, revision: row.revision, blob: JSON.parse(row.blob as string), modified_at: row.modified_at };
}

function eventJSON(row: Json, vaultID: string): Json {
  const result: Json = { id: row.id, vault_id: vaultID, timestamp: row.timestamp,
    identity_verified: row.identity_verified === 1, operation: row.operation, outcome: row.outcome };
  if (row.identity_id) result.identity_id = row.identity_id;
  if (row.target_identity_id) result.target_identity_id = row.target_identity_id;
  if (row.reason) result.reason = row.reason;
  return result;
}

function cursor(sequence: number): string {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(sequence));
  return base64url(bytes);
}

function decodeCursor(value: string): number | null {
  const bytes = decodeBase64url(value);
  if (!bytes || bytes.length !== 8) return null;
  const sequence = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0);
  return sequence > 0n && sequence <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(sequence) : null;
}

function first<T extends Record<string, SqlStorageValue>>(cursor: SqlStorageCursor<T>): T | undefined {
  for (const row of cursor) return row;
  return undefined;
}
