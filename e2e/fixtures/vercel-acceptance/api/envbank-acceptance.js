// EnvBank disposable Vercel acceptance fixture.
//
// Status-only proof that THIS deployment consumed the exact approved value of
// ENVBANK_ACCEPTANCE_FIXTURE_SECRET. It has no database, makes no outbound
// requests, writes no logs and never returns a body, the value or a hash of
// it. The harness sends a fresh random challenge and
// proof = base64url(HMAC-SHA256(key=value, "envbank.vercel.acceptance.v1" NUL challenge)).
//
//   204  proof matches (value present and equal to the approved revision)
//   409  value present, proof differs (stale build or negative control)
//   424  value absent or shorter than 32 bytes
//   400  malformed request
//   405  any method other than GET
//
// Deploy ONLY to a dedicated disposable project named envbank-acceptance-*.
const crypto = require('node:crypto');

const DOMAIN = 'envbank.vercel.acceptance.v1';
const CHALLENGE = 'x-envbank-acceptance-challenge';
const PROOF = 'x-envbank-acceptance-proof';
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

function finish(res, status) {
  res.statusCode = status;
  res.setHeader('Cache-Control', 'no-store');
  res.end();
}

module.exports = function handler(req, res) {
  if (req.method !== 'GET') {
    finish(res, 405);
    return;
  }
  const value = process.env.ENVBANK_ACCEPTANCE_FIXTURE_SECRET;
  if (typeof value !== 'string' || Buffer.byteLength(value) < 32) {
    finish(res, 424);
    return;
  }
  const challenge = req.headers[CHALLENGE];
  const proof = req.headers[PROOF];
  if (typeof challenge !== 'string' || typeof proof !== 'string' || !TOKEN.test(challenge) || !TOKEN.test(proof)) {
    finish(res, 400);
    return;
  }
  const expected = crypto
    .createHmac('sha256', value)
    .update(DOMAIN)
    .update(Buffer.from([0]))
    .update(challenge)
    .digest();
  const supplied = Buffer.from(proof, 'base64url');
  const match = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
  finish(res, match ? 204 : 409);
};
