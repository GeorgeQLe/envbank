// Status-only health for the disposable acceptance fixture: 200 when the
// approved fixture variable is configured, 503 otherwise. No body, no logs,
// no outbound requests, no value or hash in any response.
module.exports = function handler(req, res) {
  const value = process.env.ENVBANK_ACCEPTANCE_FIXTURE_SECRET;
  res.statusCode = req.method === 'GET' && typeof value === 'string' && Buffer.byteLength(value) >= 32 ? 200 : 503;
  res.setHeader('Cache-Control', 'no-store');
  res.end();
};
