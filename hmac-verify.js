// HMAC verification helpers for webhooks (GitHub + Stripe-style).

const crypto = require("crypto");

/** Constant-time compare of two hex strings. */
function timingSafeEqualHex(aHex, bHex) {
  if (typeof aHex !== "string" || typeof bHex !== "string") return false;
  const a = Buffer.from(aHex, "hex");
  const b = Buffer.from(bHex, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/** Generic HMAC-SHA verification: compute HMAC(algo, secret, payload) and compare to expected hex sig. */
function verifyHmac({ algo = "sha256", secret, payload, expected }) {
  if (!secret || expected == null) return false;
  const h = crypto.createHmac(algo, secret).update(payload).digest("hex");
  return timingSafeEqualHex(h, expected);
}

/** Parse GitHub's signature header: "sha256=<hex>" (preferred) or "sha1=<hex>" (legacy). */
function parseGitHubSignature(headerValue) {
  if (!headerValue) return null;
  const [algo, hex] = String(headerValue).split("=");
  if (!hex || (algo !== "sha256" && algo !== "sha1")) return null;
  return { algo, hex };
}

/**
 * Verify a GitHub webhook.
 * - Header: "X-Hub-Signature-256: sha256=<hexdigest>" (or X-Hub-Signature: sha1=<...>)
 * - Payload: RAW request body (Buffer), not parsed JSON string.
 */
function verifyGitHubSignature({ secret, payload, signatureHeader }) {
  const parsed = parseGitHubSignature(signatureHeader);
  if (!parsed) return false;
  return verifyHmac({
    algo: parsed.algo,
    secret,
    payload,
    expected: parsed.hex,
  });
}

/**
 * Verify a Stripe-style webhook.
 * - Header: "Stripe-Signature: t=<unix>,v1=<hexdigest>[,v0=...,v1=...]"
 * - Signed payload is: `${t}.${rawBody}`
 * - Reject if timestamp is too old (default 5 min).
 */
function parseStripeHeader(headerValue) {
  if (!headerValue) return null;
  const parts = Object.fromEntries(
    String(headerValue)
      .split(",")
      .map((kv) => kv.split("=").map((s) => s.trim()))
  );
  if (!parts.t || !parts.v1) return null;
  const t = Number(parts.t);
  if (!Number.isFinite(t)) return null;
  return { t, v1: parts.v1 };
}

function verifyStripeSignature({
  secret,
  payload,
  header,
  toleranceSec = 5 * 60,
  nowSec = () => Math.floor(Date.now() / 1000),
}) {
  const parsed = parseStripeHeader(header);
  if (!parsed) return false;

  // Timestamp freshness check
  const skew = Math.abs(nowSec() - parsed.t);
  if (skew > toleranceSec) return false;

  const signed = `${parsed.t}.${Buffer.isBuffer(payload) ? payload.toString("utf8") : String(payload)}`;
  return verifyHmac({
    algo: "sha256",
    secret,
    payload: signed,
    expected: parsed.v1,
  });
}

module.exports = {
  timingSafeEqualHex,
  verifyHmac,
  verifyGitHubSignature,
  verifyStripeSignature,
  parseGitHubSignature,
  parseStripeHeader,
};
