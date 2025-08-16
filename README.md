# hmac-verify (Node)

Dependency-free helpers to verify HMAC-signed **webhooks** in Node.js.

- ✅ **GitHub**: `X-Hub-Signature-256: sha256=<hex>` (or legacy `sha1=…`)
- ✅ **Stripe-style**: `Stripe-Signature: t=<unix>,v1=<hex>[,…]` with timestamp tolerance + constant-time compare
- ⚠️ **Important**: verify against the **RAW** request body (bytes), not the parsed JSON

```bash
npm i hmac-verify
# (or just copy hmac-verify.js into your repo)
