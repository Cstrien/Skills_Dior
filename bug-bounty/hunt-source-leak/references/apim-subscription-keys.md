# Public API gateway keys in frontend bundles

Use this reference when JS/static analysis reveals API gateway credentials such as Azure API Management subscription keys, `x-api-key`, or gateway-specific client keys.

## Detection patterns

Search public JS bundles and HTML config for:

```bash
grep -RniE 'Ocp-Apim-Subscription-Key|gatewaySubscriptionKey|subscriptionKey|x-api-key|api[_-]?key|gatewayUrl|services\.gateway' recon/<target>/js/
```

Azure APIM common strings:

- `Ocp-Apim-Subscription-Key`
- `gatewaySubscriptionKey`
- `Access denied due to missing subscription key`
- `Access denied due to invalid subscription key`

Frontend framework pattern:

```js
axios.create({
  baseURL: config.services.gatewayUrl,
  headers: {
    "Ocp-Apim-Subscription-Key": config.services.gatewaySubscriptionKey,
    "Content-Type": "application/json"
  }
})
```

## Validation workflow

1. Prove the key is publicly retrievable from a static asset.
2. Redact the key in notes; store only a hash or first/last characters.
3. Pick a read-only endpoint first. Avoid auth, payment, order submission, wallet, or state-changing endpoints.
4. Compare responses:

```bash
# Missing key baseline
curl -sk https://api.target.com/safe/read-only/path

# With public frontend key
curl -sk \
  -H 'Ocp-Apim-Subscription-Key: <REDACTED>' \
  -H 'Content-Type: application/json' \
  https://api.target.com/safe/read-only/path
```

5. Record status, size, content-type, and a short snippet only. Do not dump large datasets.
6. If endpoints begin returning `429`, stop active probing and switch back to static analysis/route mapping.

## Severity guidance

Do **not** overclaim. Public frontend API keys are often intentionally non-secret client identifiers. Severity depends on what the key gates:

- **Informational/Low**: only public menu/catalog/restaurant/status data.
- **Medium**: direct scripted access to operational data, broad endpoint discovery, or weak rate-limiting that materially expands abuse surface.
- **High/Critical**: key alone unlocks customer data, payment/wallet data, loyalty balances, admin functions, or state-changing operations without a user JWT/session.

Report as a chain lead when the key is intended-public but enables later business-logic testing with a guest/customer JWT.

## Evidence hygiene

- Never paste the full key into the final report unless the user explicitly needs a private client deliverable and asks for it.
- Prefer `SHA-256(key)` plus first/last 4–6 chars in working notes.
- State exactly which endpoints remained protected by JWT/additional auth.
