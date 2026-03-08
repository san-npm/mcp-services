# Security Notes

## Supported security posture

This service is designed for internet exposure, but requires correct deployment configuration.

## Key controls

- SSRF protections in browser and outbound fetch paths
- Auth tiers: free/IP limited, API key, x402 pay-per-call
- Stripe webhook signature verification
- x402 replay protection with persistent tx-hash cache
- x402 transaction freshness checks (`X402_MAX_TX_AGE_SECONDS`)
- Namespaced memory isolation by auth tier

## Production requirements

1. `NODE_ENV=production`
2. `ALLOW_APIKEY_QUERY=false`
3. Correct `TRUST_PROXY` value for your reverse-proxy topology
4. Set strict `SSE_ALLOWED_HOSTS` and `SSE_ALLOWED_ORIGINS`
5. Keep `X402_TEST_MODE=0` (test mode is ignored in production)
6. Persist:
   - `KEYS_FILE`
   - `MEMORY_DB_PATH`
   - `X402_TX_CACHE_FILE`

## Dependency hygiene

- Run `npm audit` in CI.
- This repo uses an override for `express-rate-limit` to avoid a known high-severity advisory in transitive deps.

## Reporting

If you find a vulnerability, open a private report to the maintainers before public disclosure.
