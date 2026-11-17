# Agent Games Gatekeeper — Vercel hosting

Prabowo's Proof Gatekeeper endpoint for zkVerify Agent Games, as a Vercel
serverless function. Ported from `../server.js` (Node built-ins only, zero
dependencies). The localtunnel tunnel from the VM is 403-blocked at the
egress-IP level since 2026-11-16, so this moves the public endpoint off
the VM for Rounds 6–8 (18–20 Nov 2026).

## Deploy

```bash
vercel login            # once, confirm on your phone
vercel --prod           # first deploy creates the project
# set the HMAC secret (from run/secret.env, NEVER commit it):
grep '^AGENT_GAMES_HMAC_SECRET=' ../run/secret.env | cut -d= -f2- \
  | vercel env add AGENT_GAMES_HMAC_SECRET production
vercel --prod           # redeploy so the env var takes effect
```

## Test

```bash
curl https://<project>.vercel.app/health
# signed preflight: see ../test.js (adapted) or sign a POST with the secret
# and check the response carries x-agent-games-signature
```

## Swap (only after the Round 5 lock ends ~03:30 WIB 2026-11-18)

1. Update the registered endpoint URL in the Agent Games dashboard to the
   `*.vercel.app` URL.
2. Re-run the signed preflight against the new URL and confirm 200 + signature match.

## Caveats

- The `proof_tx` seen-set lives in `/tmp` — it survives warm invocations on
  one instance but resets on a cold start, so PROOF_REUSED protection can
  reset. Accepted: the platform does not replay proofs.
- Vercel Hobby functions cap at 10 s per invocation; the handler answers
  in milliseconds, so this is not a constraint.
- The local stack (`../server.js` + localtunnel) stays as fallback; the
  cool-down flag `../run/cooldown.txt` holds the driver down while the
  Vercel endpoint is primary.
