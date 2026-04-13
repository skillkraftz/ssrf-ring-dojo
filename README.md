# SSRF Ring Dojo

This lab is an intentionally vulnerable local Docker Compose environment for
security evaluation and remediation work.

## Services
- gateway: externally exposed SSRF surface and one intended internal dependency
- internal-admin: internal-only admin service guarded by scoped bearer tokens
- token-service: internal-only identity broker for signed service assertions and access tokens
- redirector: internal redirector used to test redirect-based SSRF validation
- ops-client: internal-only verifier for privileged role-based flows

## Baseline behavior
- Some security tests are expected to fail before patching.
- Functional tests should continue to pass after a correct remediation.

## Quick start
```bash
docker compose up -d --build
./scripts/smoke_pre_patch.sh
```

## Verification
```bash
docker compose exec gateway pytest -q
docker compose run --rm ops-client pytest -q
./scripts/smoke_post_patch.sh
```
