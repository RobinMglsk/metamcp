# Plan: Per-session short-lived API keys for kcw (klootjescode)

- Date: 2026-11-09
- Ticket: IMP
- Mode: headless
- Status: implemented

## Summary
Each kcw session gets its own MetaMCP API key that is valid for at most 1 hour. kcw mints the key
when the session starts (push model, via a service-authenticated route), and revokes it when the
session ends. When a key expires, kcw starts a new session with a new key, so there is no refresh
flow. Keys reuse the existing `api_keys` table, hashed storage (#7) and auth middleware.

## Assumptions
Check these, they are judgment calls:
1. **Service credential** is a static env token `KCW_SERVICE_TOKEN` (min 32 chars, compared in
   constant time) sent as `Authorization: Bearer`. The routes are meant for the internal network only
   (documented; not enforced in code). Unset = routes return 404 (feature off).
2. **Key owner** is the user in env `KCW_KEY_OWNER_USER_ID` (one shared identity). If unset the keys
   are public (`user_id` NULL), which only reach public endpoints (`checkApiKeyAccess`). Private
   endpoints need the owner set to the endpoint owner.
3. **TTL** is capped server-side at 3600s; the default is 3600s. A requested value above the cap is
   clamped, not rejected.
4. **Scoping**: optional `endpoint_names[]` at mint time. Empty/absent = every endpoint the owner
   can reach (kcw can still choose to always send it).
5. **One live key per kcw session id**: minting again for the same `session_id` revokes the previous
   key and issues a new one (idempotent retry, no key leaks).
6. **Audit**: a `kcw_session_id` column is copied onto each `mcp_request_audit_logs` row (denormalised,
   so it survives deleting the key row). The existing `session_id` column is the MCP transport
   session, so it is not reused.
7. **Retention**: the sweeper deletes keys 24h after expiry/revocation, hourly.
8. **kcw side** (injecting the key into the session's MCP config, revoking on session end) lives in
   the kcw repo and is not planned here.

## Out of scope
- Refresh/rotation of a key inside a running session.
- Per-user identities (one shared owner for now).
- Hashing/scoping changes to existing user-created keys; expiry in the keys UI beyond showing it.
- mTLS/HMAC-signed mint requests (possible follow-up if the env token is judged too weak).
- The kcw client code.

## Approach
**Schema** (`apps/backend/src/db/schema.ts`, new migration `0021_kcw_session_keys.sql` via
`pnpm --filter backend db:generate`):
- `api_keys`: add `expires_at timestamptz NULL` (NULL = never, so every existing key is unchanged),
  `revoked_at timestamptz NULL`, `session_id text NULL`, `endpoint_names text[] NULL`. Add a partial
  unique index on `session_id WHERE session_id IS NOT NULL`, and an index on `expires_at`.
- `mcp_request_audit_logs`: add `kcw_session_id text NULL` + index.

**Key validity** (`db/repositories/api-keys.repo.ts#validateApiKey`): select `expires_at, revoked_at,
endpoint_names, session_id` in both lookups. Run the expiry/revocation check after the lookups
(including the legacy plaintext fallback path) so an expired key can never be accepted through it:
invalid if `!is_active || revoked_at || (expires_at && expires_at <= now())`. Return `endpoint_names`
and `session_id`. The 401 message already says "invalid or expired".

**Scope check** (`middleware/api-key-oauth.middleware.ts`): `checkApiKeyAccess` also takes
`endpoint_names`; if non-null and `endpoint.name` is not in it, return 403 with a clear message. Set
`authReq.apiKeySessionId` next to `apiKeyUuid`; thread it through the places that already pass
`apiKeyUuid` (`streamable-http.ts`, `sse.ts`, `openapi/tool-execution.ts`, `functional-middleware.ts`
auth context, `audit-requests.functional.ts` -> `createAuditLog` -> `mcp-request-audit-logs.repo.ts`).

**Mint/revoke routes** (new `routers/kcw-keys.ts`, mounted in `index.ts` at `/internal/kcw`, before the
tRPC mount; reuses the small default JSON body limit):
- `requireKcwServiceToken` middleware: 404 if `KCW_SERVICE_TOKEN` is unset, 401 on mismatch
  (`crypto.timingSafeEqual` on equal-length digests), failed attempts go through `authRateLimiter`.
- `POST /internal/kcw/keys` body `{ session_id: string, ttl_seconds?: number, endpoint_names?: string[] }`
  (zod in `packages/zod-types/src/api-keys.zod.ts`). Validates `session_id` (1-128 chars, `[\w.-]+`),
  clamps TTL to `[1, 3600]`, in one transaction revokes any live key with that `session_id` and
  inserts the new one. Returns `{ key, key_uuid, expires_at }` (the key is shown once).
- `DELETE /internal/kcw/keys/:session_id` sets `revoked_at = now()`; 204 even if absent/already
  revoked (idempotent).
- Repo methods `createSessionKey` / `revokeBySessionId` / `deleteExpired` in `api-keys.repo.ts`.
- Key name `kcw-session-<session_id>` goes into `lib/reserved-key-names.ts` as a second reserved
  prefix, so users cannot create/rename into it (extend `isReservedKeyName`, its message and its
  tests). Hide these keys from the user key list or mark them read-only in the UI (they appear in
  `findAccessibleToUser` only when public; filter them out of it).

**Sweeper** (`lib/kcw-key-sweeper.ts`, started from `start()` in `index.ts` after DB is up, hourly
`setInterval(...).unref()`): `deleteExpired` removes keys expired/revoked more than 24h ago.

**Config** (`lib/config-guard.ts`, `example.env`, docs): validate `KCW_SERVICE_TOKEN` with
`isPlaceholderSecret` (error in production, like the other secrets); document `KCW_SERVICE_TOKEN`
and `KCW_KEY_OWNER_USER_ID`. Check at startup that the owner user exists (warn if not).

Precedent followed: hashed keys + `key_prefix` (#7), `reserved-key-names.ts`, `config-guard.ts`,
`require-admin-principal.middleware.ts` style middleware, `bootstrap.service.ts` for key creation.

## Steps
All steps done (one commit per step group on `feat/IMP-kcw-session-api-keys`).

1. `schema.ts`: new columns/indexes above; `pnpm --filter backend db:generate`; review the SQL
   (additive, nullable, safe to roll out).
2. `packages/zod-types/src/api-keys.zod.ts`: request/response schemas for mint; rebuild the package.
3. `api-keys.repo.ts`: `validateApiKey` change, `createSessionKey`, `revokeBySessionId`,
   `deleteExpired`; filter kcw keys out of `findAccessibleToUser`.
4. `reserved-key-names.ts` (+ test): second reserved prefix.
5. `middleware/api-key-oauth.middleware.ts`: scope check, `apiKeySessionId`; thread it to the audit
   log (files listed above); add the audit column mapping.
6. `middleware/kcw-service-token.middleware.ts` + `routers/kcw-keys.ts`; mount in `index.ts`.
7. `lib/kcw-key-sweeper.ts`; start it in `index.ts`.
8. `config-guard.ts`, `example.env`, `docs/` note (including: expose `/internal/kcw` only on the
   internal network; reverse proxy must not forward it, add a note to `nginx.conf.example`).
9. Tests (below), `pnpm lint`, `pnpm --filter backend test`, `pnpm check-types`.

## Testing
Vitest, colocated `*.test.ts`:
- `validateApiKey`: valid, expired, revoked, inactive, never-expiring (NULL), and an expired key
  reached through the legacy plaintext fallback is rejected.
- Scope: key with `endpoint_names` gets 403 on another endpoint, 200 on a listed one; NULL = all.
- Service-token middleware: unset -> 404, missing/wrong -> 401, correct -> next; rate limiting.
- Mint: TTL clamp (0, negative, 99999, absent), `session_id` validation, re-mint revokes the old
  key, key returned once and stored hashed, `expires_at` ~ now + ttl.
- Revoke: idempotent, key rejected immediately afterwards.
- Sweeper: deletes only rows expired/revoked > 24h ago.
- Reserved names: users cannot create `kcw-session-*` keys.
- Audit row carries `kcw_session_id`.
Manual (QA harness: embedded Postgres + `tsx src/index.ts`): mint with curl, call a
streamable-http endpoint with `X-API-Key`, revoke and confirm 401, mint with `ttl_seconds=2`, wait
and confirm 401, check the audit log row.

## Risks / open questions
- **The service token is a bearer secret that mints unlimited keys.** Mitigations: internal network
  only, rate limiting, TTL cap, optional scoping. Is that enough, or HMAC-signed requests now?
- Public keys (owner unset) only reach public endpoints; confirm which owner you want in production.
- Clock skew between instances: expiry uses the DB clock (`now()` in SQL), not the app clock.
- `authRateLimiter` identifiers are per endpoint; the mint route needs its own identifier (IP) so
  it cannot be used to lock out real endpoint users.
- Migration is additive; old app instances ignore the new columns but would not enforce expiry
  during a rolling deploy: mint routes should only be enabled after the rollout completes.
- This builds on the merged security work (#4, #7, #12, #14); no dependency on open PRs.

## Deviations
- Step 1: the partial unique index on `api_keys.session_id` only covers live keys
  (`session_id IS NOT NULL AND revoked_at IS NULL`). A revoked key keeps its `session_id`, so a plain
  partial index would have made re-minting for the same session fail.
- Step 3: key names are `kcw-session-<session_id>-<base36 timestamp>`, because `(user_id, name)` is
  unique and a revoked key of the same session still holds the name.
- Step 6: the service-token middleware uses a separate `AuthRateLimiter` (10 failures/min per IP) and
  calls only `isRateLimited`, which already counts the attempt (the existing endpoint middleware calls
  `recordFailedAttempt` first and so counts every failure twice; left unchanged).
- Step 8: `KCW_SERVICE_TOKEN` and `KCW_KEY_OWNER_USER_ID` added to `globalEnv` in `turbo.json` (CLAUDE.md
  requires it); docs page `docs/en/integrations/kcw-session-keys.mdx` and a `/internal/` 404 block in
  `nginx.conf.example` added. The frontend does not rewrite `/internal`, so the routes are unreachable
  through it anyway.
- The startup warning for a missing owner user (Config paragraph) was not built: an unknown
  `KCW_KEY_OWNER_USER_ID` fails at mint time with a 500 (foreign key). **needs review** (cheap to add).

## Verification
- Backend: 321 tests pass (baseline 279), `pnpm lint`, `pnpm check-types`, `tsc --noEmit` clean.
- Live (embedded Postgres + backend): no/wrong token 401; mint 201 with TTL clamped to 1h; scoped key
  200 on the listed endpoint and 403 on another; invalid key 401; re-mint revokes the old key; revoke
  204 then 401; `ttl_seconds=2` works then 401 after 3s; bad body 400; sweeper deleted a key revoked
  25h ago and one expired 26h ago and kept a recently revoked one; keys stored hashed.
- Not verified live: the audit row's `kcw_session_id` (needs an upstream MCP server to call a tool;
  covered by a unit test), the UI key list (kcw keys are filtered out in the repository query).

## Follow-ups
- `findAll()` / `findPublicApiKeys()` in `api-keys.repo.ts` do not filter kcw keys (no callers found
  outside tests).
- Show `kcw_session_id` in the request-log UI.
- Signed (HMAC) mint requests if the shared token is judged too weak.
