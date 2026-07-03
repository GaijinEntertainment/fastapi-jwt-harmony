# Code Audit — fastapi-jwt-harmony

Audit date: 2026-07-03
Scope: `src/fastapi_jwt_harmony/` (all modules)
Method: manual source review of every module + empirical verification of the
high-impact findings against the installed dependency set (PyJWT 2.10+,
Pydantic 2, Python 3.14).

**Update (2026-07-03):** the fixes marked ✅ below have been applied to the
source and are covered by regression tests in `tests/test_audit_fixes.py`. The
full suite (130 tests), `mypy --strict`, and `ruff` all pass.

**Review round (2026-07-03):** an independent adversarial review of the applied
fixes confirmed no auth/CSRF/denylist/cache bypass. It surfaced follow-up items,
all addressed (see [Review-round follow-ups](#review-round-follow-ups)).

## Summary

| # | Severity | Area | Title | Status |
|---|----------|------|-------|--------|
| [1](findings.md#1-crafted-alg-header-causes-unhandled-runtimeerror-http-500) | High | Robustness / DoS | Crafted `alg` header raises an **unhandled `RuntimeError` → HTTP 500** | ✅ Fixed |
| [2](findings.md#2-header-controlled-algorithm-selection-for-the-decode-key) | Medium (security) | Crypto | Decode key is chosen from the **attacker-controlled** token header | ✅ Fixed (allowlist check) |
| [3](findings.md#3-denylist-callback-runs-on-the-unverified-token) | Medium (security) | Denylist | Denylist callback runs against the **unverified** token payload | ✅ Fixed |
| [4](findings.md#4-user_claims-omits-aud-and-iss-from-the-reserved-set) | Medium | Correctness | `user_claims` silently returns `None` when `audience`/`issuer` is used | ✅ Fixed |
| [5](findings.md#5-falsy-subject-0--is-rejected) | Medium | Correctness | Integer/`0`/empty `subject` is rejected as "missing" | ✅ Fixed |
| [6](findings.md#6-invalid-header-token-short-circuits-cookie-fallback) | Medium | Correctness | A bad header token prevents the cookie fallback from being tried | ✅ Fixed |
| [7](findings.md#7-token-decoded-24x-per-request-repeated-denylist-callbacks) | Medium | Performance | Each request decodes the JWT 2–4× and re-invokes the denylist callback | ✅ Fixed (memoized) |
| [8](findings.md#8-no-samesitenone--secure-consistency-validation) | Low | Config | `cookie_samesite='none'` allowed without `cookie_secure=True` | ✅ Fixed |
| [9](findings.md#9-required-keys-are-not-validated-at-configure-time) | Low | Config | Missing `secret_key`/`private_key` fails lazily at token time, not startup | ⏭️ Deferred (documented design) |
| [10](findings.md#10-global-str_min_length1-blocks-legitimate-empty-string-config) | Low | Config | Global `str_min_length=1` blocks empty `header_type` and similar | ⏭️ Deferred |
| [11](findings.md#11-configure-silently-keeps-stale-config-when-config-is-none) | Low | API | `configure(..., config=None)` silently keeps previous/`None` config | ⏭️ Deferred |
| [12](findings.md#12-cookies-are-unset-without-samesitesecure-attributes) | Low | Cookies | `unset_*_cookies` omit `samesite`/`secure`, may fail to clear in some browsers | ✅ Fixed |
| [13](findings.md#13-minor-issues--nits) | Info | Various | Dead code, typing gaps, duplicated logic, global singleton state | ◑ Partial (stray comment removed) |

See [findings.md](findings.md) for full detail, reproduction, and suggested
direction on each item.

### Why #9–#11 were deferred

- **#9 / #10** — the test suite explicitly encodes the current design: keys are
  validated at token-creation time, not config time (`test_symmetric_algorithm_without_secret_key`),
  and `JWTHarmonyConfig()` must construct with no keys. Changing this is a
  deliberate API decision rather than a bug fix, so it is left for the maintainer.
- **#11** — changing `configure()` semantics risks the reset-based test isolation
  pattern; low value relative to that risk.

## Review-round follow-ups

Applying the fixes introduced/exposed a few secondary issues, each fixed and
covered by a regression test:

- **R1 — malformed Authorization *header* bypassed the #6 cookie fallback.** In
  headers+cookies mode, a malformed header *format* (`Basic ...`, bare `Bearer`,
  a proxy-injected scheme) raised `InvalidHeaderError` in `__init__` and returned
  422 without trying a valid auth cookie. `JWTHarmony.__init__` now defers a
  malformed header to cookie auth when cookies are enabled (headers-only still
  raises). ✅
- **R2 — the #6 fallback masked informative header errors.** The broadened
  `except JWTHarmonyException` made an expired/wrong-type/non-fresh header token
  fall through to a generic `Missing cookie` error when no cookie was present,
  breaking SPA silent-refresh (which keys off `TokenExpired`+`jti`). The three
  required-mode methods now share `_authenticate`, which surfaces the specific
  header error when the cookie location has no token to try. ✅
- **R3 — the #1 alg fix was incomplete under multi-algorithm configs.** If
  `decode_algorithms` lists an algorithm whose key is not provisioned (e.g.
  `['RS256','HS256']` with `secret_key=None` during key rotation), an attacker
  choosing that algorithm still reached a bare `RuntimeError` (500). Key selection
  for an accepted-but-non-primary algorithm now rejects with `JWTDecodeError`
  (422); a missing key for the *primary* configured algorithm remains a loud
  `RuntimeError` (genuine misconfiguration, as the existing tests require). ✅
- **R4 — cache + instance reuse.** The per-token verification cache would skip the
  denylist check if a `JWTHarmony` instance were reused across requests. Instances
  are request-scoped by design; the class docstring now states this contract
  explicitly. ◑ Documented.

## Highest-priority items

- **#1** is the most actionable: it turns a malformed/hostile request into a
  `500` with a stack trace instead of a clean `422`, and is trivially triggered.
- **#4** and **#5** are real functional bugs that silently break documented
  features (`audience`/`issuer` support, and integer subjects).
- **#2** and **#3** are defense-in-depth / ordering concerns rather than direct
  exploits under the default configuration, but matter for a security library.
