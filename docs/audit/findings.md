# Findings — detailed

All line references are against the tree audited on 2026-07-03.

---

## 1. Crafted `alg` header causes unhandled `RuntimeError` (HTTP 500)

**Severity:** High (robustness / availability)
**Location:** `base.py` `_verified_token` (lines 503-508) + `_get_decode_key` (465-483)

### What happens

`_verified_token` picks the decode key using the algorithm taken from the
**token header**, before PyJWT validates anything:

```python
unverified_headers = jwt.get_unverified_header(encoded_token)
algorithm_from_header = unverified_headers.get('alg')
final_algorithm = algorithm_from_header or self.config.algorithm
secret = self._get_decode_key(final_algorithm)   # <-- can raise RuntimeError
```

`_get_decode_key` raises a bare `RuntimeError` when the key for that algorithm
family is not configured:

```python
if algorithm in SYMMETRIC_ALGORITHMS:
    if not self.config.secret_key:
        raise RuntimeError('secret_key must be set to decode HS256 tokens')
```

The `try/except` in `_verified_token` only catches `jwt.ExpiredSignatureError`
and `jwt.InvalidTokenError`. A `RuntimeError` propagates out of
`get_raw_jwt()` → `jwt_required()` → the FastAPI dependency, and is **not** a
`JWTHarmonyException`, so any app-level exception handler registered for
`JWTHarmonyException` will not catch it. The client receives a `500 Internal
Server Error` with a stack trace.

### Trigger

Configure the server for an asymmetric algorithm (`RS256`, `public_key` +
`private_key`, no `secret_key`). An unauthenticated attacker sends any token
whose header advertises a symmetric algorithm:

```python
forged = jwt.encode({'sub': '1', 'type': 'access', 'fresh': False},
                    'anything', algorithm='HS256')
# -> Authorization: Bearer <forged>
```

### Verified output

```
A: RuntimeError: secret_key must be set to decode HS256 tokens
```

A correctly-behaving library should reject this as a `422`/`401`
`JWTDecodeError`, because the header algorithm is not in the allowed
`algorithms` list anyway.

### Direction

Select the decode key from the **configured/allowed** algorithm set, not from
the token header; and/or raise a `JWTDecodeError` (not `RuntimeError`) for a
key/algorithm mismatch so it flows through the normal error path. See also
finding #2 — both stem from trusting `alg` from the header.

---

## 2. Header-controlled algorithm selection for the decode key

**Severity:** Medium (security hardening)
**Location:** `base.py` `_verified_token` (499-520)

The list passed to `jwt.decode(algorithms=...)` is derived from config
(`decode_algorithms` or `[algorithm]`), which is correct and does block the
classic "alg confusion" forgery. **However**, the *key* handed to `jwt.decode`
is selected from the header-supplied `alg`:

```python
final_algorithm = algorithm_from_header or self.config.algorithm
secret = self._get_decode_key(final_algorithm)
```

Under the default single-family configuration this is safe (PyJWT rejects a
mismatched `alg`). It becomes risky if an operator configures
`decode_algorithms` to span **both** families (e.g. `['HS256', 'RS256']`) while
setting both `secret_key` and `public_key`. In that setup the attacker chooses
which key family verifies their token by setting the header, which is exactly
the configuration the library should refuse or at least warn about. Even where
not directly forgeable, relying on the header for key selection is fragile and
is the root cause of finding #1.

### Direction

Drive key selection from the resolved/validated algorithm, and reject
configurations that mix symmetric and asymmetric algorithms in
`decode_algorithms`.

---

## 3. Denylist callback runs on the unverified token

**Severity:** Medium (security / DoS surface)
**Location:** `base.py` `get_raw_jwt` (214-234)

The denylist callback is invoked using `unverified_token` — the payload decoded
with `verify_signature=False` — **before** the signature is checked:

```python
unverified_token = self.get_unverified_jwt(token)
...
if self.config.denylist_enabled:
    ...
    if denylist_callback(unverified_token):
        raise RevokedTokenError('Token has been revoked')
# signature is only verified afterwards
return self._verified_token(token)
```

Consequences:

- The callback (commonly a DB/Redis lookup keyed on `jti`) receives fully
  attacker-controlled claims. An unauthenticated attacker can drive arbitrary
  lookups with arbitrary `jti`/`type` values — a cheap amplification/DoS vector
  against the denylist store.
- Any logic inside the callback runs on data that may never pass signature
  verification.

Forgery is still prevented (verification runs afterwards), so this is an
ordering/abuse-surface issue rather than an auth bypass.

### Direction

Verify the signature first, then run the denylist check on the verified
payload. If the intent is to allow denylisting of expired tokens, decode with
signature verification but `verify_exp=False` for the denylist step, rather than
skipping the signature.

---

## 4. `user_claims` omits `aud` and `iss` from the reserved set

**Severity:** Medium (correctness)
**Location:** `base.py` `user_claims` (142) vs `_build_token_payload` (440)

The two reserved-claim sets disagree:

```python
# _build_token_payload (encode side)
reserved_claims = {'sub','iat','nbf','jti','exp','type','fresh','csrf','aud','iss'}

# user_claims (decode side)
user_data = {k: v for k, v in decoded_token.items()
             if k not in {'sub','iat','nbf','jti','exp','fresh','type','csrf'}}
#                                     ^ 'aud' and 'iss' are missing here
```

When `encode_issuer`/`audience` are used, the token carries `iss`/`aud`. On the
way back, `user_claims` passes those keys into the user model constructor:

- Pydantic model with default `extra='ignore'` → the values are dropped
  silently (data loss but no crash).
- Pydantic model with `extra='forbid'` → construction raises, is swallowed by
  the `except (TypeError, ValueError)`, and `user_claims` returns **`None`** —
  the authenticated user's claims vanish.

### Verified output (strict model + audience + issuer)

```
raw keys: ['aud','exp','fresh','iat','id','iss','jti','nbf','role','sub','type']
user_claims with strict model + aud/iss: None
```

### Direction

Use one shared reserved-claims constant for both encode and decode so `aud` and
`iss` are stripped consistently.

---

## 5. Falsy `subject` (`0`, `""`) is rejected

**Severity:** Medium (correctness)
**Location:** `base.py` `_validate_and_process_token_params` (50-53)

```python
final_subject = subject or claims_dict.get('id')
if final_subject is None:
    raise TypeError('missing 1 required positional argument: ...')
```

`subject or ...` treats any falsy value as absent. A legitimate integer user id
of `0`, or an empty-string subject, falls through to `claims_dict.get('id')`,
and if that is also absent the call raises "missing subject".

### Verified output

```
C: TypeError: missing 1 required positional argument: subject or user_claims with id field
```

(`create_access_token(subject=0)` rejected.)

### Direction

Test explicitly for `None` (`subject if subject is not None else claims_dict.get('id')`),
and only reject when the resolved subject is truly `None`.

---

## 6. Invalid header token short-circuits cookie fallback

**Severity:** Medium (correctness / UX)
**Location:** `fastapi_auth.py` `jwt_required` (48-68), and the identical pattern
in `jwt_refresh_token_required` (104-123) and `fresh_jwt_required` (137-156)

When both `headers` and `cookies` are enabled, the header branch only falls
through to cookies on `MissingTokenError`:

```python
if self.jwt_in_headers:
    if self.token:
        try:
            self._verify_jwt_in_request(self.token, 'access', 'headers')
            return
        except MissingTokenError:
            if not self.jwt_in_cookies:
                raise
            # continue to cookies
```

But when a header token is present, `_verify_jwt_in_request` never raises
`MissingTokenError` — it raises `TokenExpired` / `JWTDecodeError` /
`AccessTokenRequired` instead, which propagate immediately. So a malformed or
expired **header** token prevents a valid **cookie** token from ever being
tried. The `except MissingTokenError` here is effectively dead for the
token-present case. (Compare flask-jwt-extended, which tries all configured
locations before failing.)

### Direction

Decide the intended precedence explicitly. If any-location success is desired,
catch the broader auth-exception set and fall through to cookies, only
re-raising after all locations fail.

---

## 7. Token decoded 2–4× per request; repeated denylist callbacks

**Severity:** Medium (performance)
**Location:** `base.py` `_verify_jwt_in_request` (545-546), `user_claims` (137),
`get_jwt_subject` (246), `get_jti` (259); `fastapi_auth.py`
`_verify_and_get_jwt_in_cookies` (330-346)

`get_raw_jwt()` performs: `get_unverified_jwt` (a full `jwt.decode`) → denylist
callback → `_verified_token` (a second full `jwt.decode`). It is then called
repeatedly with no caching:

- `_verify_jwt_in_request` calls `get_raw_jwt()` once.
- The cookie path calls `_verify_jwt_in_request` **and then** `get_raw_jwt()`
  again to read the CSRF claim (`_verify_and_get_jwt_in_cookies`, lines
  331/333) — so the token is decoded ~4 times.
- Every later `auth.user_claims` / `get_jwt_subject()` / `get_jti()` access
  decodes again from scratch.

Because the denylist callback lives inside `get_raw_jwt`, each of those calls
**re-invokes the denylist lookup** (e.g. a Redis/DB round-trip) for the same
token within a single request.

### Direction

Memoize the verified payload on the instance after the first successful
verification (invalidated when `_token` changes), and run the denylist lookup at
most once per request.

---

## 8. No `samesite='none'` ⇒ `secure` consistency validation

**Severity:** Low (config correctness)
**Location:** `config.py` (105-106)

`cookie_secure` defaults to `False` and `cookie_samesite` accepts `'none'`, but
nothing enforces the browser rule that `SameSite=None` requires `Secure`.
Cookies configured this way are silently rejected by modern browsers, producing
hard-to-diagnose "auth randomly doesn't work" reports.

### Direction

Add a model validator: if `cookie_samesite == 'none'` then `cookie_secure` must
be `True`.

---

## 9. Required keys are not validated at `configure()` time

**Severity:** Low (ergonomics)
**Location:** `base.py` `configure` (149-171); key checks in `_get_secret_key`
(455-463) / `_get_decode_key` (465-483)

`JWTHarmonyConfig` allows `secret_key=None` and `private_key=None`. The
requirement (secret for HS*, private/public for asymmetric) is only enforced
when a token is first created or decoded — i.e. at request time in production,
not at startup. A misconfigured deployment boots "successfully" and fails on the
first authenticated request.

### Direction

Validate key presence against `algorithm`/`decode_algorithms` in a config model
validator (or in `configure`) so misconfiguration fails fast at startup.

---

## 10. Global `str_min_length=1` blocks legitimate empty-string config

**Severity:** Low (config)
**Location:** `config.py` `model_config` (120)

`model_config = ConfigDict(validate_default=False, str_min_length=1,
str_strip_whitespace=True)` applies `min_length=1` to **every** string field.
That prevents legitimate empty values such as `header_type=''` (used by setups
that send the raw token with no `Bearer` prefix) and any intentionally-empty
override. The constraint is broader than intended.

### Direction

Apply length/strip constraints per-field where they actually make sense rather
than globally.

---

## 11. `configure(..., config=None)` silently keeps stale/`None` config

**Severity:** Low (API footgun)
**Location:** `base.py` `configure` (165-169)

```python
if config is not None:
    cls._config = JWTHarmonyConfig(...) or config
```

Calling `configure(UserModel)` with no `config` leaves `cls._config` untouched.
On a fresh process that means it stays `None`, and the failure only surfaces
later as `RuntimeError('JWTHarmony is not configured')` from `__init__`. Because
config is class-level global state, a second `configure()` call in the same
process also silently mutates config for everything already using it (relevant
in tests and multi-app processes — see #13).

### Direction

Either require `config` explicitly, or default to `JWTHarmonyConfig()` when
omitted, so the state after `configure()` is always well-defined.

---

## 12. Cookies are unset without `samesite`/`secure` attributes

**Severity:** Low (cookies)
**Location:** `fastapi_auth.py` `unset_access_cookies` (249-253),
`unset_refresh_cookies` (267-272)

`delete_cookie` is called with only `path`/`domain`. The set side uses `secure`,
`httponly`, and `samesite`. Some browsers require the delete cookie's attributes
(notably `SameSite`/`Secure`) to match the original for the deletion to take
effect, so logout can leave the cookie in place in those browsers.

### Direction

Pass the same `samesite`/`secure`/`domain`/`path` attributes when deleting as
when setting.

---

## 13. Minor issues / nits

**Severity:** Info

- **Global singleton state.** `_config`, `_user_model_class`, and
  `_token_in_denylist_callback` are class attributes on `JWTHarmonyBase`.
  Two FastAPI apps in one process cannot have independent JWT configs, and test
  isolation depends on re-`configure()`-ing between cases. Worth documenting as
  a deliberate constraint.
- **Duplicated CSRF/verify logic.** `fastapi_auth._verify_and_get_jwt_in_cookies`
  and `websocket_auth._verify_jwt_in_cookies` implement the same CSRF
  double-submit flow twice; they can drift (e.g. only the WS optional path has
  the `or 'access_token_cookie'` fallback at `websocket_auth.py:193`).
- **Dead/unused helper.** `utils.get_int_from_datetime` (utils.py:21) is not used
  anywhere in the package and is not exported.
- **Typing of denylist callback.** Declared
  `Callable[[dict[str, Union[str, int, bool]]], bool]`, but the dict handed in
  (raw PyJWT claims) can contain other JSON types; the annotation is narrower
  than reality.
- **`get_unverified_jwt` return type.** Annotated
  `dict[str, Union[str, int, bool]]` while `jwt.decode` may return nested
  structures; annotation is optimistic.
- **`fastapi_auth.py:432`** trailing `# Import required types` comment refers to
  imports that are not there — stray leftover.
