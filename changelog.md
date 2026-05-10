# 2.0.4

- Bump the default HTTP `timeout` and `connect_timeout` for ACME
  requests from 10s to 30s. In practice the `finalize` step (CSR
  submission → CA mints and signs the certificate) can exceed the old
  10s budget on busy ACME servers — reproducibly observed against
  Let's Encrypt staging — even though `directory` was returning in
  well under a second on the same node. Callers saw a misleading
  `{http_retry, timeout}` from `s10_finalize` for what was a transient
  CA-side slowness. 30s gives more headroom without giving up
  fail-fast on genuinely stuck requests; callers can raise (or lower)
  the per-request budget by passing `httpc_opts => #{timeout => Ms,
  connect_timeout => Ms}` in the issuance request — `http_opts/1`
  merges the override on top of the new defaults. CT case
  `t_httpc_opts_override_timeout` documents the override path.
- Surface RFC 7807 problem details in the abort reason for
  unrecoverable 4xx/5xx responses. `handle_rsp_with_hdr/6`'s
  catch-all clause used to emit `{unknown_response, Code, Slogan}` no
  matter what — so a 403 from a rate-limited CA reached callers as
  bare `"Forbidden"` even when the body contained
  `urn:ietf:params:acme:error:rateLimited` and a human `detail`.
  The reason is now a map: `#{cause => unknown_response, http_code =>
  Code, http_slogan => Slogan, problem => ParsedJSON}` (the `problem`
  key is omitted when the body isn't `application/problem+json` /
  `application/json`). The existing `t_unrecoverable_http_retry_aborts`
  case asserts the new shape including the parsed error type.

# 2.0.3

- Fix `bad_return_from_state_function, ok` crash on the s11_certificate
  success path. After `reply_caller/2` (which returns `ok`), the case
  clause in `acme_client_issuance:s11_certificate(internal, {validate_ders, _}, _)`
  was evaluating to `ok`, but gen_statem state callbacks must return a
  state-transition tuple. The caller already had its `{ok, Result}` by
  the time the state machine died, so the existing CT cases passed —
  the only visible symptom was a crash report in the log right after
  every successful issuance. The terminal-success clause now returns
  `{stop, normal, Data}`, matching the abort path.
- Abort on non-`badNonce` `?HTTP_RETRY` events instead of dropping them.
  Previously only `?HTTP_RETRY("badNonce")` was matched in
  `handle_event/4`; any other retry signal — most commonly
  `?HTTP_RETRY({unknown_response, Code, Slogan})` from a 4xx/5xx the
  client doesn't have a recovery path for — fell through to the
  catch-all `unknown_event_ignored` clause, leaving the state machine
  stalled until `do_run/2`'s timeout fired. The new clause replies to
  the caller with `{error, #{cause => http_retry_unrecoverable, reason
  => Reason}}` and stops cleanly. Adds CT coverage in
  `t_unrecoverable_http_retry_aborts`.

# 2.0.2

- Require `contact` entries to be binaries. The README and typespec
  previously advertised `[string()]`, but Erlang's stdlib `json` module
  encodes a string (list of integers) as a JSON array of integers, so a
  request with `contact => ["mailto:admin@example.com"]` was rejected
  by ACME servers with `urn:ietf:params:acme:error:malformed` ("Error
  unmarshaling JSON"). `make_data/3` now validates the input and
  rejects non-binary entries with `{bad_contact, _}`. The typespec is
  tightened to `[binary()]` and the README example uses a binary.

# 2.0.1

- Fix `acme_client_lib:generate_csr/2` on OTP 28+: replace the removed
  `'AttributePKCS-10'` record with `'Attribute'` (same `type`/`values`
  fields, defined in `public_key.hrl`). OTP 27 and earlier shipped both
  names in `OTP-PUB-KEY.hrl`, so the pre-fix code worked there; OTP 28
  dropped `'AttributePKCS-10'`, so any consumer on OTP 28+ failed to
  compile.
- Add `t_generate_csr_ec` and `t_generate_csr_rsa` regression cases to
  `acme_client_lib_SUITE` so the rename does not silently come back.
- Add OTP 28 to the CI matrix so future PRs catch the same class of bug
  before merge.
- Send a `User-Agent` header on every ACME request (RFC 8555 §6.1).
  Recent Pebble builds reject requests without one with HTTP 400
  "All requests MUST include a User-Agent header", which broke every
  issuance suite run on `main`.
- Bump `jose` from 1.11.10 to 1.11.12. 1.11.11 fixed EC key conversion
  for OTP 28 (`jose_jwk_kty_ec:to_map/2` previously crashed on the new
  `'ECPrivateKey'` shape). Without the bump the issuance suite fails on
  OTP 28 while signing the JWS for the ACME account creation request.

# 2.0.0

Major refactoring.

- Added tests.
- Code format.
- No longer support rebar (now rebar3 only).
- No support for OTP < 27 (use the builtin `json` lib), can be made to support OTP < 27 later if needed.
- To minize build dependencies, deleted `yconf` for JSON decoding and validation.
  - Do not convert JSON field names into atoms.
  - Changed from schema framework validation to naive checking of JSON layout and field values.
- Support DNS-01 challenge.
