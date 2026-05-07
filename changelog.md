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
