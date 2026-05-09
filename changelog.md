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
