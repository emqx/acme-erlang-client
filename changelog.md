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
