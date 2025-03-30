# Erlang ACME Client (RFC8555)

An Erlang implementation of the Automatic Certificate Management Environment (ACME) protocol as specified in [RFC8555](https://tools.ietf.org/html/rfc8555).

This is a fork of [processone/p1_acme](https://github.com/processone/p1_acme) with significant refactoring. Special thanks to ProcessOne for the original implementation.

## Major Changes from Upstream

- Reimplemented using `gen_statem` for better state management
- Added tests
- Removed YAML dependency in favor of direct JSON field validation
- Removed `base64url` dependency in favor of `base64` with `urlsafe` mode and `padding => false`
- Erlang with OTP >= 27 support (so far no support for OTP < 27)
- Rebar3-only build system
- Added polling for challenge status for each domain

## Usage

```erlang
%% Start the application
application:ensure_all_started(acme_client).

%% Prepare the challenge responder function
ChallengeFun = fun(Challenges) ->
    %% Set up HTTP-01 challenge response
    %% The ACME server will make a GET request to:
    %% http://{Domain}/.well-known/acme-challenge/{Token}
    %% Expected response is the Key
    lists:foreach(
        fun(#{domain := Domain, token := Token, key := Key}) ->
            %% Note: The domain is a binary string without idna encoding
            ok = my_http_server:add_challenge(Domain, Token, Key)
        end,
        Challenges
    )
end.

%% Request configuration
Request = #{
    %% ACME directory URL (e.g., Let's Encrypt staging/production)
    dir_url => "https://acme-staging-v02.api.letsencrypt.org/directory",
    %% Domains to get certificate for
    %% Note: Not all ACME servers support wildcard certificates
    domains => [<<"example.com">>, <<"*.example.com">>],
    %% Optional contact information
    contact => ["mailto:admin@example.com"],
    %% Certificate key type (ec | rsa)
    cert_type => ec,
    %% Challenge type (currently only http-01 is tested)
    challenge_type => <<"http-01">>,
    %% Challenge responder function
    challenge_fn => ChallengeFun,
    %% Optional trusted CA certificates for issued certificate-chain validation
    ca_certs => [CACert],
    %% Optional existing account key (will generate new one if not provided)
    %% Note: The account key is used to identify the account at the ACME server
    %% It's a good practice to use the same account key for certificate renewal and revocation
    acc_key => AccountKey,
    %% Optional HTTP client options
    httpc_opts => #{
        ssl => [{verify, verify_none}],
        ipfamily => inet % default is inet6fb4
    }
}.

%% Request the certificate (timeout in milliseconds)
case acme_client:run(Request, 60000) of
    {ok, #{
        acc_key := AccKey,      %% Account private key
        cert_key := CertKey,    %% Certificate private key
        cert_chain := [Cert|_]  %% Certificate chain
    }} ->
        %% Success! Use the certificate
        ok;
    {error, Reason} ->
        %% Handle error
        error
end.
```

The client implements a state machine that handles:
- Directory discovery
- Account registration/verification
- Order creation
- Domain authorization
- Challenge setup and verification
- Certificate issuance
- Automatic retries for temporary failures
- Proper nonce management

For testing purposes, you can use the included ACME test server:
```erlang
Request = #{
    dir_url => "https://localhost:14000/dir",
    domains => [<<"local.host">>],
    challenge_type => <<"http-01">>,
    challenge_fn => fun acme_client_challenge_responder:handle_challenge/1,
    httpc_opts => #{ssl => [{verify, verify_none}]}
}.
```

## Features

- Full ACME protocol implementation (RFC8555)
- HTTP-01 challenge support
- Automatic account registration
- Certificate issuance and renewal
- Robust error handling and retries

## Requirements

- Erlang/OTP >= 27
- Rebar3

## Testing

The test suite includes an ACME test server and challenge responder:

1. Start the test environment:
   ```bash
   make test-env
   ```

2. Run the test suite:
   ```bash
   make ct
   ```

The ACME challenge responder runs in the container `acme-challenge-responder`.
For implementation details, see `src/acme_client_challenge_responder.erl`.

## Roadmap

- [ ] Implement certificate revocation
- [ ] Implement account reuse with `onlyReturnExisting`
- [ ] Add DNS challenge support

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.

## Credits

- Original implementation by [ProcessOne](https://github.com/processone)
- ACME protocol specification by IETF
