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
- Support `file:///path/to/file.pem` for account key and CA certificates
- Always generate certificate private key, do not allow to provide it
- Support encrypted account key

## Usage

### HTTP-01 Challenge

```erlang
%% Start the application
application:ensure_all_started(acme_client).

%% Prepare the HTTP-01 challenge responder function
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
    %% Challenge type: "http-01" or "dns-01"
    challenge_type => <<"http-01">>,
    %% Challenge responder function
    challenge_fn => ChallengeFun,
    %% Optional trusted CA certificates for issued certificate-chain validation
    ca_certs => [CACert],
    %% Optional existing account key (will generate new one if not provided)
    %% Note: The account key is used to identify the account at the ACME server
    %% It's a good practice to use the same account key for certificate renewal and revocation
    acc_key => AccountKey,
    %% Optional account key password
    acc_key_pass => undefined, % | fun() -> AccountKeyPassword end,
    %% Optional HTTP client options
    httpc_opts => #{
        ssl => [{verify, verify_none}],
        ipfamily => inet % default is inet6fb4
    },
    %% Optional output directory for certificate files
    %% When provided, the keys and certificates will be saved to the directory
    %% and the returned map will contain only the file names
    %% for example:
    %% #{ acc_key => "/path/to/output/acme-client-account-key.pem",
    %%    cert_key => "/path/to/output/key.pem",
    %%    cert_chain => "/path/to/output/cert.pem"
    %%  }
    output_dir => "/path/to/output"
}.

%% Request the certificate (timeout in milliseconds)
case acme_client:run(Request, 60000) of
    {ok, #{
        acc_key := AccKey,      %% Account private key or PEM file path
        cert_key := CertKey,    %% Certificate private key or PEM file path
        cert_chain := [Cert|_]  %% Certificate chain or PEM file path
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

### DNS-01 Challenge

DNS-01 challenges are required for wildcard certificates and are useful when HTTP-01 is not available.

```erlang
%% DNS-01 challenge responder function
DnsChallengeFun = fun(Challenges) ->
    %% Set up DNS TXT records for DNS-01 challenge
    %% The ACME server will query:
    %% _acme-challenge.{Domain} TXT {RecordValue}
    lists:foreach(
        fun(#{domain := Domain, record_name := RecordName, record_value := RecordValue}) ->
            %% Create DNS TXT record using your DNS provider's API
            %% Example: AWS Route53, Cloudflare, Google Cloud DNS, etc.
            ok = my_dns_provider:add_txt_record(RecordName, RecordValue)
        end,
        Challenges
    )
end.

Request = #{
    dir_url => "https://acme-staging-v02.api.letsencrypt.org/directory",
    domains => [<<"example.com">>, <<"*.example.com">>],  % Wildcard requires DNS-01
    challenge_type => <<"dns-01">>,
    challenge_fn => DnsChallengeFun,
    %% ... other options
}.
```

**Note**: For DNS-01 challenges, the `challenge_fn` callback receives:
- `domain`: The domain name (e.g., `<<"example.com">>`)
- `record_name`: The TXT record name (e.g., `<<"_acme-challenge.example.com">>`)
- `record_value`: The base64url-encoded SHA-256 digest of the key authorization
- `token`: The challenge token (for reference)

You can use `open_port` to execute command-line tools (AWS CLI, Cloudflare API, etc.) or integrate directly with your DNS provider's API.

**Example: AWS Route53 using AWS CLI**:

```erlang
%% DNS-01 challenge responder using AWS Route53 CLI script
%% See examples/aws_route53_dns_challenge.sh for the bash script implementation
Route53ChallengeFun = fun(Challenges) ->
    ScriptPath = os:getenv("AWS_ROUTE53_SCRIPT", "examples/aws_route53_dns_challenge.sh"),
    lists:foreach(
        fun(#{record_name := RecordName, record_value := RecordValue}) ->
            %% Execute bash script via open_port
            Cmd = io_lib:format(
                "~s ~s ~s",
                [ScriptPath, RecordName, RecordValue]
            ),
            Port = open_port({spawn, lists:flatten(Cmd)}, [exit_status, stderr_to_stdout]),

            receive
                {Port, {exit_status, 0}} ->
                    ok;
                {Port, {exit_status, Status}} ->
                    error({aws_script_failed, Status});
                {Port, {data, Data}} ->
                    %% Log script output
                    io:format("AWS script output: ~s~n", [Data]),
                    receive
                        {Port, {exit_status, 0}} -> ok;
                        {Port, {exit_status, Status}} -> error({aws_script_failed, Status})
                    end
            after 30000 ->
                erlang:port_close(Port),
                error(timeout)
            end
        end,
        Challenges
    )
end.
```

**Note**:
- The bash script `examples/aws_route53_dns_challenge.sh` handles all AWS Route53 logic
- Make sure AWS CLI is installed and configured with appropriate credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `~/.aws/credentials`)
- You can optionally set `AWS_ROUTE53_SCRIPT` environment variable to specify a custom script path
- Optionally provide hosted zone ID as third argument to avoid lookup: `ScriptPath RecordName RecordValue ZoneID`

## Features

- Full ACME protocol implementation (RFC8555)
- HTTP-01 challenge support
- DNS-01 challenge support (required for wildcard certificates)
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
For implementation details, see `test/acme_client_challenge_responder.erl`.

## Roadmap

- [ ] Implement certificate revocation
- [ ] Implement account reuse with `onlyReturnExisting`
- [x] Add DNS challenge support
- [ ] Add support for private key password

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.

## Credits

- Original implementation by [ProcessOne](https://github.com/processone)
- ACME protocol specification by IETF
