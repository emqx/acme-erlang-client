%%%-------------------------------------------------------------------
%%% @copyright (C) 2025 EMQ Technologies Co., Ltd. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------
-module(acme_client_issuance_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("public_key/include/public_key.hrl").
-include_lib("public_key/include/OTP-PUB-KEY.hrl").

%% Test server callbacks
-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-compile([nowarn_export_all]).
-compile(export_all).

challenge_fn([]) ->
    ok;
challenge_fn([#{token := Token, key := Key} | Rest]) ->
    WellKnown = "http://localhost:5002/.well-known/acme-challenge/",
    URL = WellKnown ++ binary_to_list(Token) ++ "/" ++ binary_to_list(Key),
    {ok, _} = acme_client_httpc:post(URL, <<>>, [], [{sync, true}, {body_format, binary}]),
    challenge_fn(Rest).

dns_challenge_fn([]) ->
    ok;
dns_challenge_fn([
    #{domain := Domain, record_name := RecordName, record_value := RecordValue} | Rest
]) ->
    %% Use dns-server hostname when running in Docker, localhost when running on host
    DnsServerHost = os:getenv("ACME_DNS_SERVER_HOST", "localhost"),
    DnsServerURL = "http://" ++ DnsServerHost ++ ":8053/set-challenge",
    ct:pal("Setting DNS challenge: ~s -> ~s", [RecordName, RecordValue]),
    case set_dns_challenge(DnsServerURL, Domain, RecordName, RecordValue) of
        ok ->
            dns_challenge_fn(Rest);
        Error ->
            ct:pal("Failed to set DNS challenge: ~p", [Error]),
            Error
    end.

set_dns_challenge(URL, Domain, RecordName, RecordValue) ->
    %% Use httpc to make HTTP POST request
    Body = #{
        <<"domain">> => Domain,
        <<"record_name">> => RecordName,
        <<"record_value">> => RecordValue
    },
    JSONBody = json:encode(Body),
    Headers = [{"Content-Type", "application/json"}],
    HttpOpts = [{timeout, 5000}, {connect_timeout, 5000}],
    case httpc:request(post, {URL, Headers, "application/json", JSONBody}, HttpOpts, []) of
        {ok, {{_, 200, _}, _, _}} ->
            ok;
        {ok, {{_, Code, _}, _, ResponseBody}} ->
            ct:pal("DNS challenge setup failed with HTTP status ~p: ~s", [Code, ResponseBody]),
            {error, {http_error, Code}};
        {error, Reason} ->
            ct:pal("DNS challenge setup failed: ~p", [Reason]),
            {error, Reason}
    end.

all() ->
    [
        F
     || {F, 1} <- ?MODULE:module_info(exports),
        lists:prefix("t_", atom_to_list(F))
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(inets),
    ok = application:stop(ssl),
    ok.

init_per_testcase(TestCase, Config) ->
    logger:set_primary_config(level, info),
    ?MODULE:TestCase({init, Config}).

end_per_testcase(TestCase, Config) ->
    logger:set_primary_config(level, warning),
    ?MODULE:TestCase({'end', Config}),
    ok.

%% Test cases

t_invalid_args({init, Config}) ->
    Config;
t_invalid_args({'end', _Config}) ->
    ok;
t_invalid_args(_Config) ->
    ?assertEqual(
        {error, empty_domains},
        run(
            #{
                dir_url => <<"https://localhost:14000/dir">>,
                domains => []
            }
        )
    ),
    ?assertEqual(
        {error, bad_url},
        run(
            #{
                %% not string, not binary
                dir_url => {localhost},
                domains => ["local.host"]
            }
        )
    ),
    ok.

t_one_domain({init, Config}) ->
    Config;
t_one_domain({'end', _Config}) ->
    ok;
t_one_domain(_Config) ->
    R = run(
        #{
            dir_url => "https://localhost:14000/dir",
            domains => ["a.local.net"],
            challenge_fn => fun challenge_fn/1,
            poll_interval => 100
        }
    ),
    ?assertMatch({ok, _}, R),
    ok.

t_two_domains({init, Config}) ->
    Config;
t_two_domains({'end', _Config}) ->
    ok;
t_two_domains(_Config) ->
    R = run(
        #{
            dir_url => "https://localhost:14000/dir",
            key_type => rsa,
            domains => ["a.local.net", "b.local.net"],
            challenge_fn => fun challenge_fn/1,
            poll_interval => 100,
            httpc_opts => #{ipfamily => inet, ssl => [{verify, verify_none}]}
        }
    ),
    ?assertMatch({ok, _}, R),
    ok.

t_idna_domains({init, Config}) ->
    Config;
t_idna_domains({'end', _Config}) ->
    ok;
t_idna_domains(_Config) ->
    R = run(
        #{
            dir_url => "https://localhost:14000/dir",
            domains => ["甲.local.net", "乙.local.net"],
            challenge_fn => fun challenge_fn/1,
            poll_interval => 100
        }
    ),
    ?assertMatch({ok, _}, R),
    ok.

t_untrusted_ca({init, Config}) ->
    % Create a temporary directory for OpenSSL files
    TmpDir = string:trim(os:cmd("mktemp -d")),
    % Generate CA key and cert using OpenSSL
    CmdList = [
        "cd " ++ TmpDir,
        "openssl genrsa -out ca.key 2048",
        "openssl req -x509 -new -nodes -key ca.key -sha256 -days 365"
        " -out ca.pem -subj '/CN=Untrusted Test CA'"
    ],
    Cmd = string:join(CmdList, " && "),
    ok = cmd("/bin/sh -c '" ++ Cmd ++ "'"),
    % Read the generated CA cert
    {ok, PemBin} = file:read_file(TmpDir ++ "/ca.pem"),
    [{'Certificate', Der, _}] = public_key:pem_decode(PemBin),
    CACert = public_key:pkix_decode_cert(Der, otp),
    [{tmp_dir, TmpDir}, {ca_cert, CACert} | Config];
t_untrusted_ca({'end', Config}) ->
    TmpDir1 = proplists:get_value(tmp_dir, Config),
    ok = cmd("rm -rf " ++ TmpDir1),
    ok;
t_untrusted_ca(Config) ->
    CACert = proplists:get_value(ca_cert, Config),
    R = run(
        #{
            dir_url => "https://localhost:14000/dir",
            domains => ["a.local.net"],
            challenge_fn => fun challenge_fn/1,
            poll_interval => 100,
            cert_type => rsa,
            ca_certs => [CACert],
            httpc_opts => #{ssl => [{verify, verify_none}]}
        }
    ),
    ?assertMatch({error, #{cause := unknown_ca}}, R),
    ok.

t_trusted_ca({init, Config}) ->
    % Get Pebble's root certificate
    {ok, {{_, 200, _}, _, PEM}} = httpc:request(
        get,
        {
            "https://localhost:15000/roots/0",
            []
        },
        [{ssl, [{verify, verify_none}]}],
        [{body_format, binary}]
    ),
    [{'Certificate', RootDER, _}] = public_key:pem_decode(PEM),
    RootCert = public_key:pkix_decode_cert(RootDER, otp),

    % Detect root CA key type
    TBSCert = RootCert#'OTPCertificate'.tbsCertificate,
    PubKeyInfo = TBSCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    KeyType =
        case PubKeyInfo#'OTPSubjectPublicKeyInfo'.algorithm of
            #'PublicKeyAlgorithm'{algorithm = ?'rsaEncryption'} -> rsa;
            #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey'} -> ec
        end,
    % Choose opposite key type for our certificate
    OppositeType =
        case KeyType of
            rsa -> ec;
            ec -> rsa
        end,
    [{ca_cert, RootCert}, {ca_type, OppositeType} | Config];
t_trusted_ca({'end', _Config}) ->
    ok;
t_trusted_ca(Config) ->
    CACert = proplists:get_value(ca_cert, Config),
    CAType = proplists:get_value(ca_type, Config),
    R1 = run(
        #{
            dir_url => "https://localhost:14000/dir",
            domains => ["a.local.net"],
            challenge_fn => fun challenge_fn/1,
            poll_interval => 100,
            cert_type => CAType,
            ca_certs => [CACert],
            httpc_opts => #{ssl => [{verify, verify_none}]}
        }
    ),
    ?assertMatch({ok, _}, R1),
    ok.

t_file_input({init, Config}) ->
    % Create a temporary directory
    TmpDir = string:trim(os:cmd("mktemp -d")),

    % Generate CA key and cert with explicit format
    CmdList = [
        "cd " ++ TmpDir,
        % Generate account key in PKCS#8 format
        "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out acc.key",
        % Generate CA key and cert
        "openssl genrsa -out ca.key 2048",
        "openssl req -x509 -new -nodes -key ca.key -sha256 -days 365"
        " -out ca.pem -subj '/CN=Test CA'"
    ],
    Cmd = string:join(CmdList, " && "),
    ok = cmd("/bin/sh -c '" ++ Cmd ++ "'"),

    [{tmp_dir, TmpDir} | Config];
t_file_input({'end', Config}) ->
    TmpDir = proplists:get_value(tmp_dir, Config),
    ok = cmd("rm -rf " ++ TmpDir);
t_file_input(Config) ->
    TmpDir = proplists:get_value(tmp_dir, Config),
    R = run(
        #{
            dir_url => "https://localhost:14000/dir",
            domains => ["a.local.net"],
            challenge_fn => fun challenge_fn/1,
            poll_interval => 100,
            cert_type => ec,
            ca_certs => [list_to_binary("file://" ++ TmpDir ++ "/ca.pem")],
            acc_key => list_to_binary("file://" ++ TmpDir ++ "/acc.key"),
            httpc_opts => #{ssl => [{verify, verify_none}]}
        }
    ),
    ?assertMatch({error, #{cause := unknown_ca}}, R),

    % Test with non-existent file
    BadPath = "nonexistent.pem",
    R2 = run(
        #{
            dir_url => "https://localhost:14000/dir",
            domains => ["a.local.net"],
            ca_certs => ["file://" ++ BadPath]
        }
    ),
    ?assertMatch({error, #{cause := bad_ca_cert_file, path := BadPath}}, R2),
    ok.

t_encrypted_acc_key({init, Config}) ->
    % Create a temporary directory
    TmpDir = string:trim(os:cmd("mktemp -d")),

    % Generate encrypted account key with password "secret"
    CmdList = [
        "cd " ++ TmpDir,
        % Generate account key and encrypt it with password "secret"
        "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out acc.key.plain",
        "openssl pkcs8 -topk8 -in acc.key.plain -out acc.key -passout pass:secret"
    ],
    Cmd = string:join(CmdList, " && "),
    ok = cmd("/bin/sh -c '" ++ Cmd ++ "'"),

    [{tmp_dir, TmpDir} | Config];
t_encrypted_acc_key({'end', Config}) ->
    TmpDir = proplists:get_value(tmp_dir, Config),
    ok = cmd("rm -rf " ++ TmpDir);
t_encrypted_acc_key(Config) ->
    TmpDir = proplists:get_value(tmp_dir, Config),
    AccKeyPath = list_to_binary("file://" ++ TmpDir ++ "/acc.key"),

    % Test with correct password
    R1 = run(#{
        dir_url => "https://localhost:14000/dir",
        domains => ["a.local.net"],
        challenge_fn => fun challenge_fn/1,
        poll_interval => 100,
        cert_type => ec,
        acc_key => AccKeyPath,
        acc_key_pass => fun() -> "secret" end,
        httpc_opts => #{ssl => [{verify, verify_none}]}
    }),
    ?assertMatch({ok, _}, R1),

    % Test with wrong password
    R2 = run(#{
        dir_url => "https://localhost:14000/dir",
        domains => ["a.local.net"],
        challenge_fn => fun challenge_fn/1,
        poll_interval => 100,
        cert_type => ec,
        acc_key => AccKeyPath,
        acc_key_pass => fun() -> "wrong" end,
        httpc_opts => #{ssl => [{verify, verify_none}]}
    }),
    ?assertMatch({error, #{cause := bad_priv_key_file}}, R2),
    ok.

t_output_dir({init, Config}) ->
    TmpDir = string:trim(os:cmd("mktemp -d")),
    [{tmp_dir, TmpDir} | Config];
t_output_dir({'end', Config}) ->
    TmpDir = proplists:get_value(tmp_dir, Config),
    ok = cmd("rm -rf " ++ TmpDir);
t_output_dir(Config) ->
    OutputDir = proplists:get_value(tmp_dir, Config),
    Req = #{
        dir_url => "https://localhost:14000/dir",
        domains => ["a.local.net"],
        challenge_fn => fun challenge_fn/1,
        poll_interval => 100,
        cert_type => ec,
        output_dir => OutputDir,
        httpc_opts => #{ssl => [{verify, verify_none}]}
    },
    {ok, #{
        acc_key := AccKeyPath,
        cert_key := KeyPath,
        cert_chain := CertPath
    }} = run(Req),
    ?assertEqual(filename:join(OutputDir, "acme-client-account-key.pem"), AccKeyPath),
    NewAccKeyPath = filename:join(OutputDir, "acc-key.pem"),
    ok = file:rename(AccKeyPath, NewAccKeyPath),
    {ok, AccKey} = file:read_file(NewAccKeyPath),
    {ok, Key} = file:read_file(KeyPath),
    {ok, Cert} = file:read_file(CertPath),
    % Run again with same account key path
    {ok, #{
        acc_key := AccKeyPath2,
        cert_key := KeyPath2,
        cert_chain := CertPath2
    }} = run(Req#{acc_key => "file://" ++ NewAccKeyPath}),
    % Account key should be unchanged
    ?assertEqual("file://" ++ NewAccKeyPath, AccKeyPath2),
    {ok, AccKey2} = file:read_file(NewAccKeyPath),
    ?assertEqual(AccKey, AccKey2),
    % Key and cert should be new
    {ok, Key2} = file:read_file(KeyPath2),
    {ok, Cert2} = file:read_file(CertPath2),
    ?assertNotEqual(Key, Key2),
    ?assertNotEqual(Cert, Cert2),
    ok.

run(Request) ->
    acme_client_issuance:run(Request, 5000).

t_dns01_one_domain({init, Config}) ->
    Config;
t_dns01_one_domain({'end', _Config}) ->
    ok;
t_dns01_one_domain(_Config) ->
    %% Use pebble hostname when running in Docker, localhost when running on host
    DirURL =
        case os:getenv("PEBBLE_HOST") of
            false -> "https://localhost:14000/dir";
            Host -> "https://" ++ Host ++ ":14000/dir"
        end,
    R = run(
        #{
            dir_url => DirURL,
            domains => ["a.local.net"],
            challenge_type => <<"dns-01">>,
            challenge_fn => fun dns_challenge_fn/1,
            poll_interval => 100,
            httpc_opts => #{ssl => [{verify, verify_none}]}
        }
    ),
    ?assertMatch(
        {ok, #{
            acc_key := _AccKey,
            cert_key := _CertKey,
            cert_chain := [_Cert | _]
        }},
        R
    ),
    {ok, #{cert_chain := CertChain}} = R,
    %% Verify certificate chain is not empty
    ?assert(length(CertChain) > 0),
    %% Verify first certificate is a valid certificate record
    [FirstCert | _] = CertChain,
    ?assertMatch(#'OTPCertificate'{}, FirstCert),
    ok.

cmd(Cmd) ->
    acme_client_test_lib:cmd(Cmd).
