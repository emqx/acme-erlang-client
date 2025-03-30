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

    % Generate CA key and cert
    CmdList = [
        "cd " ++ TmpDir,
        "openssl genrsa -out acc.key 2048",
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

run(Request) ->
    acme_client_issuance:run(Request, 5000).

%% Helper functions for running shell commands
cmd(Cmd) ->
    ct:pal("Running:\n  ~s", [Cmd]),
    Port = erlang:open_port({spawn, Cmd}, [binary, exit_status, stderr_to_stdout]),
    try
        ok = wait_cmd_down(Port)
    after
        close_port(Port)
    end.

wait_cmd_down(Port) ->
    receive
        {Port, {data, Bin}} ->
            ct:pal("~s", [Bin]),
            wait_cmd_down(Port);
        {Port, {exit_status, Status}} ->
            case Status of
                0 -> ok;
                _ -> {error, Status}
            end
    after 1_000 ->
        ct:pal("still waiting for command response..."),
        wait_cmd_down(Port)
    end.

close_port(Port) ->
    try
        _ = erlang:port_close(Port),
        ok
    catch
        error:badarg ->
            ok
    end.
