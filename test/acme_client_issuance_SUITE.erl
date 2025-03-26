-module(acme_client_issuance_SUITE).

-include_lib("stdlib/include/assert.hrl").

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
run(Request) ->
    acme_client_issuance:run(Request, 5000).
