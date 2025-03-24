#!/bin/bash

set -euo pipefail

make

# NOTE: add local.host to /etc/hosts, loopback address
# 127.0.0.1 local.host

erl -pa _build/default/lib/*/ebin -eval '
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    inets:start(httpc, [{profile, p1_acme}]),
    p1_acme_challenge_responder:start([
        #{<<"token">> => <<"token1234567890">>, <<"key">> => <<"key1234567890">>}
    ]),
    R = p1_acme:issue("https://localhost:14000/dir",
                      ["local.host"],
                      [{debug_fun, fun(Fmt, Args) -> io:format(Fmt ++ "~n", Args) end},
                      {challenge_fun, fun p1_acme_challenge_responder:challenge_fun/1}
                      ]),
    io:format("~p~n", [R]),
    halt().
'
