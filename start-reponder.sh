#!/bin/bash

## This script starts a standalone ACME challenge responder with a dummy challenge to test the responder.
## In integration tests, the responder should be started by the test runner with empty challenge map.

set -euk pipefail

make

erl -pa _build/default/lib/*/ebin -eval '
    {ok, _} = application:ensure_all_started(inets),
    p1_acme_challenge_responder:start([
        #{<<"token">> => <<"token1234567890">>, <<"key">> => <<"key1234567890">>}
    ]),
    io:format("curl http://localhost:5002/.well-known/acme-challenge/token1234567890~n", []).
'
