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

-module(acme_client_httpc).
-moduledoc """
HTTP client for ACME client to contact ACME servers.
""".

-export([start/0, init/1]).
-export([get/2, post/3, post/4]).

-export_type([opts/0]).

%% Request options
-type opts() :: #{
    timeout => timeout(),
    connect_timeout => timeout(),
    ssl => [ssl:tls_option()],
    ipfamily => inet | inet6 | inet6fb4
}.

-define(PROFILE, acme_client).

-define(DEFAULT_OPTS, #{
    timeout => timer:seconds(10),
    connect_timeout => timer:seconds(10),
    autoredirect => true,
    ssl => [{verify, verify_none}]
}).

start() ->
    inets:start(httpc, [{profile, ?PROFILE}]),
    ok.

init(Opts0) ->
    Opts = [{ipfamily, maps:get(ipfamily, Opts0, inet6fb4)}],
    httpc:set_options(Opts, ?PROFILE),
    ok.

-doc """
Send a GET request to the given URL.
Returns a reference to the request.
The caller should expect a message with the response in the format of
{http, {RequestId, Response}} where RequestId is the request id returned by the request and Response is the response from the server.
""".
-spec get(URL :: string(), Opts0 :: opts()) -> {ok, term()} | {error, term()}.
get(URL, Opts0) ->
    HttpOpts = http_opts(Opts0),
    ReqOpts = [{body_format, binary}, {sync, false}],
    httpc:request(get, {URL, []}, HttpOpts, ReqOpts, ?PROFILE).

-doc """
Send a POST request to the given URL.
Returns a reference to the request.
The caller should expect a message with the response in the format of
{http, {RequestId, Response}} where RequestId is the request id returned by the request and Response is the response from the server.
""".
-spec post(URL :: string(), Body :: binary(), Opts0 :: opts()) -> {ok, term()} | {error, term()}.
post(URL, Body, Opts0) ->
    HttpOpts = http_opts(Opts0),
    ReqOpts = [{body_format, binary}, {sync, false}],
    post(URL, Body, HttpOpts, ReqOpts).

post(URL, Body, HttpOpts, ReqOpts) ->
    ContentType = "application/jose+json",
    httpc:request(post, {URL, [], ContentType, Body}, HttpOpts, ReqOpts, ?PROFILE).

http_opts(Opts) ->
    maps:to_list(maps:without([ipfamily], maps:merge(?DEFAULT_OPTS, Opts))).
