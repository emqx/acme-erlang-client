%%%-------------------------------------------------------------------
%%% @copyright (C) 2002-2024 ProcessOne, SARL. All Rights Reserved.
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
-module(acme_client_issuance).
-moduledoc """
ACME certificate issuance implementation using gen_statem behavior.

The client maintains state through the ACME protocol flow using gen_statem and
handles retries, timeouts and error conditions appropriately.

The client is implemented as a state machine with the following states:

- `s1_directory`: Directory discovery.
- `s2_nonce`: Obtaining initial nonce, or retry after badNonce error.
  Subsequent states may jump to this state for a new nonce,
  then it should jump back after the nonce is updated.
- `s3_account`: Account registration/verification.
- `s4_order`: Certificate order creation.
- `s5_auth`: Domain authorization.
- `s6_responder`: Challenge responder.
- `s7_challenge`: Challenge completion.
- `s8_poll_challenge`: Poll for challenge validation status.
  Polls each challenge until it becomes valid or invalid.
- `s9_poll_order`: Order status polling.
  Usually transition from `s8_poll_challenge`, goes to `s10_finalize` or `s11_certificate` depending on the order status:
  `ready` -> `s10_finalize`,
  `valid` -> `s11_certificate`
- `s10_finalize`: Submit CSR once challenges are all validated.
  Sends the CSR to the CA then jump back to `s9_poll_order` to wait for the certificate.
- `s11_certificate`: Retrieve the issued certificate.
""".

-behaviour(gen_statem).

-export([
    init/1,
    callback_mode/0,
    terminate/3,
    code_change/4
]).

%% State callbacks
-export([
    s1_directory/3,
    s2_nonce/3,
    s3_account/3,
    s4_order/3,
    s5_auth/3,
    s6_responder/3,
    s7_challenge/3,
    s8_poll_challenge/3,
    s9_poll_order/3,
    s10_finalize/3,
    s11_certificate/3
]).

-export([run/2]).

-include_lib("public_key/include/public_key.hrl").

-type dir_url() :: string().
-type cert_type() :: ec | rsa.
-type priv_key() :: public_key:private_key().
-type cert() :: #'OTPCertificate'{}.
-type domain() :: binary().
-type httpc_opts() :: acme_client_httpc:opts().
-type challenge() :: #{
    domain => domain(),
    token => binary(),
    key => binary()
}.
-type challenge_fn() :: fun(([challenge()]) -> ok).
-type request() :: #{
    dir_url := dir_url(),
    domains := [domain()],
    contact => [string()],
    cert_type => cert_type(),
    ca_certs => [cert()],
    challenge_type => binary(),
    challenge_fn => challenge_fn(),
    acc_key => fun(() -> priv_key()),
    httpc_opts => httpc_opts(),
    poll_interval => timeout()
}.
-type result() :: #{
    %% Account key, provided by the caller, or generated,
    %% keep it for future revocation and/or renewal
    acc_key := priv_key(),
    %% Generated private key for the certificate
    cert_key := priv_key(),
    %% The certificate chain issued by the CA
    cert_chain := [cert()]
}.
-define(IS_2XX_3XX(Code), Code >= 200 andalso Code < 400).
-define(HTTP_OK(Code, Slogan, Hdrs, JSON), {http_ok, Code, Slogan, Hdrs, JSON}).
-define(ABORT(Reason), {abort, Reason}).
-define(HTTP_RETRY(Reason), {http_retry, Reason}).

-define(INTERNAL(Content), {next_event, internal, Content}).
-define(NEXT_ABORT(Data, Reason), {keep_state, Data, ?INTERNAL(?ABORT(Reason))}).
-define(NEXT_HTTP_OK(Data, Code, Slogan, Hdrs, JSON),
    {keep_state, Data, ?INTERNAL(?HTTP_OK(Code, Slogan, Hdrs, JSON))}
).
-define(NEXT_HTTP_RETRY(Data, Reason),
    {keep_state, Data, ?INTERNAL(?HTTP_RETRY(Reason))}
).
-define(DEFAULT_POLL_INTERVAL, timer:seconds(1)).

-define(LOG(Level, Msg, Data),
    logger:log(
        Level,
        (begin
            Data
        end)#{
            msg => Msg
        },
        #{module => ?MODULE}
    )
).

ensure_priv_key(CertType, undefined) ->
    Key = acme_client_lib:generate_key(CertType),
    fun() -> Key end;
ensure_priv_key(_CertType, Key) ->
    %% TODO: load from pem if Key is "file://{PATH}"
    fun() -> Key end.

check_cert_type(CertType) ->
    CertType =:= ec orelse CertType =:= rsa orelse
        erlang:error({bad_cert_type, CertType}).

-doc """
Starts the ACME issuance process.
""".
-spec run(request(), timeout()) -> {ok, result()} | {error, term()}.
run(#{dir_url := DirURL, domains := Domains} = Request, Timeout) ->
    {ok, _} = application:ensure_all_started(acme_client),
    ok = acme_client_httpc:init(maps:get(httpc_opts, Request, #{})),
    case make_data(DirURL, Domains, Request) of
        {ok, Data} ->
            do_run(Data, Timeout);
        {error, Reason} ->
            {error, Reason}
    end.

do_run(Data, Timeout) ->
    {ok, {Pid, Ref}} = gen_statem:start_monitor(?MODULE, Data, []),
    _ = erlang:send(Pid, {start, Ref}),
    Return =
        receive
            {Ref, Result} ->
                Result;
            {'DOWN', Ref, process, Pid, Reason} ->
                {error, Reason}
        after Timeout ->
            try
                gen_statem:stop(Pid)
            catch
                _:_ ->
                    ok
            end,
            {error, timeout}
        end,
    _ = erlang:demonitor(Ref, [flush]),
    %% avoid DOWN message contamination for the caller process
    receive
        {'DOWN', Ref, process, Pid, _Reason} ->
            Return
    after 0 ->
        Return
    end.

make_data(DirURL, Domains, Request) ->
    try
        CertType = maps:get(cert_type, Request, ec),
        %% always generate a new cert key
        CertKey = acme_client_lib:generate_key(CertType),
        true = check_cert_type(CertType),
        URL = check_url(DirURL),
        IdnaDomains = check_domains(Domains),
        Data = #{
            caller_pid => self(),
            dir_url => URL,
            domains => IdnaDomains,
            contact => maps:get(contact, Request, []),
            cert_type => maps:get(cert_type, Request, ec),
            ca_certs => maps:get(ca_certs, Request, []),
            challenge_type => maps:get(challenge_type, Request, <<"http-01">>),
            acc_key => ensure_priv_key(CertType, maps:get(acc_key, Request, undefined)),
            cert_key => fun() -> CertKey end,
            acc_url => undefined,
            challenge_fn => maps:get(challenge_fn, Request),
            poll_interval => maps:get(poll_interval, Request, ?DEFAULT_POLL_INTERVAL)
        },
        {ok, Data}
    catch
        throw:Reason ->
            {error, Reason}
    end.

callback_mode() -> [state_functions, state_enter].

init(#{caller_pid := Caller} = Data) ->
    _ = erlang:monitor(process, Caller),
    {ok, s1_directory, Data}.

terminate(_Reason, _State, _Data) ->
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%% State callbacks

-doc """
Directory discovery state.
""".
s1_directory(enter, _PrevState, _Data) ->
    keep_state_and_data;
s1_directory(info, {start, Ref}, Data) ->
    %% kickoff by the caller
    ?LOG(info, "directory_discovery_start", #{}),
    DirURL = maps:get(dir_url, Data),
    Data1 = Data#{caller_ref => Ref},
    http_get(DirURL, Data1);
s1_directory(internal, ?HTTP_OK(_Code, _Slogan, _Hdrs, JSON), Data) ->
    %% continue handling the directory response
    case JSON of
        #{
            <<"newNonce">> := NonceURL,
            <<"newAccount">> := AccURL,
            <<"newOrder">> := OrderURL,
            <<"revokeCert">> := RevokeURL
        } ->
            NoDelay = 0,
            Action = {timeout, NoDelay, {start, NoDelay}},
            Data1 = Data#{
                new_nonce_url => str(NonceURL),
                new_acc_url => str(AccURL),
                new_order_url => str(OrderURL),
                revoke_url => str(RevokeURL)
            },
            {next_state, s2_nonce, Data1, [Action]};
        _ ->
            ?NEXT_ABORT(Data, #{cause => bad_directory_response, response => JSON})
    end;
s1_directory(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Get nonce state.
Enter this state:
1. After s1_directory.
2. In other states, but server returned badNonce error, so we need to retry.
""".
s2_nonce(enter, s1_directory, _Data) ->
    keep_state_and_data;
s2_nonce(enter, PrevState, Data) ->
    %% keep the previous state for retry
    {keep_state, Data#{prev_state => PrevState}};
s2_nonce(timeout, {start, Delay}, Data) ->
    ?LOG(info, "get_nonce_after_delay", #{delay => Delay}),
    NonceURL = maps:get(new_nonce_url, Data),
    http_get(NonceURL, Data);
s2_nonce(internal, ?HTTP_OK(_Code, _Slogan, Hdrs, _JSON), Data) ->
    PrevState = maps:get(prev_state, Data, undefined),
    Data1 = maps:without([prev_state], Data),
    case update_nonce(Hdrs, Data1) of
        {ok, Data2} when PrevState =:= undefined ->
            {next_state, s3_account, Data2};
        {ok, Data2} ->
            {next_state, PrevState, Data2};
        false ->
            ?NEXT_ABORT(Data, #{cause => missing_nonce, headers => Hdrs})
    end;
s2_nonce(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Account registration state.
Keep account URL in the state.
""".
s3_account(enter, _PrevState, Data) ->
    ?LOG(info, "account_registration_start", #{}),
    URL = maps:get(new_acc_url, Data),
    Body = #{
        <<"termsOfServiceAgreed">> => true,
        <<"contact">> => maps:get(contact, Data)
    },
    JoseJSON = jose_json(Data, Body, URL),
    http_post(URL, JoseJSON, Data);
s3_account(internal, ?HTTP_OK(_Code, _Slogan, Hdrs, JSON), Data) ->
    case find_location(Hdrs, Data) of
        undefined ->
            ?NEXT_ABORT(Data, #{cause => missing_header, header => "Location"});
        AccURL ->
            case is_valid_account(JSON) of
                true ->
                    {next_state, s4_order, Data#{acc_url => AccURL}};
                false ->
                    ?NEXT_ABORT(Data, #{cause => bad_account_response, response => JSON})
            end
    end;
s3_account(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Order creation state.
""".
s4_order(enter, _PrevState, Data) ->
    ?LOG(info, "order_creation_start", #{}),
    URL = maps:get(new_order_url, Data),
    Domains = maps:get(domains, Data),
    Identifiers = lists:map(
        fun(Domain) ->
            #{
                <<"type">> => <<"dns">>,
                <<"value">> => Domain
            }
        end,
        Domains
    ),
    Body = #{<<"identifiers">> => Identifiers},
    JoseJSON = jose_json(Data, Body, URL),
    http_post(URL, JoseJSON, Data);
s4_order(internal, ?HTTP_OK(_Code, _Slogan, Hdrs, JSON), Data) ->
    case find_location(Hdrs, Data) of
        undefined ->
            ?NEXT_ABORT(Data, #{cause => missing_header, header => "Location"});
        OrderURL ->
            Data1 = Data#{order_url => OrderURL},
            %% Order must start from "pending" state
            case is_valid_order(JSON, <<"pending">>) of
                true ->
                    AuthURLs = maps:get(<<"authorizations">>, JSON),
                    {next_state, s5_auth, Data1#{auth_urls => AuthURLs}};
                status_nomatch ->
                    ?NEXT_ABORT(Data1, #{
                        cause => status_nomatch, expected => <<"pending">>, response => JSON
                    });
                invalid_order ->
                    ?NEXT_ABORT(Data1, #{cause => bad_order_response, response => JSON})
            end
    end;
s4_order(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Domain authorization state.
`auth_urls` is a non-empty list of authorization URLs discovered in the `s4_order` state.
This state repeats until all authorizations are validated.
The per-domain challenges are collected in the looping data which will be processed in the next `s6_challenge` state.
""".
s5_auth(enter, _PrevState, #{auth_urls := [AuthURL | _]} = Data) ->
    ?LOG(info, "domain_authorization_start", #{auth_url => AuthURL}),
    JoseJSON = jose_json(Data, <<>>, AuthURL),
    http_post(AuthURL, JoseJSON, Data);
s5_auth(internal, ?HTTP_OK(_Code, _Slogan, _Hdrs, JSON), Data) ->
    case pick_a_challenge(JSON, Data) of
        {ok, Challenge} ->
            %% keep the pending challenges in the looping data
            %% for the next state s6_responder to get ready for the challenges
            Data1 = add_challenge(Challenge, Data),
            case maps:get(auth_urls, Data1) of
                [_] ->
                    %% all authorizations are already validated
                    %% enter challenge completion state
                    {next_state, s6_responder, Data1};
                [_ | Rest] ->
                    %% continue with the next authorization
                    {repeat_state, Data1#{auth_urls => Rest}}
            end;
        {error, Reason} ->
            ?NEXT_ABORT(Data, Reason)
    end;
s5_auth(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Challenge responder state.
Prepare for the challenges from ACME server.
""".
s6_responder(enter, _PrevState, _Data) ->
    ?LOG(info, "responder_start", #{}),
    {keep_state_and_data, {state_timeout, 0, check_challenges}};
s6_responder(state_timeout, check_challenges, #{challenges := Challenges} = Data) ->
    case group_challenges(Challenges) of
        #{<<"invalid">> := [_ | _] = InvalidChallenges} ->
            ?NEXT_ABORT(Data, #{
                cause => invalid_challenges, challenges => InvalidChallenges
            });
        #{<<"pending">> := [_ | _] = PendingChallenges} ->
            Args = lists:map(
                fun(#{<<"token">> := Token, <<"domain">> := Domain}) ->
                    #{
                        domain => Domain,
                        key => auth_key(Data, Token),
                        token => Token
                    }
                end,
                PendingChallenges
            ),
            {keep_state, Data#{challenges => PendingChallenges},
                ?INTERNAL({prepare_responder, Args})};
        _ ->
            ?NEXT_ABORT(Data, #{
                cause => bad_challenge_status, challenges => Challenges
            })
    end;
s6_responder(internal, {prepare_responder, Args}, #{challenges := Challenges} = Data) ->
    ?LOG(info, "apply_challenge_fun", #{challenges => Challenges}),
    case apply_challenge_fun(Data, Args) of
        ok ->
            %% Start sending challenge requests
            {next_state, s7_challenge, Data};
        {error, Reason} ->
            ?NEXT_ABORT(Data, #{cause => challenge_fun_failed, error => Reason})
    end;
s6_responder(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Challenge submission state.
Submit the challenge requests for each domain to the ACME server.
""".
s7_challenge(enter, _PrevState, #{challenges := [Challenge | Challenges]} = Data) ->
    #{<<"domain">> := Domain, <<"url">> := URL} = Challenge,
    Polls = maps:get(challenge_poll, Data, []),
    ?LOG(info, "request_challenge", #{domain => Domain}),
    JoseJSON = jose_json(Data, #{}, URL),
    http_post(URL, JoseJSON, Data#{challenges => Challenges, challenge_poll => Polls ++ [Challenge]});
s7_challenge(internal, ?HTTP_OK(_Code, _Slogan, _Hdrs, _JSON), #{challenges := Challenges} = Data) ->
    case Challenges of
        [] ->
            %% All challenges are submitted, start polling them
            {next_state, s8_poll_challenge, maps:without([challenges], Data)};
        _ ->
            %% Continue with next challenge
            repeat_state_and_data
    end;
s7_challenge(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Poll for challenge validation status.
""".
s8_poll_challenge(enter, _PrevState, _Data) ->
    %% Start polling immediately for the first attempt
    {keep_state_and_data, {state_timeout, 0, poll_next_challenge}};
s8_poll_challenge(state_timeout, poll_next_challenge, #{challenge_poll := [Challenge | _]} = Data) ->
    #{<<"domain">> := Domain, <<"url">> := URL} = Challenge,
    ?LOG(info, "challenge_status_polling", #{domain => Domain}),
    JoseJSON = jose_json(Data, <<>>, URL),
    http_post(URL, JoseJSON, Data);
s8_poll_challenge(
    internal, ?HTTP_OK(_Code, _Slogan, _Hdrs, JSON), #{challenge_poll := [Challenge | Rest]} = Data
) ->
    #{<<"domain">> := Domain} = Challenge,
    Status = maps:get(<<"status">>, JSON),
    ?LOG(info, "challenge_status_reply", #{domain => Domain, challenge_status => Status}),
    case Status of
        <<"valid">> ->
            %% This challenge is valid, update status and move to next
            case Rest of
                [] ->
                    %% All challenges polled and valid, move to order polling
                    {next_state, s9_poll_order, maps:without([challenge_poll], Data)};
                _ ->
                    %% Poll next challenge
                    {keep_state, Data#{challenge_poll => Rest},
                        {state_timeout, 0, poll_next_challenge}}
            end;
        _ when Status =:= <<"pending">> orelse Status =:= <<"processing">> ->
            %% Still pending or processing, poll again after interval
            Interval = maps:get(poll_interval, Data),
            {keep_state_and_data, {state_timeout, Interval, poll_next_challenge}};
        _ ->
            ?NEXT_ABORT(Data, #{cause => bad_challenge_status, challenge => JSON})
    end;
s8_poll_challenge(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Order status polling.
""".
s9_poll_order(enter, _PrevState, _Data) ->
    {keep_state_and_data, {state_timeout, 0, check_order_status}};
s9_poll_order(state_timeout, check_order_status, #{order_url := URL} = Data) ->
    ?LOG(info, "order_status_polling_start", #{order_url => URL}),
    JoseJSON = jose_json(Data, <<>>, URL),
    http_post(URL, JoseJSON, Data);
s9_poll_order(internal, ?HTTP_OK(_Code, _Slogan, _Hdrs, JSON), Data) ->
    case JSON of
        #{<<"status">> := NotReady} when
            NotReady =:= <<"pending">> orelse NotReady =:= <<"processing">>
        ->
            ?LOG(info, "order_not_ready", #{status => NotReady}),
            %% try again later
            Interval = maps:get(poll_interval, Data),
            {keep_state_and_data, {state_timeout, Interval, check_order_status}};
        #{<<"status">> := <<"ready">>, <<"finalize">> := FinalizeURL} ->
            ?LOG(info, "order_ready_to_finalize", #{finalize_url => FinalizeURL}),
            %% ready to finalize (send CSR)
            Action = ?INTERNAL({finalize, FinalizeURL}),
            {next_state, s10_finalize, Data, [Action]};
        #{<<"status">> := <<"valid">>, <<"certificate">> := CertURL} ->
            ?LOG(info, "order_certificate_issued", #{certificate_url => CertURL}),
            %% certificate issued, ready to download
            Action = ?INTERNAL({download_certificate, str(CertURL)}),
            {next_state, s11_certificate, Data, [Action]};
        _ ->
            %% unexpected order status, abort
            ?NEXT_ABORT(Data, #{cause => bad_order_status, response => JSON})
    end;
s9_poll_order(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Finalize state, send CSR to the CA.
""".
s10_finalize(enter, _PrevState, _Data) ->
    ?LOG(info, "finalize_start", #{}),
    keep_state_and_data;
s10_finalize(internal, {finalize, URL}, Data) ->
    CSR = generate_csr(Data),
    Body = #{<<"csr">> => base64url_encode(CSR)},
    JoseJSON = jose_json(Data, Body, URL),
    http_post(URL, JoseJSON, Data);
s10_finalize(internal, ?HTTP_OK(_Code, _Slogan, Hdrs, JSON), Data0) ->
    case find_location(Hdrs, Data0) of
        undefined ->
            ?NEXT_ABORT(Data0, #{cause => missing_header, header => "Location"});
        Location ->
            Data = Data0#{order_url => Location},
            case JSON of
                #{<<"status">> := <<"processing">>} ->
                    {next_state, s9_poll_order, Data};
                #{<<"status">> := <<"valid">>, <<"certificate">> := CertURL} ->
                    {next_state, s11_certificate, Data#{cert_url => CertURL}};
                _ ->
                    ?NEXT_ABORT(Data, #{cause => bad_finalize_response, response => JSON})
            end
    end;
s10_finalize(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Certificate retrieval state.
""".
s11_certificate(enter, _PrevState, _Data) ->
    ?LOG(info, "certificate_retrieval_start", #{}),
    keep_state_and_data;
s11_certificate(internal, {download_certificate, URL}, Data) ->
    JoseJSON = jose_json(Data, <<>>, URL),
    http_post(URL, JoseJSON, Data);
s11_certificate(internal, ?HTTP_OK(_Code, _Slogan, _Hdrs, PEM), Data) ->
    case decode_pem(PEM) of
        {ok, []} ->
            ?NEXT_ABORT(Data, #{cause => empty_chain});
        {ok, DERs} ->
            {keep_state_and_data, ?INTERNAL({validate_ders, fun() -> DERs end})};
        {error, Reason} ->
            ?NEXT_ABORT(Data, #{
                cause => invalid_certificate_response,
                error => Reason
            })
    end;
s11_certificate(internal, {validate_ders, DERs}, Data) ->
    #{
        acc_key := AccKeyFn,
        cert_key := KeyFn
    } = Data,
    try validate_ders(Data, DERs()) of
        {ok, Chain} ->
            Result = #{
                acc_key => AccKeyFn(),
                cert_key => KeyFn(),
                cert_chain => Chain
            },
            ok = reply_caller(Data, {ok, Result});
        {error, #{cause := _} = Reason} ->
            ?NEXT_ABORT(Data, Reason)
    catch
        C:E:Stack ->
            ?NEXT_ABORT(Data, #{
                cause => validate_chain_exception,
                exception => {C, E, Stack}
            })
    end;
s11_certificate(EventType, EventContent, Data) ->
    handle_event(?FUNCTION_NAME, EventType, EventContent, Data).

-doc """
Handle common events.
This function handles:
1. Caller process down
2. HTTP retry event: retry the request, e.g. badNonce
3. Abort event: unrecoverable error, reply to the caller and stop
4. Unknown event: log error and ignore
""".
handle_event(_StateName, info, {http, {RequestId, Response}}, Data) ->
    %% Received HTTP response,
    %% handle_rsp should trigger HTTP_OK, HTTP_RETRY or ABORT internal event
    %% HTTP_OK is handled by the state functions
    %% and HTTP_RETRY or ABORT will be handled by the handle_event function
    handle_rsp(RequestId, Response, Data);
handle_event(StateName, internal, ?HTTP_RETRY("badNonce"), Data) ->
    ?LOG(info, "need_retry_at_state_" ++ atom_to_list(StateName), #{reason => "badNonce"}),
    Delay = maps:get(poll_interval, Data),
    DelayAction = {timeout, Delay, {start, Delay}},
    {next_state, s2_nonce, Data, DelayAction};
handle_event(StateName, internal, ?ABORT(Reason), Data) ->
    ok = reply_caller(Data, {error, Reason}),
    Msg = "aborting_at_state_" ++ atom_to_list(StateName),
    ?LOG(warning, Msg, #{reason => Reason}),
    {stop, normal, Data};
handle_event(_StateName, info, {'DOWN', _, process, Pid, _}, #{caller_pid := Pid} = Data) ->
    {stop, normal, Data};
handle_event(StateName, EventType, EventContent, _Data) ->
    ?LOG(
        error,
        "unknown_event_ignored",
        #{
            state_name => StateName,
            event_type => EventType,
            event_content => EventContent
        }
    ),
    keep_state_and_data.

is_valid_account(#{<<"status">> := <<"valid">>} = JSON) ->
    false =/= maps:get(<<"termsOfServiceAgreed">>, JSON, undefined);
is_valid_account(_) ->
    false.

find_location(Hdrs, Data) ->
    proplists:get_value("location", Hdrs, maps:get(order_url, Data, undefined)).

check_url(S) ->
    try
        L = unicode:characters_to_list(S),
        [_ | _] = L
    catch
        _:_ ->
            erlang:throw(bad_url)
    end.

check_domains([]) ->
    erlang:throw(empty_domains);
check_domains(Domains) ->
    lists:map(fun(D) -> bin(idna:to_ascii(D)) end, Domains).

set_request_id(RequestId, Data) ->
    Data#{request_id => RequestId}.

reset_request_id(Data) ->
    Data#{request_id => undefined}.

http_get(URL, Data) ->
    Opts = maps:get(httpc_opts, Data, #{}),
    return_httpc(acme_client_httpc:get(URL, Opts), Data).

http_post(URL, Body, Data) when is_binary(URL) ->
    http_post(str(URL), Body, Data);
http_post(URL, Body, Data) ->
    Opts = maps:get(httpc_opts, Data, #{}),
    return_httpc(acme_client_httpc:post(URL, Body, Opts), Data).

return_httpc({ok, RequestId}, Data) ->
    {keep_state, set_request_id(RequestId, Data)};
return_httpc(Error, Data) ->
    RequestId = make_ref(),
    self() ! {http, {RequestId, Error}},
    {keep_state, set_request_id(RequestId, Data)}.

reply_caller(#{caller_pid := Caller, caller_ref := CallerRef}, Result) ->
    _ = erlang:send(Caller, {CallerRef, Result}),
    ok.

%% Ensure binary.
bin(X) -> unicode:characters_to_binary(X).

%% Ensure char-list string.
str(X) -> unicode:characters_to_list(X).

update_nonce(Hdrs, Data) ->
    case lists:keyfind("replay-nonce", 1, Hdrs) of
        {_, Nonce} ->
            {ok, Data#{nonce => bin(Nonce)}};
        _ ->
            false
    end.

%% Handle HTTP response
%% First check if the response has content-type header
handle_rsp(RequestId, Response, #{request_id := RequestId} = Data) ->
    do_handle_rsp(Response, reset_request_id(Data));
handle_rsp(RequestId, Response, Data) ->
    ?NEXT_ABORT(Data, #{cause => unexpected_response, request_id => RequestId, response => Response}).

do_handle_rsp({{_, Code, Slogan}, Hdrs, Body}, Data) ->
    case lists:keyfind("content-type", 1, Hdrs) of
        {_, Type} ->
            handle_rsp_with_hdr(Code, Slogan, Hdrs, Body, Data, Type);
        false when ?IS_2XX_3XX(Code) andalso Body =:= <<>> ->
            ?NEXT_HTTP_OK(Data, Code, Slogan, Hdrs, #{});
        _ ->
            %% no content-type header, so there is no way to parse the body hence don't know if we can retry, must abort
            ?NEXT_ABORT(Data, #{cause => missing_header, header => "Content-Type"})
    end;
do_handle_rsp({error, Reason}, Data) ->
    ?NEXT_HTTP_RETRY(Data, Reason);
do_handle_rsp(Reason, Data) ->
    ?NEXT_HTTP_RETRY(Data, Reason).

%% Handle HTTP response with content-type header
handle_rsp_with_hdr(
    Code,
    Slogan,
    Hdrs,
    Body,
    Data,
    "application/pem-certificate-chain" ++ _
) when ?IS_2XX_3XX(Code) ->
    ?NEXT_HTTP_OK(Data, Code, Slogan, Hdrs, Body);
handle_rsp_with_hdr(Code, Slogan, Hdrs, Body, Data, Type) when Code =< 400 ->
    %% 400 should trigger a retry depending on the body content
    IsValidType =
        case Type of
            "application/problem+json" ++ _ ->
                true;
            "application/json" ++ _ ->
                true;
            _ ->
                false
        end,
    case IsValidType of
        true ->
            %% Server might have returned a new nonce, keep it for the next request
            Data1 =
                case update_nonce(Hdrs, Data) of
                    {ok, Data2} ->
                        Data2;
                    false ->
                        Data
                end,
            handle_rsp_body(Code, Slogan, Hdrs, Body, Data1, Type);
        false ->
            ?NEXT_ABORT(Data, #{cause => unknown_content_type, type => Type})
    end;
handle_rsp_with_hdr(Code, Slogan, _Hdrs, _Body, Data, _Type) ->
    ?NEXT_HTTP_RETRY(Data, {unknown_response, Code, Slogan}).

handle_rsp_body(Code, Slogan, Hdrs, Body, Data, Type) ->
    try json:decode(Body) of
        JSON ->
            handle_rsp_json(Code, Slogan, Hdrs, JSON, Data, Type)
    catch
        _:_ ->
            ?NEXT_ABORT(Data, #{cause => bad_json, body => Body})
    end.

handle_rsp_json(Code, Slogan, Hdrs, JSON, Data, Type) ->
    case Type of
        "application/problem+json" ++ _ ->
            handle_rsp_problem(JSON, Data);
        _ ->
            ?NEXT_HTTP_OK(Data, Code, Slogan, Hdrs, JSON)
    end.

handle_rsp_problem(JSON, Data) ->
    case JSON of
        #{<<"type">> := <<"urn:ietf:params:acme:error:badNonce">>} ->
            ?LOG(info, "bad_nonce_will_retry", #{}),
            ?NEXT_HTTP_RETRY(Data, "badNonce");
        _ ->
            ?NEXT_ABORT(Data, #{cause => bad_response, response => JSON})
    end.

json_encode(JSON) ->
    bin(json:encode(JSON)).

jose_json(Data, Body, URL) when is_map(Body) ->
    jose_json(Data, json_encode(Body), URL);
jose_json(Data, Body, URL) when is_binary(Body) ->
    Nonce = maps:get(nonce, Data),
    %% assert that nonce is a binary
    true = is_binary(Nonce),
    AccKey = (maps:get(acc_key, Data))(),
    acme_client_lib:jose_json(
        AccKey,
        maps:get(acc_url, Data),
        Nonce,
        Body,
        URL
    ).

%% possible order statuses:
%% pending: Order is pending, start authorization
%% processing: Order is processing, continue authorization
%% ready: Order is ready, start certificate issuance, send CSR
%% valid: Order is valid, certificate issued
%% invalid: Order is invalid, stop authorization
is_valid_order(Order, ExpectedStatus) ->
    case Order of
        #{
            <<"status">> := Status,
            <<"identifiers">> := [_ | _],
            <<"authorizations">> := [_ | _]
        } ->
            case Status =:= ExpectedStatus of
                true ->
                    true;
                false ->
                    status_nomatch
            end;
        _ ->
            invalid_order
    end.

is_valid_auth(JSON) ->
    case JSON of
        #{
            <<"identifier">> := #{<<"type">> := <<"dns">>, <<"value">> := _},
            <<"status">> := Status,
            <<"challenges">> := [_ | _]
        } ->
            %% TODO: check expires timestamp
            lists:member(Status, [
                <<"pending">>,
                <<"valid">>,
                <<"invalid">>,
                <<"deactivated">>,
                <<"expired">>,
                <<"revoked">>
            ]);
        _ ->
            false
    end.

%% Pick a challenge from the list of challenges received from the CA.
%% Hopefully the supported challenge type (from caller) can be found in the list.
%% If not, return an error.
pick_a_challenge(JSON, Data) ->
    case is_valid_auth(JSON) of
        true ->
            do_pick_a_challenge(JSON, Data);
        false ->
            {error, #{cause => bad_auth_response, response => JSON}}
    end.

do_pick_a_challenge(
    #{
        <<"challenges">> := Challenges,
        <<"identifier">> := #{<<"value">> := D}
    },
    Data
) ->
    Domain = bin(idna:to_unicode(str(D))),
    SupportedChallengeType = maps:get(challenge_type, Data),
    case
        lists:filter(
            fun(#{<<"type">> := T}) ->
                T =:= SupportedChallengeType
            end,
            Challenges
        )
    of
        [Challenge | _] ->
            {ok, Challenge#{<<"domain">> => Domain}};
        [] ->
            {error, #{
                cause => no_supported_challenges,
                domain => Domain,
                supported_challenge_type => SupportedChallengeType,
                challenges => Challenges
            }}
    end.

add_challenge(Challenge, Data) ->
    Challenges = maps:get(challenges, Data, []),
    Data#{challenges => Challenges ++ [Challenge]}.

group_challenges(Challenges) ->
    group_challenges(Challenges, #{
        <<"pending">> => [], <<"processing">> => [], <<"valid">> => [], <<"invalid">> => []
    }).

group_challenges([], Acc) ->
    Acc;
group_challenges([Challenge | Cs], Acc) ->
    Key = maps:get(<<"status">>, Challenge),
    Group = maps:get(Key, Acc),
    group_challenges(Cs, Acc#{Key => Group ++ [Challenge]}).

apply_challenge_fun(Data, Args) ->
    F = maps:get(challenge_fn, Data),
    try
        ok = F(Args)
    catch
        E:C:Stack ->
            {error, {E, C, Stack}}
    end.

auth_key(#{acc_key := PrivKeyFn}, Token) ->
    Thumbprint = jose_jwk:thumbprint(jose_jwk:from_key(PrivKeyFn())),
    <<Token/binary, $., Thumbprint/binary>>.

generate_csr(#{domains := Domains, cert_key := Key}) ->
    CSR = acme_client_lib:generate_csr([str(D) || D <- Domains], Key()),
    public_key:der_encode('CertificationRequest', CSR).

validate_ders(
    #{
        cert_key := CertKey,
        ca_certs := CaCerts
    },
    DERs
) ->
    Chain = lists:map(fun decode_der/1, DERs),
    validate_chain(Chain, CertKey, CaCerts).

decode_der(DER) ->
    Cert = public_key:pkix_decode_cert(DER, otp),
    {Cert, DER}.

validate_chain(Chain, CertKey, CaCerts) ->
    {Certs, DERs} = acme_client_lib:sort_cert_chain(Chain),
    case CaCerts =:= [] of
        true ->
            %% trust the server
            {ok, Certs};
        false ->
            %% ensure the chain is issued by trusted CA
            case acme_client_lib:validate_cert_chain(Certs, DERs, CertKey, CaCerts) of
                valid ->
                    {ok, Certs};
                {bad_cert, Reason} ->
                    {error, #{cause => Reason}}
            end
    end.

%% Decode PEM file into a list of DER format certs.
decode_pem(PEM) ->
    try
        {ok,
            lists:map(
                fun({'Certificate', DER, not_encrypted}) -> DER end,
                public_key:pem_decode(PEM)
            )}
    catch
        C:E:Stack ->
            {error, {C, E, Stack}}
    end.

base64url_encode(Bin) ->
    base64:encode(Bin, #{mode => urlsafe, padding => false}).
