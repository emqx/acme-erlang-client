-module(p1_acme_challenge_responder).
-moduledoc """
This module is used only for testing.
It starts a dependency-free HTTP server that responds to ACME challenge requests.
""".

%% API
-export([challenge_fun/1, start/1, stop/1]).

%% Internal exports
-export([start_server/2, handle_request/2]).

-record(state, {
    challenges = #{} :: #{binary() => binary()},
    port :: inet:port_number()
}).

-define(PORT, 5002).
-define(RETRY_DELAY, 1000).
-define(SERVER_NAME, ?MODULE).
-define(CHALLENGE_TABLE, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

-doc """
This is the callback function for p1_acme:issue/3.
It inserts the challenges into the challenge table. The table is shared with the server process which handles the challenge requests.
The ets table is created in the start/1 function, so, make sure the responder server is started before calling this function.
The input is a list of maps like:
```
[
    #{
        <<"domain">> => <<"local.host">>,
        <<"token">> => <<"1234567890">>,
        <<"key">> => <<"1234567890">>
    }
]
```
""".
challenge_fun(Challenges) ->
    ok = insert_challenges(Challenges).

start(Challenges) ->
    %% turn the list of maps into a map, key is token, value is key
    io:format("[RESPONDER] Starting challenge responder on port ~p~n", [?PORT]),
    Pid = spawn_link(
        fun() ->
            register(?SERVER_NAME, self()),
            ?CHALLENGE_TABLE = ets:new(?CHALLENGE_TABLE, [named_table, set, public]),
            ok = insert_challenges(Challenges),
            {ok, LSocket} = listen(?PORT),
            Acceptor = spawn_link(fun() ->
                io:format("[RESPONDER] Acceptor process started~n", []),
                accept_connections(LSocket)
            end),
            receive
                stop ->
                    io:format("[RESPONDER] Received stop signal, shutting down...~n", []),
                    unlink(Acceptor),
                    gen_tcp:close(LSocket),
                    exit(Acceptor, kill),
                    exit(normal)
            end
        end
    ),
    {ok, Pid}.

listen(Port) ->
    Opts = [
        binary,
        {packet, http},
        {active, false},
        {reuseaddr, true},
        {ip, {0, 0, 0, 0}},
        {backlog, 5},
        {nodelay, true},
        {keepalive, true}
    ],
    case gen_tcp:listen(Port, Opts) of
        {ok, Socket} ->
            io:format("[RESPONDER] Server listening on port ~p~n", [Port]),
            {ok, Socket};
        {error, eacces} ->
            io:format(
                "[RESPONDER] Permission denied to bind to port ~p. Try running with sudo.~n", [Port]
            ),
            {error, permission_denied};
        {error, eaddrinuse} ->
            io:format("[RESPONDER] Port ~p is already in use.~n", [Port]),
            {error, port_in_use};
        {error, Reason} ->
            io:format("[RESPONDER] Failed to start server: ~p~n", [Reason]),
            {error, Reason}
    end.

accept_connections(ListenSocket) ->
    io:format("[RESPONDER] Waiting for connection...~n", []),
    case gen_tcp:accept(ListenSocket) of
        {ok, Socket} ->
            io:format("[RESPONDER] Accepted connection from ~p~n", [inet:peername(Socket)]),
            handle_connection(Socket),
            accept_connections(ListenSocket);
        {error, closed} ->
            io:format("[RESPONDER] Listen socket closed~n", []),
            exit(normal);
        {error, Reason} ->
            io:format("[RESPONDER] Failed to accept connection: ~p~n", [Reason]),
            timer:sleep(?RETRY_DELAY),
            accept_connections(ListenSocket)
    end.

handle_connection(Socket) ->
    spawn_link(fun() -> handle_client(Socket) end).

handle_client(Socket) ->
    case receive_request(Socket) of
        {ok, {http_request, Method, Path, Version}} ->
            io:format("[RESPONDER] Received ~p request for ~p~n", [Method, Path]),
            handle_request(Socket, Method, Path, Version);
        {error, Reason} ->
            io:format("[RESPONDER] Error receiving request: ~p~n", [Reason])
    end,
    gen_tcp:close(Socket).

receive_request(Socket) ->
    case gen_tcp:recv(Socket, 0) of
        {ok, {http_request, Method, Path, Version}} ->
            {ok, {http_request, Method, Path, Version}};
        {error, closed} ->
            {error, connection_closed};
        {error, Reason} ->
            {error, Reason}
    end.

handle_request(Socket, Method, {abs_path, Path}, Version) ->
    case {Method, Path} of
        {'GET', "/.well-known/acme-challenge/" ++ Token} ->
            io:format("[RESPONDER] Challenge request for token: ~p~n", [Token]),
            case ets:lookup(?CHALLENGE_TABLE, iolist_to_binary(Token)) of
                [{_, Key}] ->
                    io:format("[RESPONDER] Found key for token: ~p~n", [Key]),
                    send_response(Socket, Version, 200, "OK", Key);
                [] ->
                    io:format("[RESPONDER] Token not found: ~p~n", [Token]),
                    send_response(Socket, Version, 404, "Not Found", "")
            end;
        _ ->
            io:format("[RESPONDER] Invalid request: ~p ~p~n", [Method, Path]),
            send_response(Socket, Version, 404, "Not Found", "")
    end;
handle_request(Socket, Method, Path, Version) ->
    io:format("[RESPONDER] Invalid request format: ~p ~p~n", [Method, Path]),
    send_response(Socket, Version, 400, "Bad Request", "").

send_response(Socket, Version, Code, Status, Body) ->
    Response = [
        io_lib:format("~s ~p ~s\r\n", [format_version(Version), Code, Status]),
        "Content-Type: text/plain\r\n",
        "Content-Length: ",
        integer_to_list(byte_size(iolist_to_binary(Body))),
        "\r\n",
        "\r\n",
        Body
    ],
    case gen_tcp:send(Socket, Response) of
        ok ->
            io:format("[RESPONDER] Sent response: ~p ~p~n", [Code, Status]);
        {error, Reason} ->
            io:format("[RESPONDER] Failed to send response: ~p~n", [Reason])
    end.

stop(Pid) ->
    Pid ! stop.

%%%===================================================================
%%% Internal functions
%%%===================================================================
format_version({Major, Minor}) ->
    io_lib:format("HTTP/~p.~p", [Major, Minor]).

-spec start_server(#{binary() => binary()}, inet:port_number()) ->
    {ok, inet:port_number()} | {error, term()}.
start_server(Challenges, Port) ->
    case
        gen_tcp:listen(Port, [
            binary,
            {active, false},
            {reuseaddr, true},
            % Bind to all interfaces
            {ip, {0, 0, 0, 0}}
        ])
    of
        {ok, ListenSocket} ->
            {ok, ActualPort} = inet:port(ListenSocket),
            io:format("[RESPONDER] Server listening on port ~p~n", [ActualPort]),
            % Start acceptor process
            Pid = spawn_link(?MODULE, handle_request, [
                ListenSocket,
                #state{
                    challenges = Challenges,
                    port = ActualPort
                }
            ]),
            % Accept one connection
            gen_tcp:controlling_process(ListenSocket, Pid),
            {ok, ListenSocket};
        Error ->
            io:format("[RESPONDER] Failed to start server: ~p~n", [Error]),
            Error
    end.

handle_request(ListenSocket, State) ->
    io:format("[RESPONDER] Waiting for connection...~n"),
    case gen_tcp:accept(ListenSocket) of
        {ok, Socket} ->
            io:format("[RESPONDER] Got connection~n"),
            % Handle the request
            handle_http_request(Socket, State),
            % Close the socket
            gen_tcp:close(Socket),
            % Close the listener
            gen_tcp:close(ListenSocket);
        {error, Error} ->
            io:format("[RESPONDER] Failed to accept connection: ~p~n", [Error]),
            error_logger:error_msg("[RESPONDER] Failed to accept connection: ~p~n", [Error]),
            gen_tcp:close(ListenSocket)
    end.

handle_http_request(Socket, State) ->
    io:format("[RESPONDER] Waiting for HTTP request...~n"),
    case gen_tcp:recv(Socket, 0) of
        {ok, {http_request, Method, Path, Version}} ->
            io:format("[RESPONDER] Got request: ~p ~p ~p~n", [Method, Path, Version]),
            % Extract token from path
            case Path of
                "/.well-known/acme-challenge/" ++ Token ->
                    io:format("[RESPONDER] Looking up token: ~p~n", [Token]),
                    case maps:find(Token, State#state.challenges) of
                        {ok, Key} ->
                            io:format("[RESPONDER] Found key for token~n"),
                            send_challenge_response(Socket, Key);
                        error ->
                            io:format("[RESPONDER] Token not found~n"),
                            send_404(Socket)
                    end;
                _ ->
                    io:format("[RESPONDER] Invalid path: ~p~n", [Path]),
                    send_404(Socket)
            end;
        {error, Error} ->
            io:format("[RESPONDER] Failed to receive request: ~p~n", [Error]),
            send_400(Socket)
    end.

-spec send_challenge_response(gen_tcp:socket(), binary()) -> ok.
send_challenge_response(Socket, Key) ->
    Response = [
        "HTTP/1.1 200 OK\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Length: ",
        integer_to_list(byte_size(Key)),
        "\r\n",
        "\r\n",
        Key
    ],
    gen_tcp:send(Socket, Response).

-spec send_404(gen_tcp:socket()) -> ok.
send_404(Socket) ->
    Response = [
        "HTTP/1.1 404 Not Found\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Length: 9\r\n",
        "\r\n",
        "Not Found"
    ],
    gen_tcp:send(Socket, Response).

-spec send_400(gen_tcp:socket()) -> ok.
send_400(Socket) ->
    Response = [
        "HTTP/1.1 400 Bad Request\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Length: 11\r\n",
        "\r\n",
        "Bad Request"
    ],
    gen_tcp:send(Socket, Response).

insert_challenges(Challenges) ->
    lists:foreach(
        fun(#{<<"token">> := Token, <<"key">> := Key}) ->
            true = ets:insert(?CHALLENGE_TABLE, {Token, Key})
        end,
        Challenges
    ).
