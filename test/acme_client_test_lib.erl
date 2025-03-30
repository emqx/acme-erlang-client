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

-module(acme_client_test_lib).

-export([cmd/1]).

cmd(Cmd) ->
    ct:pal("Running:\n  ~s", [Cmd]),
    Port = erlang:open_port({spawn, Cmd}, [binary, exit_status, stderr_to_stdout]),
    try
        {Status, Bin} = wait_cmd_down(Port, []),
        ct:pal("Command output:\n  ~s", [Bin]),
        case Status of
            0 -> ok;
            _ -> {error, Status}
        end
    after
        close_port(Port)
    end.

wait_cmd_down(Port, Acc) ->
    receive
        {Port, {data, Bin}} ->
            wait_cmd_down(Port, [Bin | Acc]);
        {Port, {exit_status, Status}} ->
            {Status, lists:reverse(Acc)}
    after 1_000 ->
        ct:pal("still waiting for command response..."),
        wait_cmd_down(Port, Acc)
    end.

close_port(Port) ->
    try
        _ = erlang:port_close(Port),
        ok
    catch
        error:badarg ->
            ok
    end.
