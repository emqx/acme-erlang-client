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
-module(acme_client_lib_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("public_key/include/public_key.hrl").
-include_lib("common_test/include/ct.hrl").

%% Test server callbacks
-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    t_decode_key/1
]).

all() ->
    [
        t_decode_key
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ?MODULE:TestCase({init, Config}).

end_per_testcase(TestCase, Config) ->
    ?MODULE:TestCase({'end', Config}),
    ok.

%% Test cases

t_decode_key({init, Config}) ->
    % Create a temporary directory
    TmpDir = string:trim(os:cmd("mktemp -d")),

    % Generate keys in different formats
    CmdList = [
        "cd " ++ TmpDir,
        % Generate traditional RSA key
        "openssl genrsa -out rsa.key 2048",
        % Generate EC key
        "openssl ecparam -name prime256v1 -genkey -noout -out ec.key",
        % Generate RSA key in PKCS#8 format
        "openssl pkcs8 -topk8 -nocrypt -in rsa.key -out rsa.pk8",
        % Generate EC key in PKCS#8 format
        "openssl pkcs8 -topk8 -nocrypt -in ec.key -out ec.pk8",
        % Generate an invalid key (just a text file)
        "echo \"invalid key\" > invalid.key",
        "openssl genrsa -out rsa2.key 2048",
        % Generate a file with multiple keys
        "cat rsa.key >> rsa2.key",
        % Generate encrypted RSA key (traditional format)
        "openssl genrsa -aes256 -passout pass:secret -out rsa_enc.key 2048",
        % Generate encrypted EC key (traditional format)
        "openssl ecparam -name prime256v1 -genkey | openssl ec -aes256 -passout pass:secret -out ec_enc.key",
        % Generate encrypted RSA key in PKCS#8 format
        "openssl pkcs8 -topk8 -v2 aes256 -in rsa.key -out rsa_enc.pk8 -passout pass:secret",
        % Generate encrypted EC key in PKCS#8 format
        "openssl pkcs8 -topk8 -v2 aes256 -in ec.key -out ec_enc.pk8 -passout pass:secret"
    ],
    Cmd = string:join(CmdList, " && "),
    ok = cmd("/bin/sh -c '" ++ Cmd ++ "'"),

    [{tmp_dir, TmpDir} | Config];
t_decode_key({'end', Config}) ->
    TmpDir = proplists:get_value(tmp_dir, Config),
    ok = cmd("rm -rf " ++ TmpDir);
t_decode_key(Config) ->
    TmpDir = proplists:get_value(tmp_dir, Config),

    % Test traditional RSAPrivateKey format
    {ok, RsaKey} = read_key(TmpDir ++ "/rsa.key"),
    ?assert(is_record(RsaKey, 'RSAPrivateKey')),
    ?assertEqual(ok, write_key(TmpDir ++ "/rsa.key", RsaKey)),

    % Test traditional ECPrivateKey format
    {ok, EcKey} = read_key(TmpDir ++ "/ec.key"),
    ?assert(is_record(EcKey, 'ECPrivateKey')),
    ?assertEqual(ok, write_key(TmpDir ++ "/ec.key", EcKey)),

    % Test PKCS#8 RSA PrivateKeyInfo format
    {ok, RsaKeyPk8} = read_key(TmpDir ++ "/rsa.pk8"),
    ?assert(is_record(RsaKeyPk8, 'RSAPrivateKey')),
    ?assertEqual(ok, write_key(TmpDir ++ "/rsa.pk8", RsaKeyPk8)),

    % Test PKCS#8 EC PrivateKeyInfo format
    {ok, EcKeyPk8} = read_key(TmpDir ++ "/ec.pk8"),
    ?assert(is_record(EcKeyPk8, 'ECPrivateKey')),
    ?assertEqual(ok, write_key(TmpDir ++ "/ec.pk8", EcKeyPk8)),

    %% cannot test this after OK case, maybe OTP caches the decode result?
    ?assertMatch(
        {error, {bad_key, bad_password}},
        read_key(TmpDir ++ "/rsa_enc.key", "wrong_password")
    ),

    % Test encrypted traditional RSA key
    {ok, RsaKeyEnc} = read_key(TmpDir ++ "/rsa_enc.key", "secret"),
    ?assert(is_record(RsaKeyEnc, 'RSAPrivateKey')),
    ?assertEqual(ok, write_key(TmpDir ++ "/rsa_enc.key", RsaKeyEnc, "secret")),

    % Test encrypted traditional EC key
    {ok, EcKeyEnc} = read_key(TmpDir ++ "/ec_enc.key", "secret"),
    ?assert(is_record(EcKeyEnc, 'ECPrivateKey')),
    ?assertEqual(ok, write_key(TmpDir ++ "/ec_enc.key", EcKeyEnc, "secret")),

    % Test encrypted PKCS#8 RSA key
    {ok, RsaKeyPk8Enc} = read_key(TmpDir ++ "/rsa_enc.pk8", "secret"),
    ?assert(is_record(RsaKeyPk8Enc, 'RSAPrivateKey')),
    ?assertEqual(ok, write_key(TmpDir ++ "/rsa_enc.pk8", RsaKeyPk8Enc, "secret")),

    % Test encrypted PKCS#8 EC key
    {ok, EcKeyPk8Enc} = read_key(TmpDir ++ "/ec_enc.pk8", "secret"),
    ?assert(is_record(EcKeyPk8Enc, 'ECPrivateKey')),
    ?assertEqual(ok, write_key(TmpDir ++ "/ec_enc.pk8", EcKeyPk8Enc, "secret")),

    ?assertMatch(
        {error, {file_error, enoent}},
        read_key(TmpDir ++ "/non-existent.key")
    ),

    % Test invalid key format
    ?assertMatch(
        {error, no_valid_key},
        read_key(TmpDir ++ "/invalid.key")
    ),

    % Test multiple keys in one file
    ?assertMatch(
        {error, multiple_keys_found},
        read_key(TmpDir ++ "/rsa2.key")
    ),
    ok.

%% Helper functions for running shell commands
cmd(Cmd) ->
    acme_client_test_lib:cmd(Cmd).

read_key(Path) ->
    acme_client_lib:read_priv_key_file(Path).

read_key(Path, Password) ->
    acme_client_lib:read_priv_key_file(Path, Password).

write_key(Path, Key) ->
    acme_client_lib:write_priv_key(Path, Key).

write_key(Path, Key, Password) ->
    acme_client_lib:write_priv_key(Path, Key, Password).
