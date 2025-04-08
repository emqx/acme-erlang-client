%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@process-one.net>
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
-module(acme_client_lib).

-export([
    generate_key/1,
    generate_csr/2,
    jose_json/5,
    sort_cert_chain/1,
    validate_cert_chain/4,
    write_priv_key/2,
    read_priv_key_file/1,
    read_priv_key_file/2,
    read_cert_file/1
]).

-include_lib("public_key/include/public_key.hrl").

-type priv_key() :: public_key:private_key().
-type domain() :: string().
-type url() :: binary().
-type nonce() :: binary().
-type cert() :: #'OTPCertificate'{}.
-type pub_key() :: #'RSAPublicKey'{} | #'ECPoint'{}.
-type cert_type() :: ec | rsa.
-type password() :: undefined | string() | binary() | fun(() -> string() | binary()).

-define(DER_NULL, <<5, 0>>).

-spec generate_key(cert_type()) -> priv_key().
generate_key(ec) ->
    public_key:generate_key({namedCurve, secp256r1});
generate_key(rsa) ->
    public_key:generate_key({rsa, 2048, 65537}).

-spec generate_csr([domain()], priv_key()) -> #'CertificationRequest'{}.
generate_csr([_ | _] = Domains, PrivKey) ->
    SignAlgoOID = signature_algorithm(PrivKey),
    PubKey = pubkey_from_privkey(PrivKey),
    {DigestType, _} = public_key:pkix_sign_types(SignAlgoOID),
    DerParams = der_params(PrivKey),
    DerSAN = public_key:der_encode(
        'SubjectAltName',
        [{dNSName, Domain} || Domain <- Domains]
    ),
    Extns = [
        #'Extension'{
            extnID = ?'id-ce-subjectAltName',
            critical = false,
            extnValue = DerSAN
        }
    ],
    DerExtnReq = public_key:der_encode('ExtensionRequest', Extns),
    Attribute = #'AttributePKCS-10'{
        type = ?'pkcs-9-at-extensionRequest',
        values = [{asn1_OPENTYPE, DerExtnReq}]
    },
    SubjPKInfo = #'CertificationRequestInfo_subjectPKInfo'{
        subjectPublicKey = subject_pubkey(PubKey),
        algorithm =
            #'CertificationRequestInfo_subjectPKInfo_algorithm'{
                algorithm = algorithm(PrivKey),
                parameters = {asn1_OPENTYPE, DerParams}
            }
    },
    CsrInfo = #'CertificationRequestInfo'{
        version = v1,
        subject = {rdnSequence, []},
        subjectPKInfo = SubjPKInfo,
        attributes = [Attribute]
    },
    DerCsrInfo = public_key:der_encode('CertificationRequestInfo', CsrInfo),
    Signature = public_key:sign(DerCsrInfo, DigestType, PrivKey),
    #'CertificationRequest'{
        certificationRequestInfo = CsrInfo,
        signatureAlgorithm =
            #'CertificationRequest_signatureAlgorithm'{
                algorithm = SignAlgoOID
            },
        signature = Signature
    }.

signature_algorithm(#'ECPrivateKey'{}) ->
    ?'ecdsa-with-SHA256';
signature_algorithm(#'RSAPrivateKey'{}) ->
    ?'sha256WithRSAEncryption'.

algorithm(#'ECPrivateKey'{}) ->
    ?'id-ecPublicKey';
algorithm(#'RSAPrivateKey'{}) ->
    ?'rsaEncryption'.

-spec pubkey_from_privkey(priv_key()) -> pub_key().
pubkey_from_privkey(#'RSAPrivateKey'{
    modulus = Modulus,
    publicExponent = Exp
}) ->
    #'RSAPublicKey'{
        modulus = Modulus,
        publicExponent = Exp
    };
pubkey_from_privkey(#'ECPrivateKey'{publicKey = Key}) ->
    #'ECPoint'{point = Key}.

-spec subject_pubkey(pub_key()) -> binary().
subject_pubkey(#'ECPoint'{point = Point}) ->
    Point;
subject_pubkey(#'RSAPublicKey'{} = Key) ->
    public_key:der_encode('RSAPublicKey', Key).

-spec der_params(priv_key()) -> binary().
der_params(#'ECPrivateKey'{parameters = Params}) ->
    public_key:der_encode('EcpkParameters', Params);
der_params(_) ->
    ?DER_NULL.

-spec pubkey_from_cert(cert()) -> pub_key().
pubkey_from_cert(Cert) ->
    TBSCert = Cert#'OTPCertificate'.tbsCertificate,
    PubKeyInfo = TBSCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    SubjPubKey = PubKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey,
    case PubKeyInfo#'OTPSubjectPublicKeyInfo'.algorithm of
        #'PublicKeyAlgorithm'{
            algorithm = ?'rsaEncryption'
        } ->
            SubjPubKey;
        #'PublicKeyAlgorithm'{
            algorithm = ?'id-ecPublicKey'
        } ->
            SubjPubKey
    end.

-spec validate_cert_chain([cert()], [binary()], priv_key(), [cert()]) ->
    valid | {bad_cert, term()}.
validate_cert_chain([Cert | _] = Certs, DerCerts, PrivKey, CaCerts) ->
    case pubkey_from_privkey(PrivKey) == pubkey_from_cert(Cert) of
        false ->
            {bad_cert, key_mismatch};
        true ->
            Last = lists:last(Certs),
            case find_issuer_cert(Last, CaCerts) of
                {ok, CaCert} ->
                    case
                        public_key:pkix_path_validation(
                            CaCert, lists:reverse(DerCerts), []
                        )
                    of
                        {ok, _} -> valid;
                        {error, {bad_cert, _} = Reason} -> Reason
                    end;
                error ->
                    case public_key:pkix_is_self_signed(Last) of
                        true ->
                            {bad_cert, selfsigned_peer};
                        false ->
                            {bad_cert, unknown_ca}
                    end
            end
    end.

-doc """
Sort certificate chain from leaf to root.
""".
-spec sort_cert_chain([{cert(), binary()}]) -> {[cert()], [binary()]}.
sort_cert_chain(Chain) ->
    lists:unzip(
        lists:sort(
            fun({Cert1, _}, {Cert2, _}) ->
                public_key:pkix_is_issuer(Cert1, Cert2)
            end,
            Chain
        )
    ).

-spec find_issuer_cert(cert(), [cert()]) -> {ok, cert()} | error.
find_issuer_cert(Cert, [IssuerCert | IssuerCerts]) ->
    case public_key:pkix_is_issuer(Cert, IssuerCert) of
        true -> {ok, IssuerCert};
        false -> find_issuer_cert(Cert, IssuerCerts)
    end;
find_issuer_cert(_Cert, []) ->
    error.

-doc """
Generate a JOSE JSON object for the given data and URL.
""".
-spec jose_json(priv_key(), url(), nonce(), binary(), url()) -> binary().
jose_json(AccKey, AccURL, Nonce, Data, URL) ->
    PrivKey = jose_jwk:from_key(AccKey),
    PubKey = jose_jwk:to_public(PrivKey),
    AlgMap =
        case jose_jwk:signer(PrivKey) of
            M when is_record(AccKey, 'RSAPrivateKey') ->
                M#{<<"alg">> => <<"RS256">>};
            M ->
                M
        end,
    JwsMap0 = #{
        <<"nonce">> => Nonce,
        <<"url">> => iolist_to_binary(URL)
    },
    JwsMap =
        case AccURL of
            undefined ->
                {_, BinaryPubKey} = jose_jwk:to_binary(PubKey),
                PubKeyJson = json:decode(BinaryPubKey),
                JwsMap0#{<<"jwk">> => PubKeyJson};
            _ ->
                JwsMap0#{<<"kid">> => iolist_to_binary(AccURL)}
        end,
    JwsObj = jose_jws:from(maps:merge(JwsMap, AlgMap)),
    {_, JoseJSON} = jose_jws:sign(PrivKey, Data, JwsObj),
    encode_json(JoseJSON).

encode_json(JSON) ->
    iolist_to_binary(json:encode(JSON)).

-spec write_priv_key(file:filename(), priv_key()) -> ok | {error, term()}.
write_priv_key(Path, Key) ->
    Type = element(1, Key),
    PemEntry = {Type, public_key:der_encode(Type, Key), not_encrypted},
    case file:write_file(Path, public_key:pem_encode([PemEntry])) of
        ok -> ok;
        {error, Reason} -> {error, {file_error, Reason}}
    end.

-spec read_priv_key_file(file:filename()) -> {ok, priv_key()} | {error, term()}.
read_priv_key_file(Path) ->
    read_priv_key_file(Path, undefined).

-spec read_priv_key_file(file:filename(), undefined | password()) ->
    {ok, priv_key()} | {error, term()}.
read_priv_key_file(Path, Password) ->
    case file:read_file(Path) of
        {ok, PemBin} ->
            decode_pem_to_priv_key(PemBin, Password);
        {error, Reason} ->
            {error, {file_error, Reason}}
    end.

-spec decode_pem_to_priv_key(binary(), undefined | password()) ->
    {ok, priv_key()} | {error, term()}.
decode_pem_to_priv_key(PemBin, Password) ->
    try public_key:pem_decode(PemBin) of
        [{Tag, DER, not_encrypted}] ->
            {ok, public_key:der_decode(Tag, DER)};
        [{_Tag, _DER, _Encrypted} = PemEntry] when Password =/= undefined ->
            try public_key:pem_entry_decode(PemEntry, Password) of
                Decoded ->
                    {ok, Decoded}
            catch
                _:_ ->
                    {error, {bad_key, bad_password}}
            end;
        [{_Tag, _DER, _Encrypted}] ->
            {error, {bad_key, encrypted_key_but_no_password_provided}};
        [] ->
            {error, no_valid_key};
        [_ | _] ->
            {error, multiple_keys_found}
    catch
        C:E ->
            {error, {invalid_pem, {C, E}}}
    end.

-spec read_cert_file(file:filename()) -> {ok, [cert()]} | {error, term()}.
read_cert_file(Path) ->
    case file:read_file(Path) of
        {ok, PemBin} ->
            decode_pem_to_certs(PemBin);
        {error, Reason} ->
            {error, Reason}
    end.

-spec decode_pem_to_certs(binary()) -> {ok, [cert()]} | {error, term()}.
decode_pem_to_certs(PemBin) ->
    try
        DERs = lists:map(
            fun({'Certificate', DER, not_encrypted}) -> DER end,
            public_key:pem_decode(PemBin)
        ),
        {ok, lists:map(fun(DER) -> public_key:pkix_decode_cert(DER, otp) end, DERs)}
    catch
        C:E:Stack ->
            {error, {C, E, Stack}}
    end.
