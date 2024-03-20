const TokenManager = require("../src/tokenManager.js");

describe("PingOne TokenManager test", function () {
    let tokenManager;
    let originalLocation;

    const clientId = "fdd997b0-dd57-11ea-87d0-0242ac130003";
    const accessTokenContent = "someAccessToken";
    const userinfoEndpoint = "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/userinfo";
    const accessToken = {
        accessToken: accessTokenContent,
        expiresAt: 1597395016,
        scopes: [
            "custom",
            "openid"
        ],
        tokenEndpoint: "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/token",
        tokenType: "Bearer",
        userinfoUrl: userinfoEndpoint,
        value: accessTokenContent
    };
    const idToken = {
        claims: "someIdTokenPayload",
        idToken: "someIdToken",
        scopes: [
            "custom",
            "openid"
        ],
        value: "someIdToken"
    };

    const refreshToken = {
        value: "refreshToken",
        expiresAt: 1597395016
    };
    const scopes = [
        "custom",
        "newCustom",
        "openid"
    ];
    const state = "abc";
    const authParams = {
        responseType: ["id_token", "token"],
        scopes: scopes,
        state: state
    };

    const revocationEndpoint = "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/revoke";
    const config = {
        environmentId: "11c22fc5-11ab-111a-811e-1149b4b917e9",
        clientId: clientId,
        pkce: false
    };

    afterEach(() => {
        global.window.location = originalLocation;
        jest.clearAllMocks();
    });

    beforeEach(() => {
        tokenManager = new TokenManager(config);
        // mock window.location so we appear to be on an HTTPS origin
        originalLocation = global.window.location;
        delete global.window.location;
        global.window.location = {
            protocol: "https:",
            hostname: "somesite.com",
            href: "https://somesite.com",
            search: "",
            assign: jest.fn()
        };

        jest.spyOn(Date, "now").mockReturnValue(1597391416227);

        jest.spyOn(TokenManager.prototype, "discover").mockImplementation(function () {
            return {
                "issuer": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as",
                "authorization_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/authorize",
                "token_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/token",
                "userinfo_endpoint": userinfoEndpoint,
                "jwks_uri": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/jwks",
                "end_session_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/signoff",
                "introspection_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/introspect",
                "revocation_endpoint": revocationEndpoint,
                "claims_parameter_supported": true,
                "request_parameter_supported": false,
                "request_uri_parameter_supported": false,
                "scopes_supported": ["openid", "profile", "email", "address", "phone"],
                "response_types_supported": ["code", "id_token", "token id_token"],
                "response_modes_supported": ["fragment", "query"],
                "grant_types_supported": ["authorization_code", "implicit", "client_credentials", "refresh_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "userinfo_signing_alg_values_supported": ["none"],
                "request_object_signing_alg_values_supported": ["none"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                "claim_types_supported": ["normal"],
                "claims_supported": ["sub", "iss", "auth_time", "acr", "name", "given_name", "family_name",
                    "middle_name", "preferred_username", "profile", "picture", "zoneinfo", "phone_number",
                    "updated_at", "address", "email", "locale"],
                "code_challenge_methods_supported": ["plain", "S256"]
            };
        });
    });

    describe("Token manipulation", function () {
        it("get tokens from url", async function () {
            const urlWithHash = Object.assign({
                hash: "#access_token=someAccessToken&token_type=Bearer&expires_in=3600&scope=openid email&id_token=someIdToken"
            }, global.window.location);
            delete global.window.location;
            global.window.location = urlWithHash;


            jest.spyOn(tokenManager.cookiesStorage, "get").mockImplementation(key => {
                return JSON.stringify({
                    responseType: ["token", "id_token"],
                    scopes: ["custom", "openid"],
                    clientId: clientId,
                    tokenEndpoint: "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/token"
                });
            });

            jest.spyOn(tokenManager.jwtVerifier, "validateToken").mockImplementation(() => true);
            jest.spyOn(tokenManager.jwtVerifier, "getIdTokenPayload").mockImplementation(() => "someIdTokenPayload");

            const redirectUrl = await tokenManager.parseRedirectUrl();

            expect(redirectUrl).toEqual({
                tokens: {
                    accessToken: accessToken,
                    idToken: idToken
                }
            }
            );
        });

        it("renew id token with iframe", async function () {
            const mockPrepareAuthParams = jest.spyOn(tokenManager, "prepareAuthParams");
            const mockGettingTokenWithIFrame = jest.spyOn(tokenManager, "getTokenWithIFrame").mockReturnValue({
                tokens: {
                    accessToken: accessToken,
                    idToken: idToken
                }
            });

            const renewedToken = await tokenManager.renewToken({
                claims: "oldIdTokenClaims",
                idToken: "oldIdToken",
                scopes: scopes,
                value: "oldIdToken"
            });

            expect(mockGettingTokenWithIFrame).toBeCalled();
            expect(mockPrepareAuthParams).toHaveBeenCalledWith({responseType: "id_token", scopes: scopes});
            expect(renewedToken).toEqual(idToken);
        });

        it("renew id token with refresh token", async function () {
            const authParamsWithRefreshToken = {
                accessToken: accessToken,
                useRefreshTokens: true
            };
            const mockGettingRefreshTokenFromStorage = jest.spyOn(tokenManager.tokenStorageManager, "get")
                .mockReturnValue(refreshToken);
            const mockPrepareAuthParams = jest.spyOn(tokenManager, "prepareAuthParams")
                .mockReturnValue(authParamsWithRefreshToken);
            const mockGettingTokenWithRefreshToken = jest.spyOn(tokenManager, "getTokenWithRefreshToken")
                .mockReturnValue({
                    tokens: {
                        accessToken: accessToken,
                        idToken: idToken
                    }
                });


            const renewedToken = await tokenManager.renewToken({
                claims: "oldIdTokenClaims",
                idToken: "oldIdToken",
                scopes: ["openid"],
                value: "oldIdToken"
            });

            expect(mockGettingRefreshTokenFromStorage).toBeCalled();
            expect(mockPrepareAuthParams).toBeCalled();
            expect(mockGettingTokenWithRefreshToken).toBeCalled();
            expect(renewedToken).toEqual(idToken);
        });

        it("revoke the token", async function () {
            const mockHttpPost = jest.spyOn(tokenManager.http, "post").mockReturnValue(Promise.resolve());
            const request = {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    Authorization: `Basic ${btoa(clientId)}`
                },
                body: `token=${accessTokenContent}`
            };

            await tokenManager.revokeToken(accessToken);

            expect(mockHttpPost).toHaveBeenCalledWith(revocationEndpoint, request);
        });

        it("handle authentication response within implicit flow", async function () {
            const expectedTokens = {
                accessToken: accessToken,
                idToken: idToken,
                refreshToken: refreshToken
            };
            const authResponse = {
                state: "abc"
            };
            const tokenEndpoint = "tokenEndpoint";
            const mockValidateAuthResponse = jest.spyOn(tokenManager, "validateAuthResponse")
                .mockImplementation(() => jest.fn());
            const mockValidateTokenResponse = jest.spyOn(tokenManager, "validateTokenResponse")
                .mockReturnValue({
                    tokens: expectedTokens,
                    state: authResponse.state
                });
            // Mock response with parsed tokens
            const mockParseTokenResponse = jest.spyOn(tokenManager, "parseTokenResponse")
                .mockReturnValue({
                    tokens: expectedTokens
                });

            const tokens = await tokenManager.handleAuthenticationResponse(authParams, authResponse, tokenEndpoint);

            expect(mockValidateAuthResponse).toHaveBeenCalledWith(authResponse, authParams);
            expect(mockParseTokenResponse).toHaveBeenCalledWith(authResponse, scopes, tokenEndpoint, userinfoEndpoint);
            expect(mockValidateTokenResponse).toHaveBeenCalledWith(["id_token", "token"], {
                tokens: expectedTokens
            }, authResponse);
            expect(tokens).toEqual({
                tokens: expectedTokens,
                state: authResponse.state
            });
        });

        it("handle authentication response within PKCE flow", async function () {
            const expectedTokens = {
                accessToken: accessToken,
                idToken: idToken,
                refreshToken: refreshToken
            };
            const authResponse = {
                state: state,
                code: "efg"
            };
            const tokenEndpoint = "tokenEndpoint";

            tokenManager = new TokenManager({
                config,
                ...{pkce: true}
            });

            // Mock auth response validation
            const mockValidateAuthResponse = jest.spyOn(tokenManager, "validateAuthResponse")
                .mockImplementation(() => jest.fn());

            const exchangeCodeResponse = {
                "access_token": accessTokenContent,
                "id_token": "someIdTokenContent,",
                "expires_in": 3600,
                "refresh_token": "someRefreshTokenContent,",
                scope: scopes.join(" "),
                "token_type": "Bearer"
            };
            // Mock token exchange request
            const mockExchangeCodeForToken = jest.spyOn(tokenManager, "exchangeCodeForToken")
                .mockReturnValue(exchangeCodeResponse);

            // Mock token response validation
            const mockValidateTokenResponse = jest.spyOn(tokenManager, "validateTokenResponse")
                .mockReturnValue({
                    tokens: expectedTokens,
                    state: authResponse.state,
                    code: authResponse.code
                });

            // Mock token response parsing
            const mockParseTokenResponse = jest.spyOn(tokenManager, "parseTokenResponse")
                .mockReturnValue({
                    tokens: expectedTokens
                });

            const tokens = await tokenManager.handleAuthenticationResponse(authParams, authResponse, tokenEndpoint);

            expect(mockExchangeCodeForToken).toHaveBeenCalledWith(authParams, "efg", tokenEndpoint);
            expect(mockValidateAuthResponse).toHaveBeenCalledWith(authResponse, authParams);
            expect(mockParseTokenResponse).toHaveBeenCalledWith(exchangeCodeResponse, scopes, tokenEndpoint, userinfoEndpoint);
            expect(mockValidateTokenResponse).toHaveBeenCalledWith(["token", "id_token"],
                {tokens: expectedTokens}, exchangeCodeResponse);
            expect(tokens).toEqual({
                code: authResponse.code,
                tokens: expectedTokens,
                state: authResponse.state
            });
        });
    });
});
