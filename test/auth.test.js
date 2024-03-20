const PingOneAuthClient = require("../src/auth.js");
const tokenUtils = require("../src/tokenUtils.js");
const TokenManager = require("../src/tokenManager.js");
const PKCEManager = require("../src/pkceManager.js");

describe("PingOne Auth client test", function () {
    let authClient;
    const clientId = "fdd997b0-dd57-11ea-87d0-0242ac130003";
    const config = {
        environmentId: "11c22fc5-11ab-111a-811e-1149b4b917e9",
        clientId: clientId
    };

    beforeEach(() => {
        authClient = new PingOneAuthClient(config);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe("PingOne Auth client construction", function () {
        it("Invalid client ID", function () {
            try {
                authClient = new PingOneAuthClient({
                    environmentId: "11c22fc5-11ab-111a-811e-1149b4b917e9",
                    clientId: "invalid"
                });
            } catch (e) {
                expect(e.message).toEqual("Invalid client ID, it should be a valid UUID. Current value: invalid.");
            }
        });
        it("Invalid environment ID", function () {
            try {
                authClient = new PingOneAuthClient({
                    environmentId: "invalid",
                    clientId: "11c22fc5-11ab-111a-811e-1149b4b917e9"
                });
            } catch (e) {
                expect(e.message).toEqual("Invalid environment ID, it should be a valid UUID. Current value: invalid.");
            }
        });
    });

    describe("Sign in/Sign out with PingOne Auth client ", function () {
        let originalLocation;
        afterEach(() => {
            global.window.location = originalLocation;
        });

        beforeEach(function () {
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

            jest.spyOn(tokenUtils, "generateState").mockImplementation(function () {
                return "abcd";
            });
            jest.spyOn(tokenUtils, "generateNonce").mockImplementation(function () {
                return "efg";
            });

            jest.spyOn(TokenManager.prototype, "discover").mockImplementation(function () {
                return {
                    "issuer": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as",
                    "authorization_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/authorize",
                    "token_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/token",
                    "userinfo_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/userinfo",
                    "jwks_uri": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/jwks",
                    "end_session_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/signoff",
                    "introspection_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/introspect",
                    "revocation_endpoint": "https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/revoke",
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
        }
        );

        describe("Sign in with PingOne Auth client ", function () {
            it("successful redirect URL within implicit flow", async function () {
                const windowLocationMock = jest.spyOn(window.location, "assign");
                authClient = new PingOneAuthClient({
                    pkce: false,
                    ...config});
                await authClient.signIn();

                expect(windowLocationMock).toHaveBeenCalledWith("https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/authorize?client_id=fdd997b0-dd57-11ea-87d0-0242ac130003&nonce=efg&redirect_uri=https%3A%2F%2Fsomesite.com&response_type=token%20id_token&state=abcd&scope=openid");
            });

            it("successful redirect URL with pkce flow", async function () {
                const windowLocationMock = jest.spyOn(window.location, "assign");

                const isPKCESupported = jest.spyOn(tokenUtils, "isPKCESupported").mockImplementation(() => true);
                const getCodeChallenge = jest.spyOn(PKCEManager.prototype, "getCodeChallenge")
                    .mockImplementation(() => "randomCodeChallenge");
                const getCodeVerifier = jest.spyOn(PKCEManager.prototype, "getCodeVerifier")
                    .mockImplementation(() => "randomCodeVerifier");

                authClient = new PingOneAuthClient(config);
                await authClient.signIn();

                expect(isPKCESupported).toHaveBeenCalled();
                expect(getCodeChallenge).toHaveBeenCalled();
                expect(getCodeVerifier).toHaveBeenCalled();
                expect(windowLocationMock).toHaveBeenCalledWith("https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/authorize?client_id=fdd997b0-dd57-11ea-87d0-0242ac130003&code_challenge=randomCodeChallenge&code_challenge_method=S256&nonce=efg&redirect_uri=https%3A%2F%2Fsomesite.com&response_type=code&state=abcd&scope=openid");
            });

            it("successful redirect URL with token responseType within implicit flow", async function () {
                const windowLocationMock = jest.spyOn(window.location, "assign");
                authClient = new PingOneAuthClient({
                    pkce: false,
                    responseType: ["token"],
                    ...config});
                await authClient.signIn();

                expect(windowLocationMock).toHaveBeenCalledWith("https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/authorize?client_id=fdd997b0-dd57-11ea-87d0-0242ac130003&nonce=efg&redirect_uri=https%3A%2F%2Fsomesite.com&response_type=token&state=abcd&scope=openid");
            });

            it("successful redirect URL with additional scope within implicit flow", async function () {
                const windowLocationMock = jest.spyOn(window.location, "assign");

                authClient = new PingOneAuthClient({
                    pkce: false,
                    scopes: ["custom_scope"],
                    ...config});
                await authClient.signIn();

                expect(windowLocationMock).toHaveBeenCalledWith("https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/authorize?client_id=fdd997b0-dd57-11ea-87d0-0242ac130003&nonce=efg&redirect_uri=https%3A%2F%2Fsomesite.com&response_type=token%20id_token&state=abcd&scope=custom_scope%20openid");
            });
        });

        describe("Sign out with PingOne Auth client ", function () {
            it("successful logout URL without revoking tokens within implicit flow", async function () {
                const windowLocationMock = jest.spyOn(window.location, "assign");
                const tokenManagerClearMock = jest.spyOn(TokenManager.prototype, "clear");

                authClient = new PingOneAuthClient(config);
                await authClient.signOut({
                    idToken: {
                        idToken: "someIdToken"
                    }
                });

                expect(tokenManagerClearMock).toBeCalled();
                expect(windowLocationMock).toHaveBeenCalledWith("https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/signoff?id_token_hint=someIdToken");
            });
            it("successful logout URL with logout redirect Uri", async function () {
                const windowLocationMock = jest.spyOn(window.location, "assign");
                const tokenManagerClearMock = jest.spyOn(TokenManager.prototype, "clear");

                authClient = new PingOneAuthClient(config);
                await authClient.signOut({
                    idToken: {
                        idToken: "someIdToken"
                    },
                    postLogoutRedirectUri: "https://someredirect.com"
                });

                expect(tokenManagerClearMock).toBeCalled();
                expect(windowLocationMock).toHaveBeenCalledWith("https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/signoff?id_token_hint=someIdToken&post_logout_redirect_uri=https%3A%2F%2Fsomeredirect.com");
            });
            it("successful logout URL with state", async function () {
                const windowLocationMock = jest.spyOn(window.location, "assign");
                const tokenManagerClearMock = jest.spyOn(TokenManager.prototype, "clear");

                authClient = new PingOneAuthClient(config);
                await authClient.signOut({
                    idToken: {
                        idToken: "someIdToken"
                    },
                    state: "randomState"
                });
                expect(tokenManagerClearMock).toBeCalled();
                expect(windowLocationMock).toHaveBeenCalledWith("https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/signoff?id_token_hint=someIdToken&state=randomState");
            });

            it("successful logout URL with logout redirect Uri in config", async function () {
                const windowLocationMock = jest.spyOn(window.location, "assign");
                const tokenManagerClearMock = jest.spyOn(TokenManager.prototype, "clear");

                authClient = new PingOneAuthClient({
                    postLogoutRedirectUri: "https://someredirect.com",
                    ...config
                });
                await authClient.signOut({
                    idToken: {
                        idToken: "someIdToken"
                    }
                });

                expect(tokenManagerClearMock).toBeCalled();
                expect(windowLocationMock).toHaveBeenCalledWith("https://auth-staging.pingone.com/11c22fc5-11ab-111a-811e-1149b4b917e9/as/signoff?id_token_hint=someIdToken&post_logout_redirect_uri=https%3A%2F%2Fsomeredirect.com");
            });

            it("failed logout URL without id token hint", async function () {
                authClient = new PingOneAuthClient(config);
                try { await authClient.signOut(); } catch (e) {
                    expect(e.message).toBe(
                        "There is no id token to make a hint about the user's current or past authenticated session.");
                }
            });
        });
    });

    describe("Parse redirect Url with PingOne Auth client ", function () {
        let originalLocation;
        let newLocation;

        afterEach(() => {
            global.window.location = originalLocation;
        });

        beforeEach(function () {
            // mock window.location so we appear to be on an HTTPS origin
            originalLocation = global.window.location;
            delete global.window.location;
            newLocation =
                {
                    protocol: "https:",
                    hostname: "somesite.com",
                    href: "https://somesite.com",
                    search: "",
                    assign: jest.fn()
                };
            global.window.location = newLocation;
        });

        it("get tokens from the storage", async function () {
            authClient = new PingOneAuthClient(config);
            jest.spyOn(authClient.tokenManager, "get").mockImplementation(key => {
                if (key === "accessToken") {
                    return "someAccessToken";
                }
                if (key === "idToken") {
                    return "someIdToken";
                }
                if (key === "refreshToken") {
                    return "someRefreshToken";
                }
            });

            const redirectUrl = await authClient.parseRedirectUrl();
            expect(redirectUrl).toEqual({
                tokens: {
                    accessToken: "someAccessToken",
                    idToken: "someIdToken",
                    refreshToken: "someRefreshToken"
                }
            }
            );
        });
    });
});
