const TokenManager = require("../src/tokenManager");
const PKCE = require("../src/pkceManager");
const tokenUtils = require("../src/tokenUtils");

describe("PKCE manager test", function () {
    let pkce;
    let tokenManager;

    afterEach(() => {
        window.sessionStorage.clear();
        window.localStorage.clear();
        jest.clearAllMocks();
    });

    beforeEach(() => {
        tokenManager = new TokenManager({ issuer: "https://test.com" });
        pkce = new PKCE(tokenManager);
    });

    describe("clear data", () => {
        it("clear data from sessionStorage", () => {
            const meta = { codeVerifier: "fake", redirectUri: "http://test.com/redirect" };
            sessionStorage.setItem("pkce-storage", JSON.stringify(meta));
            jest.spyOn(pkce.tokenManager.tokenStorageManager, "browserHasLocalStorage").mockReturnValue(false);
            expect(pkce.loadData()).toEqual(meta);

            pkce.clearData();
            const res = JSON.parse(window.sessionStorage.getItem("pkce-storage"));
            expect(res).toEqual({});
        });

        it("clear data from localStorage", () => {
            const meta = { codeVerifier: "fake", redirectUri: "http://test.com/redirect" };
            localStorage.setItem("pkce-storage", JSON.stringify(meta));
            expect(pkce.loadData()).toEqual(meta);

            pkce.clearData();
            const res = JSON.parse(window.localStorage.getItem("pkce-storage"));
            expect(res).toEqual({});
        });
    });

    describe("save data", () => {
        it("saves data in sessionStorage", () => {
            const meta = { codeVerifier: "fake", redirectUri: "http://test.com/redirect" };
            jest.spyOn(pkce.tokenManager.tokenStorageManager, "browserHasLocalStorage").mockReturnValue(false);
            pkce.saveData(meta);
            const res = JSON.parse(window.sessionStorage.getItem("pkce-storage"));
            expect(res).toEqual(meta);
        });
        it("saves meta in localStorage", () => {
            const meta = { codeVerifier: "fake", redirectUri: "http://test.com/redirect" };
            pkce.saveData(meta);
            const res = JSON.parse(window.localStorage.getItem("pkce-storage"));
            expect(res).toEqual(meta);
        });
        it("clear old data from storage before save", () => {
            const oldMeta = { codeVerifier: "old", redirectUri: "http://localhost/old" };
            window.localStorage.setItem("pkce-storage", JSON.stringify(oldMeta));

            const meta = { codeVerifier: "fake", redirectUri: "http://test.com/redirect" };

            pkce.saveData(meta);
            expect(JSON.parse(window.localStorage.getItem("pkce-storage"))).toEqual(meta);
        });
    });
    describe("loadMeta", () => {
        it("can return the meta from sessionStorage", () => {
            const meta = { codeVerifier: "fake" };
            window.sessionStorage.setItem("pkce-storage", JSON.stringify(meta));
            jest.spyOn(pkce.tokenManager.tokenStorageManager, "browserHasLocalStorage").mockReturnValue(false);
            const res = pkce.loadData();
            expect(res.codeVerifier).toBe(meta.codeVerifier);
        });
        it("can return the meta from localStorage", () => {
            const meta = { codeVerifier: "fake" };
            window.localStorage.setItem("pkce-storage", JSON.stringify(meta));
            const res = pkce.loadData();
            expect(res.codeVerifier).toBe(meta.codeVerifier);
        });
    });

    describe("prepare oauth params", function () {
        it("throws an error if pkce is true and PKCE is not supported", function () {
            jest.spyOn(tokenUtils, "isPKCESupported").mockReturnValue(false);
            jest.spyOn(tokenUtils, "isHTTPS").mockReturnValue(false);
            jest.spyOn(tokenUtils, "hasTextEncoder").mockReturnValue(true);
            return pkce.prepareAuthParams({
                pkce: true
            })
                .catch(function (e) {
                    expect(e.message).toEqual(
                        "PKCE requires a browser with encryption support running in a secure context. PKCE requires secure HTTPS protocol and the current page is not being served with it.");
                });
        });
        it("throws an error if pkce is true and PKCE is not supported", function () {
            jest.spyOn(tokenUtils, "isPKCESupported").mockReturnValue(false);
            jest.spyOn(tokenUtils, "isHTTPS").mockReturnValue(true);
            jest.spyOn(tokenUtils, "hasTextEncoder").mockReturnValue(false);
            return tokenManager.prepareAuthParams({
                pkce: true
            })
                .catch(function (e) {
                    expect(e.message).toEqual(
                        "PKCE requires a browser with encryption support running in a secure context. PKCE requires TextEncoder and it is not defined in the current page. To use PKCE, you may need to include a polyfill/shim for this browser.");
                });
        });

        describe("prepareAuthParams", function () {
            it('Is set to "code" if pkce is true', async function () {
                jest.spyOn(tokenUtils, "isPKCESupported").mockReturnValue(true);
                jest.spyOn(tokenManager, "checkDiscoveryConfig").mockReturnValue(Promise.resolve({
                    "code_challenge_methods_supported": ["S256"]
                }));

                jest.spyOn(pkce, "getCodeVerifier").mockReturnValue(Promise.resolve());
                jest.spyOn(pkce, "saveData").mockReturnValue(Promise.resolve());
                jest.spyOn(pkce, "getCodeChallenge").mockReturnValue(Promise.resolve());

                const params = await pkce.prepareAuthParams({
                    responseType: "token",
                    pkce: true
                });
                expect(params.responseType).toBe("code");
            });

            it("Checks codeChallengeMethod against well-known", function () {
                jest.spyOn(tokenUtils, "isPKCESupported").mockReturnValue(true);
                jest.spyOn(tokenManager, "checkDiscoveryConfig").mockReturnValue({
                    "code_challenge_methods_supported": []
                });
                return pkce.prepareAuthParams({})
                    .catch(function (e) {
                        expect(e.message).toBe("Invalid code_challenge_method");
                    });
            });
        });


        it("Computes and returns a code challenge", async function () {
            const codeChallengeMethod = "codeChallengeMethod";
            const codeVerifier = "codeVerifier";
            const codeChallenge = "codeChallenge";

            jest.spyOn(tokenUtils, "isPKCESupported").mockReturnValue(true);
            jest.spyOn(tokenManager, "checkDiscoveryConfig").mockReturnValue({
                "code_challenge_methods_supported": [codeChallengeMethod]
            });
            jest.spyOn(pkce, "getCodeVerifier").mockReturnValue(codeVerifier);
            jest.spyOn(pkce, "saveData");
            jest.spyOn(pkce, "getCodeChallenge").mockReturnValue(codeChallenge);
            const oauthParams = await pkce.prepareAuthParams({
                codeChallengeMethod: codeChallengeMethod
            });
            expect(oauthParams.codeChallenge).toBe(codeChallenge);
        });
    });

    describe("getToken", function () {
        describe("getToken", function () {
            it("Throws if no clientId", function () {
                jest.spyOn(pkce, "validateAuthOptions");
                const oauthOptions = {
                    clientId: "llk"
                };
                try {
                    pkce.getToken(oauthOptions, "http://tokenEndpoint");
                } catch (e) {
                    expect(e.message).toBe("A clientId must be specified in the OktaAuth constructor to get a token");
                }
            });
        });

        describe("validateAuthOptions", function () {
            let authOptions;

            beforeEach(function () {
                jest.spyOn(tokenUtils, "isPKCESupported").mockReturnValue(true);

                authOptions = {
                    clientId: "clientId",
                    redirectUri: "redirectUri",
                    authorizationCode: "authorizationCode",
                    codeVerifier: "codeVerifier"
                };
            });

            it("Get token", function () {
                const httpRequst = jest.spyOn(pkce.http, "post").mockImplementation();
                const getPostData = jest.spyOn(pkce, "getPostData").mockImplementation();
                pkce.getToken(authOptions, "http://tokenEndpoint");
                expect(httpRequst).toHaveBeenCalled();
                expect(getPostData).toHaveBeenCalledWith(authOptions);
            });

            it("Throws if no clientId", function () {
                authOptions.clientId = undefined;
                try {
                    pkce.validateAuthOptions(authOptions);
                } catch (e) {
                    expect(e.message).toBe("A clientId must be present to get the token.");
                }
            });

            it("Throws if no redirectUri", function () {
                authOptions.redirectUri = undefined;
                try {
                    pkce.validateAuthOptions(authOptions);
                } catch (e) {
                    expect(e.message).toBe("A redirectUri must be present to get the token.");
                }
            });

            it("Throws if no authorizationCode", function () {
                authOptions.authorizationCode = undefined;
                try {
                    pkce.validateAuthOptions(authOptions);
                } catch (e) {
                    expect(e.message)
                        .toBe("An authorization code returned from /authorize must be present to get the token.");
                }
            });

            it("Throws if no codeVerifier", function () {
                authOptions.codeVerifier = undefined;
                try {
                    pkce.validateAuthOptions(authOptions);
                } catch (e) {
                    expect(e.message)
                        .toBe('The "codeVerifier" generated by your app must be present to get the token.');
                }
            });
        });
    });
});
