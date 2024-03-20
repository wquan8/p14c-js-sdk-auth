const {utils} = require("@ping-identity/p14c-js-sdk-core");
const tokenUtils = require("./tokenUtils");
const PKCEManager = require("./pkceManager");
const {Http} = require("@ping-identity/p14c-js-sdk-core");
const CookiesStorageManager = require("./cookiesStorageManager");
const TokenStorageManager = require("./tokenStorageManager");
const JwtVerifier = require("@ping-identity/p14c-js-sdk-jwt");

class TokenManager {
    constructor (config) {
        this.config = Object.assign(
            {
                tokenRenew: true,
                storage: "localStorage"
            },
            config
        );
        this.config.jwksUri = `${this.config.issuer}/jwks`;
        this.jwtVerifier = new JwtVerifier(this.config.jwksUri);
        this.cookiesStorage = new CookiesStorageManager(config.cookies);
        this.pkce = new PKCEManager(this);
        this.http = new Http();
        this.tokenStorageManager = new TokenStorageManager(this.config);
    }

    /**
     * Get a valid token stored in token storage.
     * If token is expired - renew it in case `tokenRenew` is set to true.
     * @param {string} key the value is stored with
     * @returns {object} stored key value, or nothing - if no token is found
     */
    async get (key) {
        const token = this.tokenStorageManager.get(key);
        if (token) {
            if (!tokenUtils.hasExpired(token)) {
                return token;
            } else {
                return this.config.tokenRenew
                    ? this.renewToken(token)
                    : this.tokenStorageManager.remove(key);
            }
        }
    }

    add (key, token) {
        if (!utils.isObject(token)) {
            throw new Error("The token must be an object.");
        }
        this.tokenStorageManager.add(key, token);
    }

    clear () {
        this.tokenStorageManager.clear();
    }

    async getTokenWithRedirect () {
        await this.checkDiscoveryConfig();
        const authParams = await this.prepareAuthParams();

        const endpoint = authParams.codeChallenge ? this.config.discoveryConfig.token_endpoint
            : this.config.discoveryConfig.authorization_endpoint;
        const requestUrl = this.config.discoveryConfig.authorization_endpoint + this.buildAuthorizeParams(authParams);

        this.setCookies(authParams, endpoint);

        window.location.assign(requestUrl);
    }

    async checkDiscoveryConfig () {
        if (!this.config.discoveryConfig) {
            this.config.discoveryConfig = await this.discover();
        }
        return this.config.discoveryConfig;
    }

    setCookies (authParams, endpoint) {
        // Set session cookie to store the authParams
        this.cookiesStorage.set(
            "pingone-oauth-params",
            JSON.stringify({
                responseType: authParams.responseType,
                state: authParams.state,
                nonce: authParams.nonce,
                scopes: authParams.scopes,
                clientId: authParams.clientId,
                tokenEndpoint: endpoint,
                userinfoUrl: this.config.discoveryConfig.userinfo_endpoint
            }),
            null,
            this.config.cookies
        );

        // Set nonce cookie for servers to validate nonce in id_token
        this.cookiesStorage.set(
            "pingone-oauth-nonce",
            authParams.nonce,
            null,
            this.config.cookies
        );

        // Set state cookie for servers to validate state
        this.cookiesStorage.set(
            "pingone-oauth-state",
            authParams.state,
            null,
            this.config.cookies
        );
    }

    async getTokenWithRefreshToken (authParams, refreshToken) {
        await this.checkDiscoveryConfig();
        const params = utils.removeNils({
            "client_id": authParams.clientId,
            "redirect_uri": authParams.redirectUri,
            "response_type": authParams.responseType,
            "grant_type": "refresh_token",
            "refresh_token": refreshToken.value
        });
        // Encode OAuth params as URL string
        const data = utils.objectToURIQuery(params).slice(1);
        const response = await this.http.post(this.config.discoveryConfig.token_endpoint, {
            body: data,
            withCredentials: false,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });
        const tokensResponse = await response.json();
        const tokenDict = await this.parseTokenResponse(tokensResponse, tokensResponse.scopes,
            this.config.discoveryConfig.token_endpoint, this.config.discoveryConfig.userinfo_endpoint);
        this.storeTokens(tokenDict);
        return {
            tokens: tokenDict
        };
    }

    /**
     * Get token in hidden iframe considering the user is still present for the current session.
     * So the user is not prompted to login to re-authenticate, which can result in an error if authentication is required
     * @param {object} authParams authentication parameters
     * @returns {Promise<{code: *, tokens: *, state: *}>} tokens response
     */
    async getTokenWithIFrame (authParams) {
        await this.checkDiscoveryConfig();
        this.checkIframeLocation(window.location.origin);
        const loginParams = Object.assign({
            prompt: "none"
        }, authParams);
        const requestUrl = this.config.discoveryConfig.authorization_endpoint + this.buildAuthorizeParams(loginParams);
        this.setCookies(loginParams, this.config.discoveryConfig.token_endpoint);
        const codeResponse = await tokenUtils.runIframe(requestUrl, this.config.issuer, 12);
        const codeResult = utils.urlParamsToObject(codeResponse);
        const tokens = await this.handleAuthenticationResponse(loginParams, codeResult,
            this.config.discoveryConfig.token_endpoint);
        this.storeTokens(tokens.tokens);
        return tokens;
    }

    /**
     * Build authentication params using defaults + options
     * @param {object} options additional authentication params
     * @returns {Promise<{redirectUri: *, max_age, responseMode, responseType: string[], clientId, acr_values, pkce: boolean, state, scopes: (*|[string]), useRefreshTokens: boolean, nonce}|{codeChallenge: *}>} authentication params
     */
    async prepareAuthParams (options) {
        const responseType = (options !== undefined && options.responseType !== undefined) ? options.responseType
            : (this.config.responseType ? this.config.responseType : ["token", "id_token"]);
        const scopes = (options !== undefined && options.scopes !== undefined) ? options.scopes
            : (this.config.scopes ? this.config.scopes : ["openid"]);
        const pkce = (options !== undefined && options.pkce !== undefined) ? options.pkce
            : this.isPKCE();

        if (scopes.indexOf("openid") === -1) {
            scopes.push("openid");
        }
        const oauthParams = utils.removeNils({
            useRefreshTokens: this.config.useRefreshTokens,
            pkce: pkce,
            clientId: this.config.clientId,
            redirectUri: this.config.redirectUri || window.location.href,
            responseType: responseType,
            responseMode: this.config.responseMode,
            codeChallengeMethod: this.config.codeChallengeMethod,
            state: tokenUtils.generateState(),
            nonce: tokenUtils.generateNonce(),
            "max_age": this.config.max_age,
            "acr_values": this.config.acr_values,
            scopes: scopes
        });

        if (pkce === false) {
            return oauthParams;
        } else {
            return this.pkce.prepareAuthParams(oauthParams);
        }
    }

    transformAuthParams (authParams) {
        if (utils.isString(authParams.responseType) && authParams.responseType.indexOf(" ") !== -1) {
            throw new Error("Multiple OAuth responseTypes must be defined as an array");
        }

        // Convert our params to their actual OAuth equivalents
        const oauthQueryParams = utils.removeNils({
            "client_id": authParams.clientId,
            "code_challenge": authParams.codeChallenge,
            "code_challenge_method": authParams.codeChallengeMethod,
            "login_hint": authParams.loginHint,
            "max_age": authParams.maxAge,
            nonce: authParams.nonce,
            prompt: authParams.prompt,
            "redirect_uri": authParams.redirectUri,
            "response_mode": authParams.responseMode,
            "response_type": authParams.responseType,
            state: authParams.state
        });

        if (Array.isArray(oauthQueryParams.response_type)) {
            // eslint-disable-next-line camelcase
            oauthQueryParams.response_type = oauthQueryParams.response_type.join(" ");
        }

        if (oauthQueryParams.response_type.indexOf("id_token") !== -1 &&
            authParams.scopes.indexOf("openid") === -1) {
            throw new Error("openid scope must be specified in the scopes argument when requesting an id_token");
        } else {
            oauthQueryParams.scope = authParams.scopes.join(" ");
        }

        return oauthQueryParams;
    }

    buildAuthorizeParams (authParams) {
        return utils.objectToURIQuery(this.transformAuthParams(authParams));
    }

    async exchangeCodeForToken (authParams, authorizationCode, tokenEndpoint) {
        // PKCE authorization_code flow
        // Retrieve saved values and build authParams for call to /token
        const meta = this.pkce.loadData();
        const getTokenParams = {
            clientId: authParams.clientId,
            authorizationCode: authorizationCode,
            codeVerifier: meta.codeVerifier,
            redirectUri: meta.redirectUri
        };
        const tokensResponse = await this.pkce.getToken(getTokenParams, tokenEndpoint);
        this.validateAuthResponse(tokensResponse, getTokenParams);
        this.pkce.clearData();
        return tokensResponse;
    }

    validateAuthResponse (response, authParams) {
        if (response && (response.error || response.error_description)) {
            throw new Error(`Authentication error: ${response.error}, \n ${response.error_description}`);
        }

        if (response && (response.state !== authParams.state)) {
            throw new Error("OAuth 2.0 response state doesn't match request state");
        }
    }

    async handleAuthenticationResponse (authParams, authResponse, tokenEndpoint) {
        let responseType = authParams.responseType;
        if (!Array.isArray(responseType)) {
            responseType = [responseType];
        }

        this.validateAuthResponse(authResponse, authParams);

        // Get tokens response via PKCE flow if is defined so
        let response = {...authResponse};
        if (authResponse.code && this.isPKCE()) {
            responseType = ["token", "id_token"]; // what we expect the code to provide us
            response = await this.exchangeCodeForToken(authParams, authResponse.code, tokenEndpoint);
        }

        await this.checkDiscoveryConfig();
        const tokenDict = await this.parseTokenResponse(response, authParams.scopes,
            tokenEndpoint, this.config.discoveryConfig.userinfo_endpoint);
        return this.validateTokenResponse(responseType, tokenDict, response);
    }

    /**
     * Validate received tokens against requested response types
     * @param {array} responseType tokens response type
     * @param {object} tokens retrieved tokens
     * @param {object} response tokens response
     * @returns {{code: *, tokens: *, state: *}} enriched tokens response
     */
    validateTokenResponse (responseType, tokens, response) {
        if (responseType.indexOf("token") !== -1 && !tokens.accessToken) {
            throw new Error('Response type "token" was requested but "access_token" was not returned.');
        }
        if (responseType.indexOf("id_token") !== -1 && !tokens.idToken) {
            throw new Error('Response type "id_token" was requested but "id_token" was not returned.');
        }

        return {
            tokens: tokens,
            state: response.state,
            code: response.code
        };
    }

    checkIframeLocation (iframeOrigin) {
        if (window.location.search.indexOf("error=") > 0) {
            const errorResponse = utils.urlParamsToObject(window.location.search);
            window.parent.postMessage(errorResponse, iframeOrigin);
            throw new Error(`Authentication error: ${errorResponse.error}, \n ${errorResponse.error_description}`);
        }
        if (utils.isInIframe()) {
            let paramStr;
            if (this.isPKCE()) {
                paramStr = window.location.search;
            } else {
                paramStr = window.location.hash;
            }
            if (paramStr.indexOf("code=") > 0 || paramStr.indexOf("access_token=") > 0) {
                parent.postMessage(paramStr, window.location.origin);
            }
        }
    }

    async parseTokenResponse (response, scopes, tokenEndpoint, userInfoEndpoint) {
        const tokenDict = {};
        const expiresIn = response.expires_in;
        const tokenType = response.token_type;
        const accessToken = response.access_token;
        const idToken = response.id_token;
        const refreshToken = response.refresh_token;
        let tokenScopes = scopes;

        if (utils.isObject(scopes)) {
            tokenScopes = Object.values(scopes);
        }

        if (accessToken) {
            tokenDict.accessToken = {
                value: accessToken,
                accessToken: accessToken,
                expiresAt: Number(expiresIn) + Math.floor(Date.now() / 1000),
                tokenType: tokenType,
                scopes: tokenScopes,
                tokenEndpoint: tokenEndpoint,
                userinfoUrl: userInfoEndpoint
            };
        }

        if (refreshToken) {
            tokenDict.refreshToken = {
                value: refreshToken,
                accessToken: accessToken,
                expiresAt: Number(expiresIn) + Math.floor(Date.now() / 1000),
                tokenType: tokenType,
                scopes: tokenScopes,
                tokenEndpoint: tokenEndpoint,
                userinfoUrl: userInfoEndpoint
            };
        }

        if (idToken && await this.jwtVerifier.validateToken(idToken, this.config.clientId, this.config.issuer)) {
            const idPayload = this.jwtVerifier.getIdTokenPayload(idToken);
            tokenDict.idToken = {
                value: idToken,
                idToken: idToken,
                claims: idPayload,
                expiresAt: idPayload.exp,
                scopes: tokenScopes
            };
        }

        return tokenDict;
    }

    storeTokens (tokens) {
        if (tokens.idToken) {
            this.add("idToken", tokens.idToken);
        }
        if (tokens.accessToken) {
            this.add("accessToken", tokens.accessToken);
        }
        if (tokens.refreshToken) {
            this.add("refreshToken", tokens.refreshToken);
        }
    }

    /**
     * If refresh tokens are used, the token endpoint is called directly with the
     * 'refresh_token' grant.
     *
     * If no refresh token is available to make this call -
     * fall back to using an iframe to the '/authorize' URL using the parameters provided
     * as arguments.
     * @param {object} token the token to renew
     * @returns {object} idToken or accessToken
     */
    async renewToken (token) {
        let responseType;
        if (this.isPKCE()) {
            responseType = "code";
        } else if (token.accessToken) {
            responseType = "token";
        } else {
            responseType = "id_token";
        }

        const options = {
            responseType: responseType,
            scopes: token.scopes
        };
        const oauthParams = await this.prepareAuthParams(options);

        let tokensResp;
        const refreshToken = this.tokenStorageManager.get("refreshToken");
        if (oauthParams.useRefreshTokens && refreshToken && !tokenUtils.hasExpired(refreshToken)) {
            tokensResp = await this.getTokenWithRefreshToken(oauthParams, refreshToken);
        } else {
            tokensResp = await this.getTokenWithIFrame(oauthParams);
        }

        // Return only the token which was requested
        const tokens = tokensResp.tokens;
        return token.idToken ? tokens.idToken : tokens.accessToken;
    }

    /**
     * Revokes all access tokens for the session and application combination. A token must have an associated session (sid) claim to be revoked.
     *  If you revoke a refresh token, it also revokes all associated access tokens to that specific session and application combination.
     * It uses the same authentication method as the POST /{environmentId}/as/token endpoint, and uses the value from the application's tokenEndpointAuthMethod to determine the configuration.
     * @param {object} token the token to revoke
     * @returns {object} If the authentication method is accepted, and the token contains the necessary iat and sid claims, the response returns a 200 code with an empty body.
     * If the token is invalid or if the token does not include the necessary iat and sid claims, an unsupported_token_type error is returned as directed in OAuth 2.0 Token Revocation RFC7009 (section 2.2.1).
     * If the aud claim identifies a platform token, an unsupported_token_type error response is returned.
     * @see https://apidocs.pingidentity.com/pingone/platform/v1/api/#post-token-revocation
     */
    async revokeToken (token) {
        if (!token || !token.accessToken) {
            throw new Error("A valid access token object is required");
        }
        const clientId = this.config.clientId;
        if (!clientId) {
            throw new Error("A clientId must be specified in the PingOneAuthClient constructor to revoke a token");
        }

        await this.checkDiscoveryConfig();
        const revokeUrl = this.config.discoveryConfig.revocation_endpoint;
        const accessToken = token.accessToken;
        const creds = btoa(clientId);
        const request = {
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Authorization: `Basic ${creds}`
            },
            body: utils.objectToURIQuery({ token: accessToken }).slice(1)
        };
        return this.http.post(revokeUrl, request);
    }

    /**
     * Parse given url or window.location and get all tokens either from implicit or auth. code with PKCE flows
     * @param {{url: *, pkce: *}} options like url - to parse; pkce - if the flow is auth. code with PKCE
     * @returns {{code: *, tokens: *, state: *}} parsed code, tokens and state
     */
    async parseRedirectUrl (options) {
        // eslint-disable-next-line no-param-reassign
        options = options || {};

        const url = options.url;
        let paramStr;
        const pkce = (options && options.pkce) ? options.pkce : this.isPKCE();
        if (pkce) {
            paramStr = url ? url.substring(url.indexOf("?")) : window.location.search;
        } else {
            paramStr = url ? url.substring(url.indexOf("#")) : window.location.hash;
        }
        this.checkIframeLocation(window.location.origin);

        if (!paramStr) {
            // No tokens in current url
            return;
        }

        const oauthParamsCookie = this.cookiesStorage.get("pingone-oauth-params");
        if (!oauthParamsCookie) {
            throw new Error("Unable to retrieve 'pingone-oauth-params' cookie.");
        }

        const oauthParams = JSON.parse(oauthParamsCookie);
        const tokenEndpoint = oauthParams.tokenEndpoint;
        try {
            Reflect.deleteProperty(oauthParams, tokenEndpoint);
            this.cookiesStorage.delete("pingone-oauth-params");
        } catch (e) {
            throw new Error(`Unable to parse the 'pingone-oauth-params' cookie: ${e.message}`);
        }

        const res = utils.urlParamsToObject(paramStr);
        if (!url) {
            // Clean hash or search from the url
            tokenUtils.removeHash();
        }
        // Get and store tokens
        const tokens = await this.handleAuthenticationResponse(oauthParams, res, tokenEndpoint);
        this.storeTokens(tokens.tokens);
        return tokens;
    }

    isPKCE () {
        return this.config.pkce !== undefined ? this.config.pkce : true;
    }

    async discover () {
        return this.http.getJson(
            `${this.config.issuer}/.well-known/openid-configuration`,
            null,
            false
        );
    }
}

module.exports = TokenManager;
