const {utils} = require("@ping-identity/p14c-js-sdk-core");
const {Http} = require("@ping-identity/p14c-js-sdk-core");
const tokenUtils = require("./tokenUtils");
const TokenManager = require("./tokenManager");

class PingOneAuthClient {
    constructor (config) {
        this.config = config;
        this.config.issuer = "https://pingauthpoc.roundpointmortgage.com/as";
        this.issuer = "https://pingauthpoc.roundpointmortgage.com/as";

        utils.assertValidConfig(config);
        this.http = new Http();
        this.tokenManager = new TokenManager(this.config);
    }

    async signIn () {
        if (!this.config.discoveryConfig) {
            this.config.discoveryConfig = await this.tokenManager.discover();
        }
        this.tokenManager.clear();
        return this.tokenManager.getTokenWithRedirect();
    }

    /**
     * Signing out logged in user with all tokens revocation.
     * @param {object} options with postLogoutRedirectUri:
     *                     revokeToken:
     *                     idToken:
     *                     state:
     */
    async signOut (options) {
        // eslint-disable-next-line no-param-reassign
        options = options || {};

        let accessToken = options.accessToken;
        let refreshToken = options.refreshToken;
        const revokeToken = options.revokeToken || this.config.revokeToken || false;

        if (revokeToken && typeof accessToken === "undefined") {
            accessToken = await this.tokenManager.get("accessToken");
        }
        if (revokeToken && typeof refreshToken === "undefined") {
            refreshToken = await this.tokenManager.get("refreshToken");
        }

        if (revokeToken && accessToken) {
            await this.revokeToken(accessToken, "accessToken");
        }
        if (revokeToken && refreshToken) {
            await this.revokeToken(refreshToken, "refreshToken");
        }

        let idToken = options.idToken;
        if (typeof idToken === "undefined") {
            idToken = await this.tokenManager.get("idToken");
        }
        if (!idToken) {
            // eslint-disable-next-line max-len
            throw new Error("There is no id token to make a hint about the user's current or past authenticated session.");
        }
        const idTokenHint = idToken.idToken;

        if (!this.config.discoveryConfig) {
            this.config.discoveryConfig = await this.tokenManager.discover();
        }
        let logoutUri = `${this.config.discoveryConfig.end_session_endpoint}?id_token_hint=${encodeURIComponent(
            idTokenHint)}`;

        const postLogoutRedirectUri = options.postLogoutRedirectUri ||
            this.config.postLogoutRedirectUri;
        if (postLogoutRedirectUri) {
            logoutUri = `${logoutUri}&post_logout_redirect_uri=${encodeURIComponent(postLogoutRedirectUri)}`;
        }

        const state = options.state;
        // State allows option parameters to be passed to logout redirect uri
        if (state) {
            logoutUri = `${logoutUri}&state=${encodeURIComponent(state)}`;
        }

        // Clear all local tokens
        this.tokenManager.clear();

        window.location.assign(logoutUri);
    }

    async revokeToken (token, tokenName) {
        if (!token) {
            // eslint-disable-next-line no-param-reassign
            token = await this.tokenManager.get(tokenName);
        }
        // In case token has been removed already
        if (!token) {
            return;
        }
        return this.tokenManager.revokeToken(token);
    }

    /**
     * Parse window url to get all tokens either from implicit flow or authorization code with PKCE
     * @param {{url: *, pkce: *}} options to parse with
     * @returns {object} parsed tokens in a form of tokens.tokens.[idToken or accessToken or refreshToken]
     */
    async parseRedirectUrl (options) {
        const accessToken = await this.tokenManager.get("accessToken");
        // If access token wasn't found, then try to parse it from the current URL
        const url = options && options.url ? options.url : window.location.href;
        if (!accessToken ||
            (url.indexOf("code=") > 0 || url.indexOf("access_token=") > 0 || url.indexOf("error=") > 0)) {
            // Parse the authorization code from the URL fragment and exchange it for tokens
            // Or get and store tokens from the URL if this is an implicit flow
            return this.tokenManager.parseRedirectUrl(options);
        } else {
            const idToken = await this.tokenManager.get("idToken");
            const refreshToken = await this.tokenManager.get("refreshToken");
            return {
                tokens: {
                    accessToken: accessToken,
                    idToken: idToken,
                    refreshToken: refreshToken

                }
            };
        }
    }

    /**
     * Get user information from OIDC userinfo endpoint.
     * @returns {object} user information json
     */
    async getUserInfo () {
        const accessTokenObject = await this.tokenManager.get("accessToken");
        const idTokenObject = await this.tokenManager.get("idToken");

        if (!accessTokenObject || (!tokenUtils.isToken(accessTokenObject) &&
                !accessTokenObject.accessToken && !accessTokenObject.userinfoUrl)) {
            throw new Error("Access token is missing to retrieve user information.");
        }

        if (!idTokenObject || (!tokenUtils.isToken(idTokenObject) && !idTokenObject.idToken)) {
            throw new Error("Id token is missing to retrieve user information.");
        }

        const userInfo = await this.http
            .getJson(accessTokenObject.userinfoUrl, {accessToken: accessTokenObject.accessToken});
        // Only return the userinfo response if subjects match to mitigate token substitution attacks
        if (userInfo.sub === idTokenObject.claims.sub) {
            return userInfo;
        } else {
            throw new Error("User information response subject claim didn't match to id token subject claim");
        }
    }
}

module.exports = PingOneAuthClient;
