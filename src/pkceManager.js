const {Http} = require("@ping-identity/p14c-js-sdk-core");
const {utils} = require("@ping-identity/p14c-js-sdk-core");
const tokenUtils = require("./tokenUtils");

class PKCEManager {
    constructor (tokenManager) {
        this.http = new Http();
        this.tokenManager = tokenManager;
    }

    getCodeVerifier (prefix) {
        let verifier = prefix || "";
        // Code verifier will be a random URL-safe string with a minimum length of 43 characters.
        const minVerifierLength = 43;
        if (verifier.length < minVerifierLength) {
            verifier = verifier + getRandomString(minVerifierLength - verifier.length);
        }
        // Code verifier will be a random URL-safe string with a maximum length of 128 characters
        return encodeURIComponent(verifier).slice(0, 128);
    }

    async prepareAuthParams (oauthParams) {
        if (!tokenUtils.isPKCESupported()) {
            let errorMessage = "PKCE requires a browser with encryption support running in a secure context.";
            if (!tokenUtils.isHTTPS()) {
                // eslint-disable-next-line max-len
                errorMessage = `${errorMessage} PKCE requires secure HTTPS protocol and the current page is not being served with it.`;
            }
            if (!tokenUtils.hasTextEncoder()) {
                // eslint-disable-next-line max-len
                errorMessage = `${errorMessage} PKCE requires TextEncoder and it is not defined in the current page. To use PKCE, you may need to include a polyfill/shim for this browser.`;
            }
            throw new Error(errorMessage);
        }

        if (!oauthParams.codeChallengeMethod) {
            oauthParams.codeChallengeMethod = this.getDefaultCodeChallengeMethod();
        }

        // Set response type to code
        oauthParams.responseType = "code";

        const discoveryConfig = await this.tokenManager.checkDiscoveryConfig();
        const methods = discoveryConfig.code_challenge_methods_supported || [];
        if (methods.indexOf(oauthParams.codeChallengeMethod) === -1) {
            throw new Error("Invalid code_challenge_method");
        }

        //  Authorization code with PKCE flow
        const codeVerifier = this.getCodeVerifier(oauthParams.codeVerifier);

        // We will need these values after redirect when we call /token
        const metaData = {
            codeVerifier: codeVerifier,
            redirectUri: oauthParams.redirectUri
        };
        this.saveData(metaData);

        let codeChallenge;
        if (oauthParams.codeChallengeMethod === "S256") {
            codeChallenge = await this.getCodeChallenge(codeVerifier);
        } else {
            codeChallenge = codeVerifier;
        }
        // Add codeChallenge
        return Object.assign({
            codeChallenge: codeChallenge
        }, oauthParams);
    }

    getStorage () {
        return this.tokenManager.tokenStorageManager.getPKCEStorage();
    }

    saveData (meta) {
        const storage = this.getStorage();
        storage.setStorage(meta);
    }

    loadData () {
        const storage = this.getStorage();
        return storage.getStorage();
    }

    clearData () {
        const storage = this.getStorage();
        storage.clearStorage();
    }

    async getCodeChallenge (str) {
        const buffer = new TextEncoder().encode(str);
        const arrayBuffer = await crypto.subtle.digest("SHA-256", buffer);
        const hash = String.fromCharCode(...new Uint8Array(arrayBuffer));
        return utils.stringToBase64Url(hash);
    }

    validateAuthOptions (authOptions) {
        if (!authOptions.clientId) {
            throw new Error("A clientId must be present to get the token.");
        }

        if (!authOptions.redirectUri) {
            throw new Error("A redirectUri must be present to get the token.");
        }

        if (!authOptions.authorizationCode) {
            throw new Error("An authorization code returned from /authorize must be present to get the token.");
        }

        if (!authOptions.codeVerifier) {
            throw new Error('The "codeVerifier" generated by your app must be present to get the token.');
        }
    }

    getPostData (options) {
        // Convert options to OAuth params
        const params = utils.removeNils({
            "client_id": options.clientId,
            "redirect_uri": options.redirectUri,
            "grant_type": "authorization_code",
            "code": options.authorizationCode,
            "code_verifier": options.codeVerifier
        });
        // Encode as URL string
        return utils.objectToURIQuery(params).slice(1);
    }

    /**
     * Exchange authorization code for an access token
     * @param {object} authOptions authentication parameters
     * @param {string} url token endpoint
     * @returns access token
     */
    async getToken (authOptions, url) {
        this.validateAuthOptions(authOptions);
        const data = this.getPostData(authOptions);

        const response = await this.http.post(url, {
            body: data,
            withCredentials: false,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });
        return await response.json();
    }

    /**
     * Get default code challenge method that is `plain`.
     * @returns {string}  default code challenge method
     */
    getDefaultCodeChallengeMethod () {
        return "plain";
    }
}

function dec2hex (dec) {
    return (`0${dec.toString(16)}`).substr(-2);
}

function getRandomString (length) {
    const a = new Uint8Array(Math.ceil(length / 2));
    crypto.getRandomValues(a);
    const str = Array.from(a, dec2hex).join("");
    return str.slice(0, length);
}

module.exports = PKCEManager;
