const tokenUtils = module.exports;

tokenUtils.generateState = function () {
    return tokenUtils.genRandomString(64);
};

tokenUtils.generateNonce = function () {
    return tokenUtils.genRandomString(64);
};

tokenUtils.isToken = function (obj) {
    return obj && (obj.accessToken || obj.idToken);
};

tokenUtils.hasExpired = function (token) {
    return token.expiresAt <= Date.now() / 1000;
};

tokenUtils.genRandomString = function (length) {
    const randomCharset = "abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let random = "";
    for (let c = 0, cl = randomCharset.length; c < length; c += 1) {
        random += randomCharset[Math.floor(Math.random() * cl)];
    }
    return random;
};

/**
 *  PKCE needs Web Crypto API for a number of low-level cryptographic functions and
 *  TextEncoder for emitting a stream of UTF-8 bytes.
 * @returns {*|boolean} true if environment follows all rules to support PKCE
 */
tokenUtils.isPKCESupported = function () {
    return this.isCryptoSupported() && this.hasTextEncoder();
};

tokenUtils.isCryptoSupported = function () {
    return (typeof crypto !== "undefined" && crypto.subtle && typeof Uint8Array !== "undefined");
};

tokenUtils.hasTextEncoder = function () {
    return typeof TextEncoder !== "undefined";
};

tokenUtils.isHTTPS = function () {
    return window.location.protocol === "https:";
};

tokenUtils.removeHash = function () {
    if (window.history && window.history.replaceState) {
        window.history.replaceState(null, window.location.title, window.location.pathname + window.location.search);
    } else {
        window.location.hash = "";
    }
};

tokenUtils.removeSearch = function () {
    if (window.history && window.history.replaceState) {
        window.history.replaceState(null, window.location.title, window.location.pathname + window.location.hash);
    } else {
        window.location.search = "";
    }
};

tokenUtils.runIframe = function (authorizeUrl, eventOrigin, timeoutInSeconds) {
    return new Promise(function (resolve, reject) {
        const iframe = window.document.createElement("iframe");
        iframe.style.display = "none";

        const removeIframe = () => {
            if (window.document.body.contains(iframe)) {
                window.document.body.removeChild(iframe);
            }
        };

        const timeoutSetTimeoutId = setTimeout(() => {
            reject("Session timeout");
            removeIframe();
        }, timeoutInSeconds * 1000);

        const iframeEventHandler = function (e) {
            // if (e.origin !== eventOrigin) { return; }
            const eventSource = e.source;
            if (eventSource) {
                eventSource.close();
            }
            if (e.data.error) {
                reject(e.data);
            } else {
                resolve(e.data);
            }
            clearTimeout(timeoutSetTimeoutId);
            if (window.removeEventListener) {
                window.removeEventListener("message", iframeEventHandler, false);
            } else {
                window.detachEvent("onmessage", iframeEventHandler);
            }
            // Delay iframe removal to prevent hanging loading status
            setTimeout(removeIframe, timeoutInSeconds * 1000);
        };
        if (window.addEventListener) {
            window.addEventListener("message", iframeEventHandler, false);
        } else {
            window.attachEvent("onmessage", iframeEventHandler);
        }
        window.document.body.appendChild(iframe);
        iframe.setAttribute("src", authorizeUrl);
    });
};
