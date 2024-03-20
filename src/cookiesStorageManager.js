const Cookies = require("js-cookie");
const {utils} = require("@ping-identity/p14c-js-sdk-core");
const {logger} = require("@ping-identity/p14c-js-sdk-core");

class CookiesStorageManager {
    constructor (cookiesConfig) {
        this.cookieSettings = this.getCookieSettings(cookiesConfig);
    }

    getCookieSettings (cookiesConfig) {
        const cookieSettings = Object.assign({
            secure: true
        }, cookiesConfig);
        if (utils.isLocalhost() && !utils.isHTTPS()) {
            cookieSettings.secure = false;
        }
        if (typeof cookieSettings.sameSite === "undefined") {
            // SameSite=None requires the Secure attribute in latest browser versions
            cookieSettings.sameSite = cookieSettings.secure ? "none" : "lax";
        }
        if (!utils.isHTTPS() && cookieSettings.secure) {
            logger.warn("This page is not served with the HTTPS protocol, " +
                'thereby setting "cookies.secure" option to false.');
            cookieSettings.secure = false;
        }
        return cookieSettings;
    }

    set (name, value, expiresAt, options) {
        const secure = (options && "secure" in options) ? options.secure : this.cookieSettings.secure;
        const sameSite = (options && "sameSite" in options) ? options.sameSite : this.cookieSettings.sameSite;
        if (typeof secure === "undefined" || typeof sameSite === "undefined") {
            throw new Error('Options like "secure" and "sameSite" must be provided for cookies storage.');
        }
        const cookieOptions = {
            path: (options && "path" in options) ? options.path : "/",
            secure,
            sameSite
        };

        if (Date.parse(expiresAt)) {
            // If the 'expiresAt' value is not provided, or the value cannot be
            // parsed as a Date object, the cookie will set as a session cookie.
            cookieOptions.expires = new Date(expiresAt);
        }

        Cookies.set(name, value, cookieOptions);
        return this.get(name);
    }

    get (name) {
        return Cookies.get(name);
    }

    delete (name) {
        // We must pass the exact same path and domain attributes that were used to set the cookie:
        return Cookies.remove(name, { path: "/" });
    }
}

module.exports = CookiesStorageManager;
