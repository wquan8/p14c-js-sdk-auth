const {logger} = require("@ping-identity/p14c-js-sdk-core");
const CookiesStorageManager = require("./cookiesStorageManager");

class TokenStorageManager {
    constructor (options) {
        this.init(options);
        this.cookiesOptions = options.cookies;
    }

    init (options) {
        if (options.storage === "localStorage" && !this.browserHasLocalStorage()) {
            logger.warn("Your browser doesn't support local storage, thereby switched to session based storage.");
            options.storage = "sessionStorage";
        }

        if (options.storage === "sessionStorage" && !this.browserHasSessionStorage()) {
            logger.warn("Your browser doesn't support session storage, thereby switched to cookie based storage.");
            options.storage = "cookieStorage";
        }
        let storageType;
        switch (options.storage) {
            case "localStorage":
                storageType = localStorage;
                break;
            case "sessionStorage":
                storageType = sessionStorage;
                break;
            case "cookieStorage":
                storageType = this.getCookieStorage(options.cookies);
                break;
            case "inMemoryStorage":
                storageType = this.getInMemoryStorage();
                break;
            default:
                throw new Error("Unrecognized storage option");
        }
        const storageKey = options.storageKey || "token_storage";
        this.storage = createStorage(storageType, storageKey);
    }

    browserHasLocalStorage () {
        try {
            const storage = this.getLocalStorage();
            return this.testStorage(storage);
        } catch (e) {
            return false;
        }
    }

    browserHasSessionStorage () {
        try {
            const storage = this.getSessionStorage();
            return this.testStorage(storage);
        } catch (e) {
            return false;
        }
    }

    testStorage (storage) {
        const key = "test-storage";
        try {
            storage.setItem(key, key);
            storage.removeItem(key);
            return true;
        } catch (e) {
            return false;
        }
    }

    getLocalStorage () {
        return localStorage;
    }

    getSessionStorage () {
        return sessionStorage;
    }

    /**
     * Get cookies storage
     * @param {object} options to get cookies with (secure: true/false, sameSite: true/false)
     * @returns {{getItem: CookiesStorageManager.get, setItem: setItem}} storage
     */
    getCookieStorage (options) {
        const secure = options.secure;
        const sameSite = options.sameSite;
        if (typeof secure === "undefined" || typeof sameSite === "undefined") {
            throw new Error('For cookie storage "secure" and "sameSite" options must be provided');
        }
        const cookiesStorageManager = new CookiesStorageManager(options);
        return {
            getItem: cookiesStorageManager.get,
            setItem: function (key, value) {
                // Cookie shouldn't expire
                cookiesStorageManager.set(key, value, "3300-01-01T00:00:00.000Z", {
                    secure: secure,
                    sameSite: sameSite
                });
            }
        };
    }

    /**
     * Get in-memory storage
     * @returns {{getItem: (function(*): *), setItem: setItem}} storage
     */
    getInMemoryStorage () {
        const store = {};
        return {
            getItem: function (key) {
                return store[key];
            },
            setItem: function (key, value) {
                store[key] = value;
            }
        };
    }

    /**
     * Get PKCE storage.
     * Firstly prefer local, then session, then cookies storage.
     * @returns {{setStorage: setStorage, updateStorage: updateStorage, getStorage: getStorage, clearStorage: clearStorage}} storage
     */
    getPKCEStorage () {
        if (this.browserHasLocalStorage()) {
            return createStorage(this.getLocalStorage(), "pkce-storage");
        } else if (this.browserHasSessionStorage()) {
            return createStorage(this.getSessionStorage(), "pkce-storage");
        } else {
            return createStorage(this.getCookieStorage(this.cookiesOptions), "pkce-storage");
        }
    }

    getStorage (webstorage, storageName) {
        let storageString = webstorage.getItem(storageName);
        storageString = storageString || "{}";
        try {
            return JSON.parse(storageString);
        } catch (e) {
            throw new Error(`Unable to parse storage string: ${storageName}`);
        }
    }

    setStorage (storage, webstorage, storageName) {
        try {
            const storageString = JSON.stringify(storage);
            webstorage.setItem(storageName, storageString);
        } catch (e) {
            throw new Error(`Unable to set storage: ${storageName}`);
        }
    }

    clearStorage (key, webstorage, storageName) {
        if (!key) {
            return this.setStorage({}, webstorage, storageName);
        }
        const storage = this.getStorage(webstorage, storageName);
        Reflect.deleteProperty(storage, key);
        this.setStorage(storage, webstorage, storageName);
    }

    get (key) {
        return this.storage.getStorage()[key];
    }

    add (key, token) {
        const storage = this.storage.getStorage();
        storage[key] = token;
        this.storage.setStorage(storage);
    }

    remove (key) {
        // Remove it from storage
        const tokenStorage = this.storage.getStorage();
        Reflect.deleteProperty(tokenStorage, key);
        this.storage.setStorage(tokenStorage);
    }

    clear () {
        this.storage.clearStorage();
    }
}

function createStorage (webStorage, storageName) {
    if (typeof storageName !== "string" || !storageName.length) {
        throw new Error("Storage name is missing");
    }

    function getStorage () {
        let storageString = webStorage.getItem(storageName);
        storageString = storageString || "{}";
        try {
            return JSON.parse(storageString);
        } catch (e) {
            throw new Error(`Unable to parse storage content: ${storageName}`);
        }
    }

    function setStorage (storage) {
        try {
            const storageString = JSON.stringify(storage);
            webStorage.setItem(storageName, storageString);
        } catch (e) {
            throw new Error(`Unable to set storage: ${storageName}`);
        }
    }

    function clearStorage (key) {
        if (!key) {
            return setStorage({});
        }
        const storage = getStorage();
        Reflect.deleteProperty(storage, key);
        setStorage(storage);
    }

    function updateStorage (key, value) {
        const storage = getStorage();
        storage[key] = value;
        setStorage(storage);
    }

    return {
        getStorage: getStorage,
        setStorage: setStorage,
        clearStorage: clearStorage,
        updateStorage: updateStorage
    };
}

module.exports = TokenStorageManager;
