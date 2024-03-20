# PingOne SDK for JavaScript Authentication Module

# NOTE:
**THIS REPOSITORY IS IN A TESTING MODE AND IS NOT READY FOR PRODUCTION !!!**

## Content
 1. [Installation](#installation)
 1. [API Reference](#module-api-reference)
 1. [Supported authentication flows](#supported-authentication-flows)
 1. [Tokens](#tokens)

## Installation

To install [@ping-identity/p14c-js-sdk-auth](https://www.npmjs.com/package/@ping-identity/p14c-js-sdk-auth) you can run these commands in your project root folder:

```bash
# yarn
yarn add @ping-identity/p14c-js-sdk-auth
```
or
```
# npm
npm install --save @ping-identity/p14c-js-sdk-auth
```

If you are using the JS on a web page from the browser, you can copy [p14c-js-sdk-auth.js](https://github.com/pingidentity/pingone-javascript-sdk/tree/master/packages/authentication-api/dist/%40ping-identity) contents to a publicly hosted directory,
and include a reference to the `p14c-js-sdk-auth.js` file in a `<script>` tag.

However, if you're using a bundler like [Webpack](https://webpack.github.io/) or [Browserify](http://browserify.org/), you can simply import the module using CommonJS.

**_Warning_**: If you're in an environment that doesn't support Promises,TextEncoders etc such as Internet Explorer, you need to install such polyfills/shims:
 - an [es6-promise](https://github.com/stefanpenner/es6-promise) compatible polyfill;
 - [Array.from](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/from#Polyfill) polyfill;
 - [Object.assign](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/assign#Polyfill) polyfill;
 - [TextEncoder](https://www.npmjs.com/package/text-encoding-polyfill) polyfill;
 - [Uint8Array](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray/fill)
 - [Web Cryptography API shim](https://github.com/vibornoff/webcrypto-shim).


```javascript
const PingOneAuthClient = require("@ping-identity/p14c-js-sdk-auth");

const config = {
  clientId: "someClientId",
  environmentId: "someEnvironmentId",
  redirectUri: "https://localhost/callback",
  // Configure token storage to use session instead of local storage
  storage: "sessionStorage"
};

const authClient = new PingOneAuthClient(config);
```

, where configuration parameters are:
- `clientId` : **Required**. Your application's client UUID. You can also find this value at Application's Settings right under the
  Application name.
  
- `environmentId`: **Required**. Your application's Environment ID. You can find this value at your Application's Settings under
  _Configuration_ tab from the admin console( extract `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` string that specifies the environment 128-bit universally unique identifier ([UUID](https://tools.ietf.org/html/rfc4122)) right from `https://auth.pingone .com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/as/authorize`
  _AUTHORIZATION URL_ ). Or from the _Settings_ main menu (_ENVIRONMENT ID_ variable)
  
- `responseType` : **Optional**. Determines whether an access token, an authorization code, or an ID token is returned by the authorization server. 
Possible values are: an array from different combination of `["token", "id_token", "code"]`.  If `pkce=true` then both the access and id token will be requested and `responseType` will be ignored. Default value is: `["token", "id_token"]`.

- `storage` :  **Optional**. Tokens storage type. Possible values are: [`localStorage`](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage), [`sessionStorage`](https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage), `cookieStorage`, `memoryStorage`. Default value is: `localStorage`.
Window `localStorage` - data is stored and saved across browser sessions without expiration time. 
Window `sessionStorage` - data gets cleared when the page session ends(when the page is closed). 
`cookieStorage`, `memoryStorage`

- `tokenRenew` :  **Optional**. Renew expired token either with refresh token (if `useRefreshTokens=true`) or using a hidden iframe. Default value is: `true`.

- `useRefreshTokens`: **Optional**. Use refresh token to exchange for new access tokens instead of using a hidden iframe and `/oauth/token` endpoint call. Will be ignored if `tokenRenew=false`.  

- `pkce`: **Optional**. Use Authorization Code with Proof Key for Code Exchange (PKCE) flow for token retrieval. Default value is: `true`.

- `codeChallengeMethod`: **Optional**. Transformation method that creates the `code_challenge` value. Possible values are: `S256` or `plain`. Will be ignored if `pkce=false`. Default value is: `plain` if not specified.
 The error will be triggered if `S256_REQUIRED` PKCE enforcement option is specified by the application, but `codeChallengeMethod=plain` is set. 

- `cookies: {
           secure: true,
           sameSite: 'none'
       }` : **Optional**. Cookies storage configuration. 
       [`SameSite`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite) attribute allows you to declare if your cookie should be restricted to a first-party or same-site context.

- `scopes` : **Optional**. Array of standard OIDC or PingOne custom scopes you want to request authorization for. Default value is: `["openid"]`

- `max_age`: : **Optional**.  Integer that specifies the maximum amount of time allowed since the user last authenticated. If the `max_age` value is exceeded, the user must re-authenticate.

- `acr_values` : **Optional**. String  that designates whether the authentication request includes specified sign-on policies. Sign-on policy names should be listed in order of preference, and they must be assigned to the application. For more information, see [Sign-on policies](https://apidocs.pingidentity.com/pingone/platform/v1/api/#sign-on-policies)

- `API_URI` : **Optional**. PingOne API base endpoint. Default value is: `https://api.pingone.com`

- `AUTH_URI` : **Optional**. PingOne Authentication base endpoint. Default value is:`https://auth.pingone.com`

## Module API Reference
|    Method   |    Description   |
| ------------- |------------- |
| `signIn()` | Sign in the user |
| `signOut()`| Sign out the user  |
| `revokeToken(token, tokenName)` | Revoke either access or refresh token (`tokenName` is `accessToken` and `refreshToken` respectively)|
| `parseRedirectUrl (options)` | Parse window url to get all tokens either from implicit flow or authorization code with PKCE |
| `getUserInfo()` | Get user information from OIDC userinfo endpoint |

## Supported Authentication Flows
There are two supported grant options: 
- the Authorization Code Grant using Proof Key for Code Exchange (PKCE); 
- the Implicit Grant for Single Page application running in a browser.

For most cases, Authorization Code Grant with PKCE is recommend.

#### PKCE OAuth 2.0 flow

The PKCE OAuth flow is used by default. It requires some features browser to implement that are widely supported by most modern browsers when running on an HTTPS connection.
So please make sure the features like specified below are supported by your browser: 
- [`crypto.subtle`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) that is available only in secure contexts (HTTPS), in [some or all supporting browsers](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto#Browser_compatibility).
- TextEncoder, for which there is a polyfill implementation to support non-UTF-8 text encodings on [GitHub](https://github.com/inexorabletash/text-encoding).

#### Implicit OAuth 2.0 flow

Implicit OAuth flow is available as an option if PKCE flow cannot be supported in your deployment. It is widely supported by most browsers, and can work over an insecure HTTP connection. 
Note that implicit flow is less secure than PKCE flow, even over HTTPS, since raw tokens are exposed in the browser's history. For this reason, we highly recommend using the PKCE flow if possible.
PingOne implicit flow follows the [OAuth 2.0 spec](https://tools.ietf.org/html/rfc6749#section-4.2.2) that says that the authorization server must not issue a refresh token.
  
Implicit flow can be enabled by setting the `pkce` option to `false`

```javascript
const authClient = new PingOneAuthClient({
     pkce: false
     // other config
});
```

## Tokens

#### When and how to store tokens

- If your SPA has a backend and can handle the API calls, then handle tokens server-side using `authorization_code` or `authorization_code with Proof Key for Code Exchange (PKCE)` flow.
- If your SPA has a backend and cannot handle the API calls, then tokens should be stored in the SPA backend, but the SPA needs to fetch the tokens from the backend to perform requests to the API. 
- If your SPA doesn't have a backend server, then you should request new tokens on login and store them in memory without any persistence. To make API calls, your SPA would then use the in-memory copy of the token.

### How tokens are renewed
Depending on your configuration, the SDK falls back either to the legacy technique of using a hidden iframe for token renewal, or just using a refresh token.
- When `tokenRenew` and `useRefreshTokens` is set to `true`, refresh token will be used to exchange for new access tokens.
- When `tokenRenew` is set to `true` and `useRefreshTokens` is set to `false`, the SDK will be using a hidden iframe with `prompt=none` to call the `/oauth/token` endpoint directly for a new access token and refresh token retrieval. 
This scenario occurs, for example, if you are using token in-memory cache and you have refreshed the page. In this case, refresh token stored previously will be lost.

### What is refresh token and how it is used in SDK

Refresh tokens improve the authentication experience in a way that the user has to authenticate only once, and other subsequent re-authentication will take place without user interaction, using the Refresh Token.
The authorization server can issue refresh tokens to web applications that use an `authorization_code` grant type.

To obtain a refresh token along with an access token, the application must be configured with the `refresh_token` and the `authorization_code` grant types. 
With this configuration, a refresh token is generated along with the access token. When obtaining the original access token, a refresh token is included in the response, which is tied to the client and the user session. 
As long as the session exists and it is not expired (30 days since the last sign on), the `/{environmentId}/as/token` endpoint can be used to exchange the refresh token for a new access token and refresh token. If the openid scope is granted, an ID token is also included.

When a new refresh token is issued, the previous refresh token is rotated to prevent token abuse, which is useful when client authentication is disabled. 
In addition, when a refresh token is exchanged, the `activeAt` property of the corresponding session is updated. 
This does not extend the duration of the session, but can be used to indicate that there is activity.

Only one refresh token is valid at any time for the environment, session and client.  
If token is not recorded as the current refresh token (with `sid` and `jti`) for the environment, session and client, 
 the error "Refresh token does not exist" is thrown.
