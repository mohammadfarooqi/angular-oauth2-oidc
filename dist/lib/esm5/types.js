/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Additional options that can be passt to tryLogin.
 */
var /**
 * Additional options that can be passt to tryLogin.
 */
LoginOptions = /** @class */ (function () {
    function LoginOptions() {
        /**
         * Normally, you want to clear your hash fragment after
         * the lib read the token(s) so that they are not displayed
         * anymore in the url. If not, set this to true.
         */
        this.preventClearHashAfterLogin = false;
    }
    return LoginOptions;
}());
/**
 * Additional options that can be passt to tryLogin.
 */
export { LoginOptions };
if (false) {
    /**
     * Is called, after a token has been received and
     * successfully validated.
     *
     * Deprecated:  Use property ``events`` on OAuthService instead.
     * @type {?}
     */
    LoginOptions.prototype.onTokenReceived;
    /**
     * Hook, to validate the received tokens.
     *
     * Deprecated:  Use property ``tokenValidationHandler`` on OAuthService instead.
     * @type {?}
     */
    LoginOptions.prototype.validationHandler;
    /**
     * Called when tryLogin detects that the auth server
     * included an error message into the hash fragment.
     *
     * Deprecated:  Use property ``events`` on OAuthService instead.
     * @type {?}
     */
    LoginOptions.prototype.onLoginError;
    /**
     * A custom hash fragment to be used instead of the
     * actual one. This is used for silent refreshes, to
     * pass the iframes hash fragment to this method.
     * @type {?}
     */
    LoginOptions.prototype.customHashFragment;
    /**
     * Set this to true to disable the oauth2 state
     * check which is a best practice to avoid
     * security attacks.
     * As OIDC defines a nonce check that includes
     * this, this can be set to true when only doing
     * OIDC.
     * @type {?}
     */
    LoginOptions.prototype.disableOAuth2StateCheck;
    /**
     * Normally, you want to clear your hash fragment after
     * the lib read the token(s) so that they are not displayed
     * anymore in the url. If not, set this to true.
     * @type {?}
     */
    LoginOptions.prototype.preventClearHashAfterLogin;
}
/**
 * Defines the logging interface the OAuthService uses
 * internally. Is compatible with the `console` object,
 * but you can provide your own implementation as well
 * through dependency injection.
 * @abstract
 */
var /**
 * Defines the logging interface the OAuthService uses
 * internally. Is compatible with the `console` object,
 * but you can provide your own implementation as well
 * through dependency injection.
 * @abstract
 */
OAuthLogger = /** @class */ (function () {
    function OAuthLogger() {
    }
    return OAuthLogger;
}());
/**
 * Defines the logging interface the OAuthService uses
 * internally. Is compatible with the `console` object,
 * but you can provide your own implementation as well
 * through dependency injection.
 * @abstract
 */
export { OAuthLogger };
if (false) {
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.debug = function (message, optionalParams) { };
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.info = function (message, optionalParams) { };
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.log = function (message, optionalParams) { };
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.warn = function (message, optionalParams) { };
    /**
     * @abstract
     * @param {?=} message
     * @param {...?} optionalParams
     * @return {?}
     */
    OAuthLogger.prototype.error = function (message, optionalParams) { };
}
/**
 * Defines a simple storage that can be used for
 * storing the tokens at client side.
 * Is compatible to localStorage and sessionStorage,
 * but you can also create your own implementations.
 * @abstract
 */
var /**
 * Defines a simple storage that can be used for
 * storing the tokens at client side.
 * Is compatible to localStorage and sessionStorage,
 * but you can also create your own implementations.
 * @abstract
 */
OAuthStorage = /** @class */ (function () {
    function OAuthStorage() {
    }
    return OAuthStorage;
}());
/**
 * Defines a simple storage that can be used for
 * storing the tokens at client side.
 * Is compatible to localStorage and sessionStorage,
 * but you can also create your own implementations.
 * @abstract
 */
export { OAuthStorage };
if (false) {
    /**
     * @abstract
     * @param {?} key
     * @return {?}
     */
    OAuthStorage.prototype.getItem = function (key) { };
    /**
     * @abstract
     * @param {?} key
     * @return {?}
     */
    OAuthStorage.prototype.removeItem = function (key) { };
    /**
     * @abstract
     * @param {?} key
     * @param {?} data
     * @return {?}
     */
    OAuthStorage.prototype.setItem = function (key, data) { };
}
/**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
var /**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
ReceivedTokens = /** @class */ (function () {
    function ReceivedTokens() {
    }
    return ReceivedTokens;
}());
/**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
export { ReceivedTokens };
if (false) {
    /** @type {?} */
    ReceivedTokens.prototype.idToken;
    /** @type {?} */
    ReceivedTokens.prototype.accessToken;
    /** @type {?} */
    ReceivedTokens.prototype.idClaims;
    /** @type {?} */
    ReceivedTokens.prototype.state;
}
/**
 * Represents the parsed and validated id_token.
 * @record
 */
export function ParsedIdToken() { }
if (false) {
    /** @type {?} */
    ParsedIdToken.prototype.idToken;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenClaims;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenHeader;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenClaimsJson;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenHeaderJson;
    /** @type {?} */
    ParsedIdToken.prototype.idTokenExpiresAt;
}
/**
 * Represents the response from the token endpoint
 * http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
 * @record
 */
export function TokenResponse() { }
if (false) {
    /** @type {?} */
    TokenResponse.prototype.access_token;
    /** @type {?} */
    TokenResponse.prototype.id_token;
    /** @type {?} */
    TokenResponse.prototype.token_type;
    /** @type {?} */
    TokenResponse.prototype.expires_in;
    /** @type {?} */
    TokenResponse.prototype.refresh_token;
    /** @type {?} */
    TokenResponse.prototype.scope;
    /** @type {?|undefined} */
    TokenResponse.prototype.state;
}
/**
 * Represents the response from the user info endpoint
 * http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 * @record
 */
export function UserInfo() { }
if (false) {
    /** @type {?} */
    UserInfo.prototype.sub;
    /* Skipping unhandled member: [key: string]: any;*/
}
/**
 * Represents an OpenID Connect discovery document
 * @record
 */
export function OidcDiscoveryDoc() { }
if (false) {
    /** @type {?} */
    OidcDiscoveryDoc.prototype.issuer;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.authorization_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.token_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.token_endpoint_auth_methods_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.token_endpoint_auth_signing_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.userinfo_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.check_session_iframe;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.end_session_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.jwks_uri;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.registration_endpoint;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.scopes_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.response_types_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.acr_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.response_modes_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.grant_types_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.subject_types_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.userinfo_signing_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.userinfo_encryption_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.userinfo_encryption_enc_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.id_token_signing_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.id_token_encryption_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.id_token_encryption_enc_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.request_object_signing_alg_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.display_values_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.claim_types_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.claims_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.claims_parameter_supported;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.service_documentation;
    /** @type {?} */
    OidcDiscoveryDoc.prototype.ui_locales_supported;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHlwZXMuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidHlwZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUdBOzs7O0lBQUE7Ozs7OztRQThDRSwrQkFBMEIsR0FBSSxLQUFLLENBQUM7SUFDdEMsQ0FBQztJQUFELG1CQUFDO0FBQUQsQ0FBQyxBQS9DRCxJQStDQzs7Ozs7Ozs7Ozs7OztJQXhDQyx1Q0FBMkQ7Ozs7Ozs7SUFPM0QseUNBQXFFOzs7Ozs7OztJQVFyRSxvQ0FBd0M7Ozs7Ozs7SUFPeEMsMENBQTRCOzs7Ozs7Ozs7O0lBVTVCLCtDQUFrQzs7Ozs7OztJQU9sQyxrREFBb0M7Ozs7Ozs7OztBQVN0Qzs7Ozs7Ozs7SUFBQTtJQU1BLENBQUM7SUFBRCxrQkFBQztBQUFELENBQUMsQUFORCxJQU1DOzs7Ozs7Ozs7Ozs7Ozs7O0lBTEMscUVBQThEOzs7Ozs7O0lBQzlELG9FQUE2RDs7Ozs7OztJQUM3RCxtRUFBNEQ7Ozs7Ozs7SUFDNUQsb0VBQTZEOzs7Ozs7O0lBQzdELHFFQUE4RDs7Ozs7Ozs7O0FBU2hFOzs7Ozs7OztJQUFBO0lBSUEsQ0FBQztJQUFELG1CQUFDO0FBQUQsQ0FBQyxBQUpELElBSUM7Ozs7Ozs7Ozs7Ozs7OztJQUhDLG9EQUE2Qzs7Ozs7O0lBQzdDLHVEQUF1Qzs7Ozs7OztJQUN2QywwREFBa0Q7Ozs7OztBQU9wRDs7Ozs7SUFBQTtJQUtBLENBQUM7SUFBRCxxQkFBQztBQUFELENBQUMsQUFMRCxJQUtDOzs7Ozs7OztJQUpDLGlDQUFnQjs7SUFDaEIscUNBQW9COztJQUNwQixrQ0FBa0I7O0lBQ2xCLCtCQUFlOzs7Ozs7QUFNakIsbUNBT0M7OztJQU5DLGdDQUFnQjs7SUFDaEIsc0NBQXNCOztJQUN0QixzQ0FBc0I7O0lBQ3RCLDBDQUEwQjs7SUFDMUIsMENBQTBCOztJQUMxQix5Q0FBeUI7Ozs7Ozs7QUFPM0IsbUNBUUM7OztJQVBDLHFDQUFxQjs7SUFDckIsaUNBQWlCOztJQUNqQixtQ0FBbUI7O0lBQ25CLG1DQUFtQjs7SUFDbkIsc0NBQXNCOztJQUN0Qiw4QkFBYzs7SUFDZCw4QkFBZTs7Ozs7OztBQU9qQiw4QkFHQzs7O0lBRkMsdUJBQVk7Ozs7Ozs7QUFPZCxzQ0E4QkM7OztJQTdCQyxrQ0FBZTs7SUFDZixrREFBK0I7O0lBQy9CLDBDQUF1Qjs7SUFDdkIsaUVBQWdEOztJQUNoRCw0RUFBMkQ7O0lBQzNELDZDQUEwQjs7SUFDMUIsZ0RBQTZCOztJQUM3QixnREFBNkI7O0lBQzdCLG9DQUFpQjs7SUFDakIsaURBQThCOztJQUM5Qiw0Q0FBMkI7O0lBQzNCLG9EQUFtQzs7SUFDbkMsZ0RBQStCOztJQUMvQixvREFBbUM7O0lBQ25DLGlEQUFnQzs7SUFDaEMsbURBQWtDOztJQUNsQyxpRUFBZ0Q7O0lBQ2hELG9FQUFtRDs7SUFDbkQsb0VBQW1EOztJQUNuRCxpRUFBZ0Q7O0lBQ2hELG9FQUFtRDs7SUFDbkQsb0VBQW1EOztJQUNuRCx1RUFBc0Q7O0lBQ3RELG9EQUFtQzs7SUFDbkMsaURBQWdDOztJQUNoQyw0Q0FBMkI7O0lBQzNCLHNEQUFvQzs7SUFDcEMsaURBQThCOztJQUM5QixnREFBK0IiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIEFkZGl0aW9uYWwgb3B0aW9ucyB0aGF0IGNhbiBiZSBwYXNzdCB0byB0cnlMb2dpbi5cbiAqL1xuZXhwb3J0IGNsYXNzIExvZ2luT3B0aW9ucyB7XG4gIC8qKlxuICAgKiBJcyBjYWxsZWQsIGFmdGVyIGEgdG9rZW4gaGFzIGJlZW4gcmVjZWl2ZWQgYW5kXG4gICAqIHN1Y2Nlc3NmdWxseSB2YWxpZGF0ZWQuXG4gICAqXG4gICAqIERlcHJlY2F0ZWQ6ICBVc2UgcHJvcGVydHkgYGBldmVudHNgYCBvbiBPQXV0aFNlcnZpY2UgaW5zdGVhZC5cbiAgICovXG4gIG9uVG9rZW5SZWNlaXZlZD86IChyZWNlaXZlZFRva2VuczogUmVjZWl2ZWRUb2tlbnMpID0+IHZvaWQ7XG5cbiAgLyoqXG4gICAqIEhvb2ssIHRvIHZhbGlkYXRlIHRoZSByZWNlaXZlZCB0b2tlbnMuXG4gICAqXG4gICAqIERlcHJlY2F0ZWQ6ICBVc2UgcHJvcGVydHkgYGB0b2tlblZhbGlkYXRpb25IYW5kbGVyYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXG4gICAqL1xuICB2YWxpZGF0aW9uSGFuZGxlcj86IChyZWNlaXZlZFRva2VuczogUmVjZWl2ZWRUb2tlbnMpID0+IFByb21pc2U8YW55PjtcblxuICAvKipcbiAgICogQ2FsbGVkIHdoZW4gdHJ5TG9naW4gZGV0ZWN0cyB0aGF0IHRoZSBhdXRoIHNlcnZlclxuICAgKiBpbmNsdWRlZCBhbiBlcnJvciBtZXNzYWdlIGludG8gdGhlIGhhc2ggZnJhZ21lbnQuXG4gICAqXG4gICAqIERlcHJlY2F0ZWQ6ICBVc2UgcHJvcGVydHkgYGBldmVudHNgYCBvbiBPQXV0aFNlcnZpY2UgaW5zdGVhZC5cbiAgICovXG4gIG9uTG9naW5FcnJvcj86IChwYXJhbXM6IG9iamVjdCkgPT4gdm9pZDtcblxuICAvKipcbiAgICogQSBjdXN0b20gaGFzaCBmcmFnbWVudCB0byBiZSB1c2VkIGluc3RlYWQgb2YgdGhlXG4gICAqIGFjdHVhbCBvbmUuIFRoaXMgaXMgdXNlZCBmb3Igc2lsZW50IHJlZnJlc2hlcywgdG9cbiAgICogcGFzcyB0aGUgaWZyYW1lcyBoYXNoIGZyYWdtZW50IHRvIHRoaXMgbWV0aG9kLlxuICAgKi9cbiAgY3VzdG9tSGFzaEZyYWdtZW50Pzogc3RyaW5nO1xuXG4gIC8qKlxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIGRpc2FibGUgdGhlIG9hdXRoMiBzdGF0ZVxuICAgKiBjaGVjayB3aGljaCBpcyBhIGJlc3QgcHJhY3RpY2UgdG8gYXZvaWRcbiAgICogc2VjdXJpdHkgYXR0YWNrcy5cbiAgICogQXMgT0lEQyBkZWZpbmVzIGEgbm9uY2UgY2hlY2sgdGhhdCBpbmNsdWRlc1xuICAgKiB0aGlzLCB0aGlzIGNhbiBiZSBzZXQgdG8gdHJ1ZSB3aGVuIG9ubHkgZG9pbmdcbiAgICogT0lEQy5cbiAgICovXG4gIGRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrPzogYm9vbGVhbjtcblxuICAvKipcbiAgICogTm9ybWFsbHksIHlvdSB3YW50IHRvIGNsZWFyIHlvdXIgaGFzaCBmcmFnbWVudCBhZnRlclxuICAgKiB0aGUgbGliIHJlYWQgdGhlIHRva2VuKHMpIHNvIHRoYXQgdGhleSBhcmUgbm90IGRpc3BsYXllZFxuICAgKiBhbnltb3JlIGluIHRoZSB1cmwuIElmIG5vdCwgc2V0IHRoaXMgdG8gdHJ1ZS5cbiAgICovXG4gIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luPyA9IGZhbHNlO1xufVxuXG4vKipcbiAqIERlZmluZXMgdGhlIGxvZ2dpbmcgaW50ZXJmYWNlIHRoZSBPQXV0aFNlcnZpY2UgdXNlc1xuICogaW50ZXJuYWxseS4gSXMgY29tcGF0aWJsZSB3aXRoIHRoZSBgY29uc29sZWAgb2JqZWN0LFxuICogYnV0IHlvdSBjYW4gcHJvdmlkZSB5b3VyIG93biBpbXBsZW1lbnRhdGlvbiBhcyB3ZWxsXG4gKiB0aHJvdWdoIGRlcGVuZGVuY3kgaW5qZWN0aW9uLlxuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhMb2dnZXIge1xuICBhYnN0cmFjdCBkZWJ1ZyhtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xuICBhYnN0cmFjdCBpbmZvKG1lc3NhZ2U/OiBhbnksIC4uLm9wdGlvbmFsUGFyYW1zOiBhbnlbXSk6IHZvaWQ7XG4gIGFic3RyYWN0IGxvZyhtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xuICBhYnN0cmFjdCB3YXJuKG1lc3NhZ2U/OiBhbnksIC4uLm9wdGlvbmFsUGFyYW1zOiBhbnlbXSk6IHZvaWQ7XG4gIGFic3RyYWN0IGVycm9yKG1lc3NhZ2U/OiBhbnksIC4uLm9wdGlvbmFsUGFyYW1zOiBhbnlbXSk6IHZvaWQ7XG59XG5cbi8qKlxuICogRGVmaW5lcyBhIHNpbXBsZSBzdG9yYWdlIHRoYXQgY2FuIGJlIHVzZWQgZm9yXG4gKiBzdG9yaW5nIHRoZSB0b2tlbnMgYXQgY2xpZW50IHNpZGUuXG4gKiBJcyBjb21wYXRpYmxlIHRvIGxvY2FsU3RvcmFnZSBhbmQgc2Vzc2lvblN0b3JhZ2UsXG4gKiBidXQgeW91IGNhbiBhbHNvIGNyZWF0ZSB5b3VyIG93biBpbXBsZW1lbnRhdGlvbnMuXG4gKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aFN0b3JhZ2Uge1xuICBhYnN0cmFjdCBnZXRJdGVtKGtleTogc3RyaW5nKTogc3RyaW5nIHwgbnVsbDtcbiAgYWJzdHJhY3QgcmVtb3ZlSXRlbShrZXk6IHN0cmluZyk6IHZvaWQ7XG4gIGFic3RyYWN0IHNldEl0ZW0oa2V5OiBzdHJpbmcsIGRhdGE6IHN0cmluZyk6IHZvaWQ7XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyB0aGUgcmVjZWl2ZWQgdG9rZW5zLCB0aGUgcmVjZWl2ZWQgc3RhdGVcbiAqIGFuZCB0aGUgcGFyc2VkIGNsYWltcyBmcm9tIHRoZSBpZC10b2tlbi5cbiAqL1xuZXhwb3J0IGNsYXNzIFJlY2VpdmVkVG9rZW5zIHtcbiAgaWRUb2tlbjogc3RyaW5nO1xuICBhY2Nlc3NUb2tlbjogc3RyaW5nO1xuICBpZENsYWltcz86IG9iamVjdDtcbiAgc3RhdGU/OiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyB0aGUgcGFyc2VkIGFuZCB2YWxpZGF0ZWQgaWRfdG9rZW4uXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgUGFyc2VkSWRUb2tlbiB7XG4gIGlkVG9rZW46IHN0cmluZztcbiAgaWRUb2tlbkNsYWltczogb2JqZWN0O1xuICBpZFRva2VuSGVhZGVyOiBvYmplY3Q7XG4gIGlkVG9rZW5DbGFpbXNKc29uOiBzdHJpbmc7XG4gIGlkVG9rZW5IZWFkZXJKc29uOiBzdHJpbmc7XG4gIGlkVG9rZW5FeHBpcmVzQXQ6IG51bWJlcjtcbn1cblxuLyoqXG4gKiBSZXByZXNlbnRzIHRoZSByZXNwb25zZSBmcm9tIHRoZSB0b2tlbiBlbmRwb2ludFxuICogaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3QtY29yZS0xXzAuaHRtbCNUb2tlbkVuZHBvaW50XG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgVG9rZW5SZXNwb25zZSB7XG4gIGFjY2Vzc190b2tlbjogc3RyaW5nO1xuICBpZF90b2tlbjogc3RyaW5nOyBcbiAgdG9rZW5fdHlwZTogc3RyaW5nO1xuICBleHBpcmVzX2luOiBudW1iZXI7XG4gIHJlZnJlc2hfdG9rZW46IHN0cmluZztcbiAgc2NvcGU6IHN0cmluZztcbiAgc3RhdGU/OiBzdHJpbmc7XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyB0aGUgcmVzcG9uc2UgZnJvbSB0aGUgdXNlciBpbmZvIGVuZHBvaW50XG4gKiBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1jb3JlLTFfMC5odG1sI1VzZXJJbmZvXG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgVXNlckluZm8ge1xuICBzdWI6IHN0cmluZztcbiAgW2tleTogc3RyaW5nXTogYW55O1xufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgYW4gT3BlbklEIENvbm5lY3QgZGlzY292ZXJ5IGRvY3VtZW50XG4gKi9cbmV4cG9ydCBpbnRlcmZhY2UgT2lkY0Rpc2NvdmVyeURvYyB7XG4gIGlzc3Vlcjogc3RyaW5nO1xuICBhdXRob3JpemF0aW9uX2VuZHBvaW50OiBzdHJpbmc7XG4gIHRva2VuX2VuZHBvaW50OiBzdHJpbmc7XG4gIHRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICB0b2tlbl9lbmRwb2ludF9hdXRoX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICB1c2VyaW5mb19lbmRwb2ludDogc3RyaW5nO1xuICBjaGVja19zZXNzaW9uX2lmcmFtZTogc3RyaW5nO1xuICBlbmRfc2Vzc2lvbl9lbmRwb2ludDogc3RyaW5nO1xuICBqd2tzX3VyaTogc3RyaW5nO1xuICByZWdpc3RyYXRpb25fZW5kcG9pbnQ6IHN0cmluZztcbiAgc2NvcGVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIHJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIGFjcl92YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgcmVzcG9uc2VfbW9kZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgZ3JhbnRfdHlwZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgc3ViamVjdF90eXBlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICB1c2VyaW5mb19zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgdXNlcmluZm9fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIHVzZXJpbmZvX2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICBpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgaWRfdG9rZW5fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIGlkX3Rva2VuX2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICByZXF1ZXN0X29iamVjdF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgZGlzcGxheV92YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgY2xhaW1fdHlwZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgY2xhaW1zX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIGNsYWltc19wYXJhbWV0ZXJfc3VwcG9ydGVkOiBib29sZWFuO1xuICBzZXJ2aWNlX2RvY3VtZW50YXRpb246IHN0cmluZztcbiAgdWlfbG9jYWxlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xufVxuIl19