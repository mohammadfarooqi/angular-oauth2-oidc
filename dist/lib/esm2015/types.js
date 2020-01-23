/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Additional options that can be passt to tryLogin.
 */
export class LoginOptions {
    constructor() {
        /**
         * Normally, you want to clear your hash fragment after
         * the lib read the token(s) so that they are not displayed
         * anymore in the url. If not, set this to true.
         */
        this.preventClearHashAfterLogin = false;
    }
}
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
export class OAuthLogger {
}
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
export class OAuthStorage {
}
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
export class ReceivedTokens {
}
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidHlwZXMuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidHlwZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUdBLE1BQU0sT0FBTyxZQUFZO0lBQXpCOzs7Ozs7UUE4Q0UsK0JBQTBCLEdBQUksS0FBSyxDQUFDO0lBQ3RDLENBQUM7Q0FBQTs7Ozs7Ozs7O0lBeENDLHVDQUEyRDs7Ozs7OztJQU8zRCx5Q0FBcUU7Ozs7Ozs7O0lBUXJFLG9DQUF3Qzs7Ozs7OztJQU94QywwQ0FBNEI7Ozs7Ozs7Ozs7SUFVNUIsK0NBQWtDOzs7Ozs7O0lBT2xDLGtEQUFvQzs7Ozs7Ozs7O0FBU3RDLE1BQU0sT0FBZ0IsV0FBVztDQU1oQzs7Ozs7Ozs7SUFMQyxxRUFBOEQ7Ozs7Ozs7SUFDOUQsb0VBQTZEOzs7Ozs7O0lBQzdELG1FQUE0RDs7Ozs7OztJQUM1RCxvRUFBNkQ7Ozs7Ozs7SUFDN0QscUVBQThEOzs7Ozs7Ozs7QUFTaEUsTUFBTSxPQUFnQixZQUFZO0NBSWpDOzs7Ozs7O0lBSEMsb0RBQTZDOzs7Ozs7SUFDN0MsdURBQXVDOzs7Ozs7O0lBQ3ZDLDBEQUFrRDs7Ozs7O0FBT3BELE1BQU0sT0FBTyxjQUFjO0NBSzFCOzs7SUFKQyxpQ0FBZ0I7O0lBQ2hCLHFDQUFvQjs7SUFDcEIsa0NBQWtCOztJQUNsQiwrQkFBZTs7Ozs7O0FBTWpCLG1DQU9DOzs7SUFOQyxnQ0FBZ0I7O0lBQ2hCLHNDQUFzQjs7SUFDdEIsc0NBQXNCOztJQUN0QiwwQ0FBMEI7O0lBQzFCLDBDQUEwQjs7SUFDMUIseUNBQXlCOzs7Ozs7O0FBTzNCLG1DQVFDOzs7SUFQQyxxQ0FBcUI7O0lBQ3JCLGlDQUFpQjs7SUFDakIsbUNBQW1COztJQUNuQixtQ0FBbUI7O0lBQ25CLHNDQUFzQjs7SUFDdEIsOEJBQWM7O0lBQ2QsOEJBQWU7Ozs7Ozs7QUFPakIsOEJBR0M7OztJQUZDLHVCQUFZOzs7Ozs7O0FBT2Qsc0NBOEJDOzs7SUE3QkMsa0NBQWU7O0lBQ2Ysa0RBQStCOztJQUMvQiwwQ0FBdUI7O0lBQ3ZCLGlFQUFnRDs7SUFDaEQsNEVBQTJEOztJQUMzRCw2Q0FBMEI7O0lBQzFCLGdEQUE2Qjs7SUFDN0IsZ0RBQTZCOztJQUM3QixvQ0FBaUI7O0lBQ2pCLGlEQUE4Qjs7SUFDOUIsNENBQTJCOztJQUMzQixvREFBbUM7O0lBQ25DLGdEQUErQjs7SUFDL0Isb0RBQW1DOztJQUNuQyxpREFBZ0M7O0lBQ2hDLG1EQUFrQzs7SUFDbEMsaUVBQWdEOztJQUNoRCxvRUFBbUQ7O0lBQ25ELG9FQUFtRDs7SUFDbkQsaUVBQWdEOztJQUNoRCxvRUFBbUQ7O0lBQ25ELG9FQUFtRDs7SUFDbkQsdUVBQXNEOztJQUN0RCxvREFBbUM7O0lBQ25DLGlEQUFnQzs7SUFDaEMsNENBQTJCOztJQUMzQixzREFBb0M7O0lBQ3BDLGlEQUE4Qjs7SUFDOUIsZ0RBQStCIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBBZGRpdGlvbmFsIG9wdGlvbnMgdGhhdCBjYW4gYmUgcGFzc3QgdG8gdHJ5TG9naW4uXG4gKi9cbmV4cG9ydCBjbGFzcyBMb2dpbk9wdGlvbnMge1xuICAvKipcbiAgICogSXMgY2FsbGVkLCBhZnRlciBhIHRva2VuIGhhcyBiZWVuIHJlY2VpdmVkIGFuZFxuICAgKiBzdWNjZXNzZnVsbHkgdmFsaWRhdGVkLlxuICAgKlxuICAgKiBEZXByZWNhdGVkOiAgVXNlIHByb3BlcnR5IGBgZXZlbnRzYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXG4gICAqL1xuICBvblRva2VuUmVjZWl2ZWQ/OiAocmVjZWl2ZWRUb2tlbnM6IFJlY2VpdmVkVG9rZW5zKSA9PiB2b2lkO1xuXG4gIC8qKlxuICAgKiBIb29rLCB0byB2YWxpZGF0ZSB0aGUgcmVjZWl2ZWQgdG9rZW5zLlxuICAgKlxuICAgKiBEZXByZWNhdGVkOiAgVXNlIHByb3BlcnR5IGBgdG9rZW5WYWxpZGF0aW9uSGFuZGxlcmBgIG9uIE9BdXRoU2VydmljZSBpbnN0ZWFkLlxuICAgKi9cbiAgdmFsaWRhdGlvbkhhbmRsZXI/OiAocmVjZWl2ZWRUb2tlbnM6IFJlY2VpdmVkVG9rZW5zKSA9PiBQcm9taXNlPGFueT47XG5cbiAgLyoqXG4gICAqIENhbGxlZCB3aGVuIHRyeUxvZ2luIGRldGVjdHMgdGhhdCB0aGUgYXV0aCBzZXJ2ZXJcbiAgICogaW5jbHVkZWQgYW4gZXJyb3IgbWVzc2FnZSBpbnRvIHRoZSBoYXNoIGZyYWdtZW50LlxuICAgKlxuICAgKiBEZXByZWNhdGVkOiAgVXNlIHByb3BlcnR5IGBgZXZlbnRzYGAgb24gT0F1dGhTZXJ2aWNlIGluc3RlYWQuXG4gICAqL1xuICBvbkxvZ2luRXJyb3I/OiAocGFyYW1zOiBvYmplY3QpID0+IHZvaWQ7XG5cbiAgLyoqXG4gICAqIEEgY3VzdG9tIGhhc2ggZnJhZ21lbnQgdG8gYmUgdXNlZCBpbnN0ZWFkIG9mIHRoZVxuICAgKiBhY3R1YWwgb25lLiBUaGlzIGlzIHVzZWQgZm9yIHNpbGVudCByZWZyZXNoZXMsIHRvXG4gICAqIHBhc3MgdGhlIGlmcmFtZXMgaGFzaCBmcmFnbWVudCB0byB0aGlzIG1ldGhvZC5cbiAgICovXG4gIGN1c3RvbUhhc2hGcmFnbWVudD86IHN0cmluZztcblxuICAvKipcbiAgICogU2V0IHRoaXMgdG8gdHJ1ZSB0byBkaXNhYmxlIHRoZSBvYXV0aDIgc3RhdGVcbiAgICogY2hlY2sgd2hpY2ggaXMgYSBiZXN0IHByYWN0aWNlIHRvIGF2b2lkXG4gICAqIHNlY3VyaXR5IGF0dGFja3MuXG4gICAqIEFzIE9JREMgZGVmaW5lcyBhIG5vbmNlIGNoZWNrIHRoYXQgaW5jbHVkZXNcbiAgICogdGhpcywgdGhpcyBjYW4gYmUgc2V0IHRvIHRydWUgd2hlbiBvbmx5IGRvaW5nXG4gICAqIE9JREMuXG4gICAqL1xuICBkaXNhYmxlT0F1dGgyU3RhdGVDaGVjaz86IGJvb2xlYW47XG5cbiAgLyoqXG4gICAqIE5vcm1hbGx5LCB5b3Ugd2FudCB0byBjbGVhciB5b3VyIGhhc2ggZnJhZ21lbnQgYWZ0ZXJcbiAgICogdGhlIGxpYiByZWFkIHRoZSB0b2tlbihzKSBzbyB0aGF0IHRoZXkgYXJlIG5vdCBkaXNwbGF5ZWRcbiAgICogYW55bW9yZSBpbiB0aGUgdXJsLiBJZiBub3QsIHNldCB0aGlzIHRvIHRydWUuXG4gICAqL1xuICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbj8gPSBmYWxzZTtcbn1cblxuLyoqXG4gKiBEZWZpbmVzIHRoZSBsb2dnaW5nIGludGVyZmFjZSB0aGUgT0F1dGhTZXJ2aWNlIHVzZXNcbiAqIGludGVybmFsbHkuIElzIGNvbXBhdGlibGUgd2l0aCB0aGUgYGNvbnNvbGVgIG9iamVjdCxcbiAqIGJ1dCB5b3UgY2FuIHByb3ZpZGUgeW91ciBvd24gaW1wbGVtZW50YXRpb24gYXMgd2VsbFxuICogdGhyb3VnaCBkZXBlbmRlbmN5IGluamVjdGlvbi5cbiAqL1xuZXhwb3J0IGFic3RyYWN0IGNsYXNzIE9BdXRoTG9nZ2VyIHtcbiAgYWJzdHJhY3QgZGVidWcobWVzc2FnZT86IGFueSwgLi4ub3B0aW9uYWxQYXJhbXM6IGFueVtdKTogdm9pZDtcbiAgYWJzdHJhY3QgaW5mbyhtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xuICBhYnN0cmFjdCBsb2cobWVzc2FnZT86IGFueSwgLi4ub3B0aW9uYWxQYXJhbXM6IGFueVtdKTogdm9pZDtcbiAgYWJzdHJhY3Qgd2FybihtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xuICBhYnN0cmFjdCBlcnJvcihtZXNzYWdlPzogYW55LCAuLi5vcHRpb25hbFBhcmFtczogYW55W10pOiB2b2lkO1xufVxuXG4vKipcbiAqIERlZmluZXMgYSBzaW1wbGUgc3RvcmFnZSB0aGF0IGNhbiBiZSB1c2VkIGZvclxuICogc3RvcmluZyB0aGUgdG9rZW5zIGF0IGNsaWVudCBzaWRlLlxuICogSXMgY29tcGF0aWJsZSB0byBsb2NhbFN0b3JhZ2UgYW5kIHNlc3Npb25TdG9yYWdlLFxuICogYnV0IHlvdSBjYW4gYWxzbyBjcmVhdGUgeW91ciBvd24gaW1wbGVtZW50YXRpb25zLlxuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhTdG9yYWdlIHtcbiAgYWJzdHJhY3QgZ2V0SXRlbShrZXk6IHN0cmluZyk6IHN0cmluZyB8IG51bGw7XG4gIGFic3RyYWN0IHJlbW92ZUl0ZW0oa2V5OiBzdHJpbmcpOiB2b2lkO1xuICBhYnN0cmFjdCBzZXRJdGVtKGtleTogc3RyaW5nLCBkYXRhOiBzdHJpbmcpOiB2b2lkO1xufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgdGhlIHJlY2VpdmVkIHRva2VucywgdGhlIHJlY2VpdmVkIHN0YXRlXG4gKiBhbmQgdGhlIHBhcnNlZCBjbGFpbXMgZnJvbSB0aGUgaWQtdG9rZW4uXG4gKi9cbmV4cG9ydCBjbGFzcyBSZWNlaXZlZFRva2VucyB7XG4gIGlkVG9rZW46IHN0cmluZztcbiAgYWNjZXNzVG9rZW46IHN0cmluZztcbiAgaWRDbGFpbXM/OiBvYmplY3Q7XG4gIHN0YXRlPzogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgdGhlIHBhcnNlZCBhbmQgdmFsaWRhdGVkIGlkX3Rva2VuLlxuICovXG5leHBvcnQgaW50ZXJmYWNlIFBhcnNlZElkVG9rZW4ge1xuICBpZFRva2VuOiBzdHJpbmc7XG4gIGlkVG9rZW5DbGFpbXM6IG9iamVjdDtcbiAgaWRUb2tlbkhlYWRlcjogb2JqZWN0O1xuICBpZFRva2VuQ2xhaW1zSnNvbjogc3RyaW5nO1xuICBpZFRva2VuSGVhZGVySnNvbjogc3RyaW5nO1xuICBpZFRva2VuRXhwaXJlc0F0OiBudW1iZXI7XG59XG5cbi8qKlxuICogUmVwcmVzZW50cyB0aGUgcmVzcG9uc2UgZnJvbSB0aGUgdG9rZW4gZW5kcG9pbnRcbiAqIGh0dHA6Ly9vcGVuaWQubmV0L3NwZWNzL29wZW5pZC1jb25uZWN0LWNvcmUtMV8wLmh0bWwjVG9rZW5FbmRwb2ludFxuICovXG5leHBvcnQgaW50ZXJmYWNlIFRva2VuUmVzcG9uc2Uge1xuICBhY2Nlc3NfdG9rZW46IHN0cmluZztcbiAgaWRfdG9rZW46IHN0cmluZzsgXG4gIHRva2VuX3R5cGU6IHN0cmluZztcbiAgZXhwaXJlc19pbjogbnVtYmVyO1xuICByZWZyZXNoX3Rva2VuOiBzdHJpbmc7XG4gIHNjb3BlOiBzdHJpbmc7XG4gIHN0YXRlPzogc3RyaW5nO1xufVxuXG4vKipcbiAqIFJlcHJlc2VudHMgdGhlIHJlc3BvbnNlIGZyb20gdGhlIHVzZXIgaW5mbyBlbmRwb2ludFxuICogaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3QtY29yZS0xXzAuaHRtbCNVc2VySW5mb1xuICovXG5leHBvcnQgaW50ZXJmYWNlIFVzZXJJbmZvIHtcbiAgc3ViOiBzdHJpbmc7XG4gIFtrZXk6IHN0cmluZ106IGFueTtcbn1cblxuLyoqXG4gKiBSZXByZXNlbnRzIGFuIE9wZW5JRCBDb25uZWN0IGRpc2NvdmVyeSBkb2N1bWVudFxuICovXG5leHBvcnQgaW50ZXJmYWNlIE9pZGNEaXNjb3ZlcnlEb2Mge1xuICBpc3N1ZXI6IHN0cmluZztcbiAgYXV0aG9yaXphdGlvbl9lbmRwb2ludDogc3RyaW5nO1xuICB0b2tlbl9lbmRwb2ludDogc3RyaW5nO1xuICB0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZHNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgdG9rZW5fZW5kcG9pbnRfYXV0aF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgdXNlcmluZm9fZW5kcG9pbnQ6IHN0cmluZztcbiAgY2hlY2tfc2Vzc2lvbl9pZnJhbWU6IHN0cmluZztcbiAgZW5kX3Nlc3Npb25fZW5kcG9pbnQ6IHN0cmluZztcbiAgandrc191cmk6IHN0cmluZztcbiAgcmVnaXN0cmF0aW9uX2VuZHBvaW50OiBzdHJpbmc7XG4gIHNjb3Blc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICByZXNwb25zZV90eXBlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICBhY3JfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIHJlc3BvbnNlX21vZGVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIGdyYW50X3R5cGVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIHN1YmplY3RfdHlwZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgdXNlcmluZm9fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIHVzZXJpbmZvX2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICB1c2VyaW5mb19lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgaWRfdG9rZW5fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIGlkX3Rva2VuX2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICBpZF90b2tlbl9lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbiAgcmVxdWVzdF9vYmplY3Rfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIGRpc3BsYXlfdmFsdWVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIGNsYWltX3R5cGVzX3N1cHBvcnRlZDogc3RyaW5nW107XG4gIGNsYWltc19zdXBwb3J0ZWQ6IHN0cmluZ1tdO1xuICBjbGFpbXNfcGFyYW1ldGVyX3N1cHBvcnRlZDogYm9vbGVhbjtcbiAgc2VydmljZV9kb2N1bWVudGF0aW9uOiBzdHJpbmc7XG4gIHVpX2xvY2FsZXNfc3VwcG9ydGVkOiBzdHJpbmdbXTtcbn1cbiJdfQ==