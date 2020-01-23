/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
export class AuthConfig {
    /**
     * @param {?=} json
     */
    constructor(json) {
        /**
         * The client's id as registered with the auth server
         */
        this.clientId = '';
        /**
         * The client's redirectUri as registered with the auth server
         */
        this.redirectUri = '';
        /**
         * An optional second redirectUri where the auth server
         * redirects the user to after logging out.
         */
        this.postLogoutRedirectUri = '';
        /**
         * The auth server's endpoint that allows to log
         * the user in when using implicit flow.
         */
        this.loginUrl = '';
        /**
         * The requested scopes
         */
        this.scope = 'openid profile';
        this.resource = '';
        this.rngUrl = '';
        /**
         * Defines whether to use OpenId Connect during
         * implicit flow.
         */
        this.oidc = true;
        /**
         * Defines whether to request an access token during
         * implicit flow.
         */
        this.requestAccessToken = true;
        this.options = null;
        /**
         * The issuer's uri.
         */
        this.issuer = '';
        /**
         * The logout url.
         */
        this.logoutUrl = '';
        /**
         * Defines whether to clear the hash fragment after logging in.
         */
        this.clearHashAfterLogin = true;
        /**
         * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.tokenEndpoint = null;
        /**
         * Url of the userinfo endpoint as defined by OpenId Connect.
         */
        this.userinfoEndpoint = null;
        this.responseType = '';
        /**
         * Defines whether additional debug information should
         * be shown at the console. Note that in certain browsers
         * the verbosity of the console needs to be explicitly set
         * to include Debug level messages.
         */
        this.showDebugInformation = false;
        /**
         * The redirect uri used when doing silent refresh.
         */
        this.silentRefreshRedirectUri = '';
        this.silentRefreshMessagePrefix = '';
        /**
         * Set this to true to display the iframe used for
         * silent refresh for debugging.
         */
        this.silentRefreshShowIFrame = false;
        /**
         * Timeout for silent refresh.
         * \@internal
         * depreacted b/c of typo, see silentRefreshTimeout
         */
        this.siletRefreshTimeout = 1000 * 20;
        /**
         * Timeout for silent refresh.
         */
        this.silentRefreshTimeout = 1000 * 20;
        /**
         * Some auth servers don't allow using password flow
         * w/o a client secret while the standards do not
         * demand for it. In this case, you can set a password
         * here. As this password is exposed to the public
         * it does not bring additional security and is therefore
         * as good as using no password.
         */
        this.dummyClientSecret = null;
        /**
         * Defines whether https is required.
         * The default value is remoteOnly which only allows
         * http for localhost, while every other domains need
         * to be used with https.
         */
        this.requireHttps = 'remoteOnly';
        /**
         * Defines whether every url provided by the discovery
         * document has to start with the issuer's url.
         */
        this.strictDiscoveryDocumentValidation = true;
        /**
         * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
         * with keys used to validate received id_tokens.
         * This is taken out of the disovery document. Can be set manually too.
         */
        this.jwks = null;
        /**
         * Map with additional query parameter that are appended to
         * the request when initializing implicit flow.
         */
        this.customQueryParams = null;
        this.silentRefreshIFrameName = 'angular-oauth-oidc-silent-refresh-iframe';
        /**
         * Defines when the token_timeout event should be raised.
         * If you set this to the default value 0.75, the event
         * is triggered after 75% of the token's life time.
         */
        this.timeoutFactor = 0.75;
        /**
         * If true, the lib will try to check whether the user
         * is still logged in on a regular basis as described
         * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionChecksEnabled = false;
        /**
         * Interval in msec for checking the session
         * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionCheckIntervall = 3 * 1000;
        /**
         * Url for the iframe used for session checks
         */
        this.sessionCheckIFrameUrl = null;
        /**
         * Name of the iframe to use for session checks
         */
        this.sessionCheckIFrameName = 'angular-oauth-oidc-check-session-iframe';
        /**
         * This property has been introduced to disable at_hash checks
         * and is indented for Identity Provider that does not deliver
         * an at_hash EVEN THOUGH its recommended by the OIDC specs.
         * Of course, when disabling these checks the we are bypassing
         * a security check which means we are more vulnerable.
         */
        this.disableAtHashCheck = false;
        /**
         * Defines wether to check the subject of a refreshed token after silent refresh.
         * Normally, it should be the same as before.
         */
        this.skipSubjectCheck = false;
        this.useIdTokenHintForSilentRefresh = false;
        /**
         * Defined whether to skip the validation of the issuer in the discovery document.
         * Normally, the discovey document's url starts with the url of the issuer.
         */
        this.skipIssuerCheck = false;
        /**
         * final state sent to issuer is built as follows:
         * state = nonce + nonceStateSeparator + additional state
         * Default separator is ';' (encoded %3B).
         * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
         */
        this.nonceStateSeparator = ';';
        /**
         * Set this to true to use HTTP BASIC auth for password flow
         */
        this.useHttpBasicAuth = false;
        /**
         * Code Flow is by defauld used together with PKCI which is also higly recommented.
         * You can disbale it here by setting this flag to true.
         * https://tools.ietf.org/html/rfc7636#section-1.1
         */
        this.disablePKCE = false;
        /**
         * This property allows you to override the method that is used to open the login url,
         * allowing a way for implementations to specify their own method of routing to new
         * urls.
         */
        this.openUri = (/**
         * @param {?} uri
         * @return {?}
         */
        uri => {
            location.href = uri;
        });
        if (json) {
            Object.assign(this, json);
        }
    }
}
if (false) {
    /**
     * The client's id as registered with the auth server
     * @type {?}
     */
    AuthConfig.prototype.clientId;
    /**
     * The client's redirectUri as registered with the auth server
     * @type {?}
     */
    AuthConfig.prototype.redirectUri;
    /**
     * An optional second redirectUri where the auth server
     * redirects the user to after logging out.
     * @type {?}
     */
    AuthConfig.prototype.postLogoutRedirectUri;
    /**
     * The auth server's endpoint that allows to log
     * the user in when using implicit flow.
     * @type {?}
     */
    AuthConfig.prototype.loginUrl;
    /**
     * The requested scopes
     * @type {?}
     */
    AuthConfig.prototype.scope;
    /** @type {?} */
    AuthConfig.prototype.resource;
    /** @type {?} */
    AuthConfig.prototype.rngUrl;
    /**
     * Defines whether to use OpenId Connect during
     * implicit flow.
     * @type {?}
     */
    AuthConfig.prototype.oidc;
    /**
     * Defines whether to request an access token during
     * implicit flow.
     * @type {?}
     */
    AuthConfig.prototype.requestAccessToken;
    /** @type {?} */
    AuthConfig.prototype.options;
    /**
     * The issuer's uri.
     * @type {?}
     */
    AuthConfig.prototype.issuer;
    /**
     * The logout url.
     * @type {?}
     */
    AuthConfig.prototype.logoutUrl;
    /**
     * Defines whether to clear the hash fragment after logging in.
     * @type {?}
     */
    AuthConfig.prototype.clearHashAfterLogin;
    /**
     * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
     * @type {?}
     */
    AuthConfig.prototype.tokenEndpoint;
    /**
     * Url of the userinfo endpoint as defined by OpenId Connect.
     * @type {?}
     */
    AuthConfig.prototype.userinfoEndpoint;
    /** @type {?} */
    AuthConfig.prototype.responseType;
    /**
     * Defines whether additional debug information should
     * be shown at the console. Note that in certain browsers
     * the verbosity of the console needs to be explicitly set
     * to include Debug level messages.
     * @type {?}
     */
    AuthConfig.prototype.showDebugInformation;
    /**
     * The redirect uri used when doing silent refresh.
     * @type {?}
     */
    AuthConfig.prototype.silentRefreshRedirectUri;
    /** @type {?} */
    AuthConfig.prototype.silentRefreshMessagePrefix;
    /**
     * Set this to true to display the iframe used for
     * silent refresh for debugging.
     * @type {?}
     */
    AuthConfig.prototype.silentRefreshShowIFrame;
    /**
     * Timeout for silent refresh.
     * \@internal
     * depreacted b/c of typo, see silentRefreshTimeout
     * @type {?}
     */
    AuthConfig.prototype.siletRefreshTimeout;
    /**
     * Timeout for silent refresh.
     * @type {?}
     */
    AuthConfig.prototype.silentRefreshTimeout;
    /**
     * Some auth servers don't allow using password flow
     * w/o a client secret while the standards do not
     * demand for it. In this case, you can set a password
     * here. As this password is exposed to the public
     * it does not bring additional security and is therefore
     * as good as using no password.
     * @type {?}
     */
    AuthConfig.prototype.dummyClientSecret;
    /**
     * Defines whether https is required.
     * The default value is remoteOnly which only allows
     * http for localhost, while every other domains need
     * to be used with https.
     * @type {?}
     */
    AuthConfig.prototype.requireHttps;
    /**
     * Defines whether every url provided by the discovery
     * document has to start with the issuer's url.
     * @type {?}
     */
    AuthConfig.prototype.strictDiscoveryDocumentValidation;
    /**
     * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
     * with keys used to validate received id_tokens.
     * This is taken out of the disovery document. Can be set manually too.
     * @type {?}
     */
    AuthConfig.prototype.jwks;
    /**
     * Map with additional query parameter that are appended to
     * the request when initializing implicit flow.
     * @type {?}
     */
    AuthConfig.prototype.customQueryParams;
    /** @type {?} */
    AuthConfig.prototype.silentRefreshIFrameName;
    /**
     * Defines when the token_timeout event should be raised.
     * If you set this to the default value 0.75, the event
     * is triggered after 75% of the token's life time.
     * @type {?}
     */
    AuthConfig.prototype.timeoutFactor;
    /**
     * If true, the lib will try to check whether the user
     * is still logged in on a regular basis as described
     * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
     * @type {?}
     */
    AuthConfig.prototype.sessionChecksEnabled;
    /**
     * Interval in msec for checking the session
     * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
     * @type {?}
     */
    AuthConfig.prototype.sessionCheckIntervall;
    /**
     * Url for the iframe used for session checks
     * @type {?}
     */
    AuthConfig.prototype.sessionCheckIFrameUrl;
    /**
     * Name of the iframe to use for session checks
     * @type {?}
     */
    AuthConfig.prototype.sessionCheckIFrameName;
    /**
     * This property has been introduced to disable at_hash checks
     * and is indented for Identity Provider that does not deliver
     * an at_hash EVEN THOUGH its recommended by the OIDC specs.
     * Of course, when disabling these checks the we are bypassing
     * a security check which means we are more vulnerable.
     * @type {?}
     */
    AuthConfig.prototype.disableAtHashCheck;
    /**
     * Defines wether to check the subject of a refreshed token after silent refresh.
     * Normally, it should be the same as before.
     * @type {?}
     */
    AuthConfig.prototype.skipSubjectCheck;
    /** @type {?} */
    AuthConfig.prototype.useIdTokenHintForSilentRefresh;
    /**
     * Defined whether to skip the validation of the issuer in the discovery document.
     * Normally, the discovey document's url starts with the url of the issuer.
     * @type {?}
     */
    AuthConfig.prototype.skipIssuerCheck;
    /**
     * According to rfc6749 it is recommended (but not required) that the auth
     * server exposes the access_token's life time in seconds.
     * This is a fallback value for the case this value is not exposed.
     * @type {?}
     */
    AuthConfig.prototype.fallbackAccessTokenExpirationTimeInSec;
    /**
     * final state sent to issuer is built as follows:
     * state = nonce + nonceStateSeparator + additional state
     * Default separator is ';' (encoded %3B).
     * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
     * @type {?}
     */
    AuthConfig.prototype.nonceStateSeparator;
    /**
     * Set this to true to use HTTP BASIC auth for password flow
     * @type {?}
     */
    AuthConfig.prototype.useHttpBasicAuth;
    /**
     * The window of time (in seconds) to allow the current time to deviate when validating id_token's iat and exp values.
     * @type {?}
     */
    AuthConfig.prototype.clockSkewInSec;
    /**
     * Code Flow is by defauld used together with PKCI which is also higly recommented.
     * You can disbale it here by setting this flag to true.
     * https://tools.ietf.org/html/rfc7636#section-1.1
     * @type {?}
     */
    AuthConfig.prototype.disablePKCE;
    /**
     * This property allows you to override the method that is used to open the login url,
     * allowing a way for implementations to specify their own method of routing to new
     * urls.
     * @type {?}
     */
    AuthConfig.prototype.openUri;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWcuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsiYXV0aC5jb25maWcudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7OztBQUFBLE1BQU0sT0FBTyxVQUFVOzs7O0lBc09yQixZQUFZLElBQTBCOzs7O1FBbE8vQixhQUFRLEdBQUksRUFBRSxDQUFDOzs7O1FBS2YsZ0JBQVcsR0FBSSxFQUFFLENBQUM7Ozs7O1FBTWxCLDBCQUFxQixHQUFJLEVBQUUsQ0FBQzs7Ozs7UUFNNUIsYUFBUSxHQUFJLEVBQUUsQ0FBQzs7OztRQUtmLFVBQUssR0FBSSxnQkFBZ0IsQ0FBQztRQUUxQixhQUFRLEdBQUksRUFBRSxDQUFDO1FBRWYsV0FBTSxHQUFJLEVBQUUsQ0FBQzs7Ozs7UUFNYixTQUFJLEdBQUksSUFBSSxDQUFDOzs7OztRQU1iLHVCQUFrQixHQUFJLElBQUksQ0FBQztRQUUzQixZQUFPLEdBQVMsSUFBSSxDQUFDOzs7O1FBS3JCLFdBQU0sR0FBSSxFQUFFLENBQUM7Ozs7UUFLYixjQUFTLEdBQUksRUFBRSxDQUFDOzs7O1FBS2hCLHdCQUFtQixHQUFJLElBQUksQ0FBQzs7OztRQUs1QixrQkFBYSxHQUFZLElBQUksQ0FBQzs7OztRQUs5QixxQkFBZ0IsR0FBWSxJQUFJLENBQUM7UUFFakMsaUJBQVksR0FBSSxFQUFFLENBQUM7Ozs7Ozs7UUFRbEIseUJBQW9CLEdBQUksS0FBSyxDQUFDOzs7O1FBSy9CLDZCQUF3QixHQUFJLEVBQUUsQ0FBQztRQUUvQiwrQkFBMEIsR0FBSSxFQUFFLENBQUM7Ozs7O1FBTWpDLDRCQUF1QixHQUFJLEtBQUssQ0FBQzs7Ozs7O1FBT2pDLHdCQUFtQixHQUFZLElBQUksR0FBRyxFQUFFLENBQUM7Ozs7UUFLekMseUJBQW9CLEdBQVksSUFBSSxHQUFHLEVBQUUsQ0FBQzs7Ozs7Ozs7O1FBVTFDLHNCQUFpQixHQUFZLElBQUksQ0FBQzs7Ozs7OztRQVFsQyxpQkFBWSxHQUE0QixZQUFZLENBQUM7Ozs7O1FBTXJELHNDQUFpQyxHQUFJLElBQUksQ0FBQzs7Ozs7O1FBTzFDLFNBQUksR0FBWSxJQUFJLENBQUM7Ozs7O1FBTXJCLHNCQUFpQixHQUFZLElBQUksQ0FBQztRQUVsQyw0QkFBdUIsR0FBSSwwQ0FBMEMsQ0FBQzs7Ozs7O1FBT3RFLGtCQUFhLEdBQUksSUFBSSxDQUFDOzs7Ozs7UUFPdEIseUJBQW9CLEdBQUksS0FBSyxDQUFDOzs7OztRQU05QiwwQkFBcUIsR0FBSSxDQUFDLEdBQUcsSUFBSSxDQUFDOzs7O1FBS2xDLDBCQUFxQixHQUFZLElBQUksQ0FBQzs7OztRQUt0QywyQkFBc0IsR0FBSSx5Q0FBeUMsQ0FBQzs7Ozs7Ozs7UUFTcEUsdUJBQWtCLEdBQUksS0FBSyxDQUFDOzs7OztRQU01QixxQkFBZ0IsR0FBSSxLQUFLLENBQUM7UUFFMUIsbUNBQThCLEdBQUksS0FBSyxDQUFDOzs7OztRQU14QyxvQkFBZSxHQUFJLEtBQUssQ0FBQzs7Ozs7OztRQWV6Qix3QkFBbUIsR0FBSSxHQUFHLENBQUM7Ozs7UUFLM0IscUJBQWdCLEdBQUksS0FBSyxDQUFDOzs7Ozs7UUFZMUIsZ0JBQVcsR0FBSSxLQUFLLENBQUM7Ozs7OztRQWFyQixZQUFPOzs7O1FBQTZCLEdBQUcsQ0FBQyxFQUFFO1lBQy9DLFFBQVEsQ0FBQyxJQUFJLEdBQUcsR0FBRyxDQUFDO1FBQ3RCLENBQUMsRUFBQTtRQVpDLElBQUksSUFBSSxFQUFFO1lBQ1IsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUM7U0FDM0I7SUFDSCxDQUFDO0NBVUY7Ozs7OztJQWhQQyw4QkFBc0I7Ozs7O0lBS3RCLGlDQUF5Qjs7Ozs7O0lBTXpCLDJDQUFtQzs7Ozs7O0lBTW5DLDhCQUFzQjs7Ozs7SUFLdEIsMkJBQWlDOztJQUVqQyw4QkFBc0I7O0lBRXRCLDRCQUFvQjs7Ozs7O0lBTXBCLDBCQUFvQjs7Ozs7O0lBTXBCLHdDQUFrQzs7SUFFbEMsNkJBQTRCOzs7OztJQUs1Qiw0QkFBb0I7Ozs7O0lBS3BCLCtCQUF1Qjs7Ozs7SUFLdkIseUNBQW1DOzs7OztJQUtuQyxtQ0FBcUM7Ozs7O0lBS3JDLHNDQUF3Qzs7SUFFeEMsa0NBQTBCOzs7Ozs7OztJQVF6QiwwQ0FBcUM7Ozs7O0lBS3RDLDhDQUFzQzs7SUFFdEMsZ0RBQXdDOzs7Ozs7SUFNeEMsNkNBQXdDOzs7Ozs7O0lBT3hDLHlDQUFnRDs7Ozs7SUFLaEQsMENBQWlEOzs7Ozs7Ozs7O0lBVWpELHVDQUF5Qzs7Ozs7Ozs7SUFRekMsa0NBQTREOzs7Ozs7SUFNNUQsdURBQWlEOzs7Ozs7O0lBT2pELDBCQUE0Qjs7Ozs7O0lBTTVCLHVDQUF5Qzs7SUFFekMsNkNBQTZFOzs7Ozs7O0lBTzdFLG1DQUE2Qjs7Ozs7OztJQU83QiwwQ0FBcUM7Ozs7OztJQU1yQywyQ0FBeUM7Ozs7O0lBS3pDLDJDQUE2Qzs7Ozs7SUFLN0MsNENBQTJFOzs7Ozs7Ozs7SUFTM0Usd0NBQW1DOzs7Ozs7SUFNbkMsc0NBQWlDOztJQUVqQyxvREFBK0M7Ozs7OztJQU0vQyxxQ0FBZ0M7Ozs7Ozs7SUFPaEMsNERBQXVEOzs7Ozs7OztJQVF2RCx5Q0FBa0M7Ozs7O0lBS2xDLHNDQUFpQzs7Ozs7SUFLakMsb0NBQTRCOzs7Ozs7O0lBTzVCLGlDQUE0Qjs7Ozs7OztJQWE1Qiw2QkFFQyIsInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBjbGFzcyBBdXRoQ29uZmlnIHtcbiAgLyoqXG4gICAqIFRoZSBjbGllbnQncyBpZCBhcyByZWdpc3RlcmVkIHdpdGggdGhlIGF1dGggc2VydmVyXG4gICAqL1xuICBwdWJsaWMgY2xpZW50SWQ/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSBjbGllbnQncyByZWRpcmVjdFVyaSBhcyByZWdpc3RlcmVkIHdpdGggdGhlIGF1dGggc2VydmVyXG4gICAqL1xuICBwdWJsaWMgcmVkaXJlY3RVcmk/ID0gJyc7XG5cbiAgLyoqXG4gICAqIEFuIG9wdGlvbmFsIHNlY29uZCByZWRpcmVjdFVyaSB3aGVyZSB0aGUgYXV0aCBzZXJ2ZXJcbiAgICogcmVkaXJlY3RzIHRoZSB1c2VyIHRvIGFmdGVyIGxvZ2dpbmcgb3V0LlxuICAgKi9cbiAgcHVibGljIHBvc3RMb2dvdXRSZWRpcmVjdFVyaT8gPSAnJztcblxuICAvKipcbiAgICogVGhlIGF1dGggc2VydmVyJ3MgZW5kcG9pbnQgdGhhdCBhbGxvd3MgdG8gbG9nXG4gICAqIHRoZSB1c2VyIGluIHdoZW4gdXNpbmcgaW1wbGljaXQgZmxvdy5cbiAgICovXG4gIHB1YmxpYyBsb2dpblVybD8gPSAnJztcblxuICAvKipcbiAgICogVGhlIHJlcXVlc3RlZCBzY29wZXNcbiAgICovXG4gIHB1YmxpYyBzY29wZT8gPSAnb3BlbmlkIHByb2ZpbGUnO1xuXG4gIHB1YmxpYyByZXNvdXJjZT8gPSAnJztcblxuICBwdWJsaWMgcm5nVXJsPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgdG8gdXNlIE9wZW5JZCBDb25uZWN0IGR1cmluZ1xuICAgKiBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIG9pZGM/ID0gdHJ1ZTtcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIHJlcXVlc3QgYW4gYWNjZXNzIHRva2VuIGR1cmluZ1xuICAgKiBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIHJlcXVlc3RBY2Nlc3NUb2tlbj8gPSB0cnVlO1xuXG4gIHB1YmxpYyBvcHRpb25zPzogYW55ID0gbnVsbDtcblxuICAvKipcbiAgICogVGhlIGlzc3VlcidzIHVyaS5cbiAgICovXG4gIHB1YmxpYyBpc3N1ZXI/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSBsb2dvdXQgdXJsLlxuICAgKi9cbiAgcHVibGljIGxvZ291dFVybD8gPSAnJztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIGNsZWFyIHRoZSBoYXNoIGZyYWdtZW50IGFmdGVyIGxvZ2dpbmcgaW4uXG4gICAqL1xuICBwdWJsaWMgY2xlYXJIYXNoQWZ0ZXJMb2dpbj8gPSB0cnVlO1xuXG4gIC8qKlxuICAgKiBVcmwgb2YgdGhlIHRva2VuIGVuZHBvaW50IGFzIGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QgYW5kIE9BdXRoIDIuXG4gICAqL1xuICBwdWJsaWMgdG9rZW5FbmRwb2ludD86IHN0cmluZyA9IG51bGw7XG5cbiAgLyoqXG4gICAqIFVybCBvZiB0aGUgdXNlcmluZm8gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cbiAgICovXG4gIHB1YmxpYyB1c2VyaW5mb0VuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcblxuICBwdWJsaWMgcmVzcG9uc2VUeXBlPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgYWRkaXRpb25hbCBkZWJ1ZyBpbmZvcm1hdGlvbiBzaG91bGRcbiAgICogYmUgc2hvd24gYXQgdGhlIGNvbnNvbGUuIE5vdGUgdGhhdCBpbiBjZXJ0YWluIGJyb3dzZXJzXG4gICAqIHRoZSB2ZXJib3NpdHkgb2YgdGhlIGNvbnNvbGUgbmVlZHMgdG8gYmUgZXhwbGljaXRseSBzZXRcbiAgICogdG8gaW5jbHVkZSBEZWJ1ZyBsZXZlbCBtZXNzYWdlcy5cbiAgICovXG4gICBwdWJsaWMgc2hvd0RlYnVnSW5mb3JtYXRpb24/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRoZSByZWRpcmVjdCB1cmkgdXNlZCB3aGVuIGRvaW5nIHNpbGVudCByZWZyZXNoLlxuICAgKi9cbiAgcHVibGljIHNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaT8gPSAnJztcblxuICBwdWJsaWMgc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXg/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFNldCB0aGlzIHRvIHRydWUgdG8gZGlzcGxheSB0aGUgaWZyYW1lIHVzZWQgZm9yXG4gICAqIHNpbGVudCByZWZyZXNoIGZvciBkZWJ1Z2dpbmcuXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFNob3dJRnJhbWU/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRpbWVvdXQgZm9yIHNpbGVudCByZWZyZXNoLlxuICAgKiBAaW50ZXJuYWxcbiAgICogZGVwcmVhY3RlZCBiL2Mgb2YgdHlwbywgc2VlIHNpbGVudFJlZnJlc2hUaW1lb3V0XG4gICAqL1xuICBwdWJsaWMgc2lsZXRSZWZyZXNoVGltZW91dD86IG51bWJlciA9IDEwMDAgKiAyMDtcblxuICAvKipcbiAgICogVGltZW91dCBmb3Igc2lsZW50IHJlZnJlc2guXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFRpbWVvdXQ/OiBudW1iZXIgPSAxMDAwICogMjA7XG5cbiAgLyoqXG4gICAqIFNvbWUgYXV0aCBzZXJ2ZXJzIGRvbid0IGFsbG93IHVzaW5nIHBhc3N3b3JkIGZsb3dcbiAgICogdy9vIGEgY2xpZW50IHNlY3JldCB3aGlsZSB0aGUgc3RhbmRhcmRzIGRvIG5vdFxuICAgKiBkZW1hbmQgZm9yIGl0LiBJbiB0aGlzIGNhc2UsIHlvdSBjYW4gc2V0IGEgcGFzc3dvcmRcbiAgICogaGVyZS4gQXMgdGhpcyBwYXNzd29yZCBpcyBleHBvc2VkIHRvIHRoZSBwdWJsaWNcbiAgICogaXQgZG9lcyBub3QgYnJpbmcgYWRkaXRpb25hbCBzZWN1cml0eSBhbmQgaXMgdGhlcmVmb3JlXG4gICAqIGFzIGdvb2QgYXMgdXNpbmcgbm8gcGFzc3dvcmQuXG4gICAqL1xuICBwdWJsaWMgZHVtbXlDbGllbnRTZWNyZXQ/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgaHR0cHMgaXMgcmVxdWlyZWQuXG4gICAqIFRoZSBkZWZhdWx0IHZhbHVlIGlzIHJlbW90ZU9ubHkgd2hpY2ggb25seSBhbGxvd3NcbiAgICogaHR0cCBmb3IgbG9jYWxob3N0LCB3aGlsZSBldmVyeSBvdGhlciBkb21haW5zIG5lZWRcbiAgICogdG8gYmUgdXNlZCB3aXRoIGh0dHBzLlxuICAgKi9cbiAgcHVibGljIHJlcXVpcmVIdHRwcz86IGJvb2xlYW4gfCAncmVtb3RlT25seScgPSAncmVtb3RlT25seSc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciBldmVyeSB1cmwgcHJvdmlkZWQgYnkgdGhlIGRpc2NvdmVyeVxuICAgKiBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyJ3MgdXJsLlxuICAgKi9cbiAgcHVibGljIHN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbj8gPSB0cnVlO1xuXG4gIC8qKlxuICAgKiBKU09OIFdlYiBLZXkgU2V0IChodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzUxNylcbiAgICogd2l0aCBrZXlzIHVzZWQgdG8gdmFsaWRhdGUgcmVjZWl2ZWQgaWRfdG9rZW5zLlxuICAgKiBUaGlzIGlzIHRha2VuIG91dCBvZiB0aGUgZGlzb3ZlcnkgZG9jdW1lbnQuIENhbiBiZSBzZXQgbWFudWFsbHkgdG9vLlxuICAgKi9cbiAgcHVibGljIGp3a3M/OiBvYmplY3QgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBNYXAgd2l0aCBhZGRpdGlvbmFsIHF1ZXJ5IHBhcmFtZXRlciB0aGF0IGFyZSBhcHBlbmRlZCB0b1xuICAgKiB0aGUgcmVxdWVzdCB3aGVuIGluaXRpYWxpemluZyBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIGN1c3RvbVF1ZXJ5UGFyYW1zPzogb2JqZWN0ID0gbnVsbDtcblxuICBwdWJsaWMgc2lsZW50UmVmcmVzaElGcmFtZU5hbWU/ID0gJ2FuZ3VsYXItb2F1dGgtb2lkYy1zaWxlbnQtcmVmcmVzaC1pZnJhbWUnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZW4gdGhlIHRva2VuX3RpbWVvdXQgZXZlbnQgc2hvdWxkIGJlIHJhaXNlZC5cbiAgICogSWYgeW91IHNldCB0aGlzIHRvIHRoZSBkZWZhdWx0IHZhbHVlIDAuNzUsIHRoZSBldmVudFxuICAgKiBpcyB0cmlnZ2VyZWQgYWZ0ZXIgNzUlIG9mIHRoZSB0b2tlbidzIGxpZmUgdGltZS5cbiAgICovXG4gIHB1YmxpYyB0aW1lb3V0RmFjdG9yPyA9IDAuNzU7XG5cbiAgLyoqXG4gICAqIElmIHRydWUsIHRoZSBsaWIgd2lsbCB0cnkgdG8gY2hlY2sgd2hldGhlciB0aGUgdXNlclxuICAgKiBpcyBzdGlsbCBsb2dnZWQgaW4gb24gYSByZWd1bGFyIGJhc2lzIGFzIGRlc2NyaWJlZFxuICAgKiBpbiBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1zZXNzaW9uLTFfMC5odG1sI0NoYW5nZU5vdGlmaWNhdGlvblxuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja3NFbmFibGVkPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBJbnRlcnZhbCBpbiBtc2VjIGZvciBjaGVja2luZyB0aGUgc2Vzc2lvblxuICAgKiBhY2NvcmRpbmcgdG8gaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3Qtc2Vzc2lvbi0xXzAuaHRtbCNDaGFuZ2VOb3RpZmljYXRpb25cbiAgICovXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJbnRlcnZhbGw/ID0gMyAqIDEwMDA7XG5cbiAgLyoqXG4gICAqIFVybCBmb3IgdGhlIGlmcmFtZSB1c2VkIGZvciBzZXNzaW9uIGNoZWNrc1xuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja0lGcmFtZVVybD86IHN0cmluZyA9IG51bGw7XG5cbiAgLyoqXG4gICAqIE5hbWUgb2YgdGhlIGlmcmFtZSB0byB1c2UgZm9yIHNlc3Npb24gY2hlY2tzXG4gICAqL1xuICBwdWJsaWMgc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZT8gPSAnYW5ndWxhci1vYXV0aC1vaWRjLWNoZWNrLXNlc3Npb24taWZyYW1lJztcblxuICAvKipcbiAgICogVGhpcyBwcm9wZXJ0eSBoYXMgYmVlbiBpbnRyb2R1Y2VkIHRvIGRpc2FibGUgYXRfaGFzaCBjaGVja3NcbiAgICogYW5kIGlzIGluZGVudGVkIGZvciBJZGVudGl0eSBQcm92aWRlciB0aGF0IGRvZXMgbm90IGRlbGl2ZXJcbiAgICogYW4gYXRfaGFzaCBFVkVOIFRIT1VHSCBpdHMgcmVjb21tZW5kZWQgYnkgdGhlIE9JREMgc3BlY3MuXG4gICAqIE9mIGNvdXJzZSwgd2hlbiBkaXNhYmxpbmcgdGhlc2UgY2hlY2tzIHRoZSB3ZSBhcmUgYnlwYXNzaW5nXG4gICAqIGEgc2VjdXJpdHkgY2hlY2sgd2hpY2ggbWVhbnMgd2UgYXJlIG1vcmUgdnVsbmVyYWJsZS5cbiAgICovXG4gIHB1YmxpYyBkaXNhYmxlQXRIYXNoQ2hlY2s/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2V0aGVyIHRvIGNoZWNrIHRoZSBzdWJqZWN0IG9mIGEgcmVmcmVzaGVkIHRva2VuIGFmdGVyIHNpbGVudCByZWZyZXNoLlxuICAgKiBOb3JtYWxseSwgaXQgc2hvdWxkIGJlIHRoZSBzYW1lIGFzIGJlZm9yZS5cbiAgICovXG4gIHB1YmxpYyBza2lwU3ViamVjdENoZWNrPyA9IGZhbHNlO1xuXG4gIHB1YmxpYyB1c2VJZFRva2VuSGludEZvclNpbGVudFJlZnJlc2g/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIERlZmluZWQgd2hldGhlciB0byBza2lwIHRoZSB2YWxpZGF0aW9uIG9mIHRoZSBpc3N1ZXIgaW4gdGhlIGRpc2NvdmVyeSBkb2N1bWVudC5cbiAgICogTm9ybWFsbHksIHRoZSBkaXNjb3ZleSBkb2N1bWVudCdzIHVybCBzdGFydHMgd2l0aCB0aGUgdXJsIG9mIHRoZSBpc3N1ZXIuXG4gICAqL1xuICBwdWJsaWMgc2tpcElzc3VlckNoZWNrPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBBY2NvcmRpbmcgdG8gcmZjNjc0OSBpdCBpcyByZWNvbW1lbmRlZCAoYnV0IG5vdCByZXF1aXJlZCkgdGhhdCB0aGUgYXV0aFxuICAgKiBzZXJ2ZXIgZXhwb3NlcyB0aGUgYWNjZXNzX3Rva2VuJ3MgbGlmZSB0aW1lIGluIHNlY29uZHMuXG4gICAqIFRoaXMgaXMgYSBmYWxsYmFjayB2YWx1ZSBmb3IgdGhlIGNhc2UgdGhpcyB2YWx1ZSBpcyBub3QgZXhwb3NlZC5cbiAgICovXG4gIHB1YmxpYyBmYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYz86IG51bWJlcjtcblxuICAvKipcbiAgICogZmluYWwgc3RhdGUgc2VudCB0byBpc3N1ZXIgaXMgYnVpbHQgYXMgZm9sbG93czpcbiAgICogc3RhdGUgPSBub25jZSArIG5vbmNlU3RhdGVTZXBhcmF0b3IgKyBhZGRpdGlvbmFsIHN0YXRlXG4gICAqIERlZmF1bHQgc2VwYXJhdG9yIGlzICc7JyAoZW5jb2RlZCAlM0IpLlxuICAgKiBJbiByYXJlIGNhc2VzLCB0aGlzIGNoYXJhY3RlciBtaWdodCBiZSBmb3JiaWRkZW4gb3IgaW5jb252ZW5pZW50IHRvIHVzZSBieSB0aGUgaXNzdWVyIHNvIGl0IGNhbiBiZSBjdXN0b21pemVkLlxuICAgKi9cbiAgcHVibGljIG5vbmNlU3RhdGVTZXBhcmF0b3I/ID0gJzsnO1xuXG4gIC8qKlxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIHVzZSBIVFRQIEJBU0lDIGF1dGggZm9yIHBhc3N3b3JkIGZsb3dcbiAgICovXG4gIHB1YmxpYyB1c2VIdHRwQmFzaWNBdXRoPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBUaGUgd2luZG93IG9mIHRpbWUgKGluIHNlY29uZHMpIHRvIGFsbG93IHRoZSBjdXJyZW50IHRpbWUgdG8gZGV2aWF0ZSB3aGVuIHZhbGlkYXRpbmcgaWRfdG9rZW4ncyBpYXQgYW5kIGV4cCB2YWx1ZXMuXG4gICAqL1xuICBwdWJsaWMgY2xvY2tTa2V3SW5TZWM/OiA2MDA7XG5cbiAgLyoqXG4gICAqIENvZGUgRmxvdyBpcyBieSBkZWZhdWxkIHVzZWQgdG9nZXRoZXIgd2l0aCBQS0NJIHdoaWNoIGlzIGFsc28gaGlnbHkgcmVjb21tZW50ZWQuXG4gICAqIFlvdSBjYW4gZGlzYmFsZSBpdCBoZXJlIGJ5IHNldHRpbmcgdGhpcyBmbGFnIHRvIHRydWUuXG4gICAqIGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM3NjM2I3NlY3Rpb24tMS4xXG4gICAqL1xuICBwdWJsaWMgZGlzYWJsZVBLQ0U/ID0gZmFsc2U7XG5cbiAgY29uc3RydWN0b3IoanNvbj86IFBhcnRpYWw8QXV0aENvbmZpZz4pIHtcbiAgICBpZiAoanNvbikge1xuICAgICAgT2JqZWN0LmFzc2lnbih0aGlzLCBqc29uKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBwcm9wZXJ0eSBhbGxvd3MgeW91IHRvIG92ZXJyaWRlIHRoZSBtZXRob2QgdGhhdCBpcyB1c2VkIHRvIG9wZW4gdGhlIGxvZ2luIHVybCxcbiAgICogYWxsb3dpbmcgYSB3YXkgZm9yIGltcGxlbWVudGF0aW9ucyB0byBzcGVjaWZ5IHRoZWlyIG93biBtZXRob2Qgb2Ygcm91dGluZyB0byBuZXdcbiAgICogdXJscy5cbiAgICovXG4gIHB1YmxpYyBvcGVuVXJpPzogKCh1cmk6IHN0cmluZykgPT4gdm9pZCkgPSB1cmkgPT4ge1xuICAgIGxvY2F0aW9uLmhyZWYgPSB1cmk7XG4gIH1cbn1cbiJdfQ==