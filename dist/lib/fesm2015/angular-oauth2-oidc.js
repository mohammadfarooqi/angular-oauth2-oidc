import { Injectable, NgZone, Optional, NgModule, InjectionToken } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpHeaders, HttpParams, HttpClient, HTTP_INTERCEPTORS } from '@angular/common/http';
import { __awaiter } from 'tslib';
import { Subject, of, from, race, throwError, merge } from 'rxjs';
import { filter, tap, delay, switchMap, map, first, catchError, timeout, take, mergeMap } from 'rxjs/operators';
import { KEYUTIL, KJUR } from 'jsrsasign';

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Additional options that can be passt to tryLogin.
 */
class LoginOptions {
    constructor() {
        /**
         * Normally, you want to clear your hash fragment after
         * the lib read the token(s) so that they are not displayed
         * anymore in the url. If not, set this to true.
         */
        this.preventClearHashAfterLogin = false;
    }
}
/**
 * Defines the logging interface the OAuthService uses
 * internally. Is compatible with the `console` object,
 * but you can provide your own implementation as well
 * through dependency injection.
 * @abstract
 */
class OAuthLogger {
}
/**
 * Defines a simple storage that can be used for
 * storing the tokens at client side.
 * Is compatible to localStorage and sessionStorage,
 * but you can also create your own implementations.
 * @abstract
 */
class OAuthStorage {
}
/**
 * Represents the received tokens, the received state
 * and the parsed claims from the id-token.
 */
class ReceivedTokens {
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
// see: https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding#The_.22Unicode_Problem.22
/**
 * @param {?} str
 * @return {?}
 */
function b64DecodeUnicode(str) {
    /** @type {?} */
    const base64 = str.replace(/\-/g, '+').replace(/\_/g, '/');
    return decodeURIComponent(atob(base64)
        .split('')
        .map((/**
     * @param {?} c
     * @return {?}
     */
    function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }))
        .join(''));
}
/**
 * @param {?} str
 * @return {?}
 */
function base64UrlEncode(str) {
    /** @type {?} */
    const base64 = btoa(str);
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 * @abstract
 */
class ValidationHandler {
}
/**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 * @abstract
 */
class AbstractValidationHandler {
    /**
     * Validates the at_hash in an id_token against the received access_token.
     * @param {?} params
     * @return {?}
     */
    validateAtHash(params) {
        return __awaiter(this, void 0, void 0, function* () {
            /** @type {?} */
            let hashAlg = this.inferHashAlgorithm(params.idTokenHeader);
            /** @type {?} */
            let tokenHash = yield this.calcHash(params.accessToken, hashAlg);
            // sha256(accessToken, { asString: true });
            /** @type {?} */
            let leftMostHalf = tokenHash.substr(0, tokenHash.length / 2);
            /** @type {?} */
            let atHash = base64UrlEncode(leftMostHalf);
            /** @type {?} */
            let claimsAtHash = params.idTokenClaims['at_hash'].replace(/=/g, '');
            if (atHash !== claimsAtHash) {
                console.error('exptected at_hash: ' + atHash);
                console.error('actual at_hash: ' + claimsAtHash);
            }
            return atHash === claimsAtHash;
        });
    }
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @protected
     * @param {?} jwtHeader the id_token's parsed header
     * @return {?}
     */
    inferHashAlgorithm(jwtHeader) {
        /** @type {?} */
        let alg = jwtHeader['alg'];
        if (!alg.match(/^.S[0-9]{3}$/)) {
            throw new Error('Algorithm not supported: ' + alg);
        }
        return 'sha-' + alg.substr(2);
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class UrlHelperService {
    /**
     * @param {?=} customHashFragment
     * @return {?}
     */
    getHashFragmentParams(customHashFragment) {
        /** @type {?} */
        let hash = customHashFragment || window.location.hash;
        hash = decodeURIComponent(hash);
        if (hash.indexOf('#') !== 0) {
            return {};
        }
        /** @type {?} */
        const questionMarkPosition = hash.indexOf('?');
        if (questionMarkPosition > -1) {
            hash = hash.substr(questionMarkPosition + 1);
        }
        else {
            hash = hash.substr(1);
        }
        return this.parseQueryString(hash);
    }
    /**
     * @param {?} queryString
     * @return {?}
     */
    parseQueryString(queryString) {
        /** @type {?} */
        const data = {};
        /** @type {?} */
        let pairs;
        /** @type {?} */
        let pair;
        /** @type {?} */
        let separatorIndex;
        /** @type {?} */
        let escapedKey;
        /** @type {?} */
        let escapedValue;
        /** @type {?} */
        let key;
        /** @type {?} */
        let value;
        if (queryString === null) {
            return data;
        }
        pairs = queryString.split('&');
        for (let i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf('=');
            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            }
            else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }
            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);
            if (key.substr(0, 1) === '/') {
                key = key.substr(1);
            }
            data[key] = value;
        }
        return data;
    }
}
UrlHelperService.decorators = [
    { type: Injectable }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * @abstract
 */
class OAuthEvent {
    /**
     * @param {?} type
     */
    constructor(type) {
        this.type = type;
    }
}
class OAuthSuccessEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?=} info
     */
    constructor(type, info = null) {
        super(type);
        this.info = info;
    }
}
class OAuthInfoEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?=} info
     */
    constructor(type, info = null) {
        super(type);
        this.info = info;
    }
}
class OAuthErrorEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?} reason
     * @param {?=} params
     */
    constructor(type, reason, params = null) {
        super(type);
        this.reason = reason;
        this.params = params;
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class AuthConfig {
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

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * This custom encoder allows charactes like +, % and / to be used in passwords
 */
class WebHttpUrlEncodingCodec {
    /**
     * @param {?} k
     * @return {?}
     */
    encodeKey(k) {
        return encodeURIComponent(k);
    }
    /**
     * @param {?} v
     * @return {?}
     */
    encodeValue(v) {
        return encodeURIComponent(v);
    }
    /**
     * @param {?} k
     * @return {?}
     */
    decodeKey(k) {
        return decodeURIComponent(k);
    }
    /**
     * @param {?} v
     * @return {?}
     */
    decodeValue(v) {
        return decodeURIComponent(v);
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Abstraction for crypto algorithms
 * @abstract
 */
class CryptoHandler {
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Service for logging in and logging out with
 * OIDC and OAuth2. Supports implicit flow and
 * password flow.
 */
class OAuthService extends AuthConfig {
    /**
     * @param {?} ngZone
     * @param {?} http
     * @param {?} storage
     * @param {?} tokenValidationHandler
     * @param {?} config
     * @param {?} urlHelper
     * @param {?} logger
     * @param {?} crypto
     */
    constructor(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto) {
        super();
        this.ngZone = ngZone;
        this.http = http;
        this.config = config;
        this.urlHelper = urlHelper;
        this.logger = logger;
        this.crypto = crypto;
        /**
         * \@internal
         * Deprecated:  use property events instead
         */
        this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        this.state = '';
        this.eventsSubject = new Subject();
        this.discoveryDocumentLoadedSubject = new Subject();
        this.grantTypesSupported = [];
        this.inImplicitFlow = false;
        this.debug('angular-oauth2-oidc v8-beta');
        this.discoveryDocumentLoaded$ = this.discoveryDocumentLoadedSubject.asObservable();
        this.events = this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            this.configure(config);
        }
        try {
            if (storage) {
                this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).'
                + 'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        this.setupRefreshTimer();
    }
    /**
     * Use this method to configure the service
     * @param {?} config the configuration
     * @return {?}
     */
    configure(config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign((/** @type {?} */ ({})), new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    }
    /**
     * @protected
     * @return {?}
     */
    configChanged() {
        this.setupRefreshTimer();
    }
    /**
     * @return {?}
     */
    restartSessionChecksIfStillLoggedIn() {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    }
    /**
     * @protected
     * @return {?}
     */
    restartRefreshTimerIfStillLoggedIn() {
        this.setupExpirationTimers();
    }
    /**
     * @protected
     * @return {?}
     */
    setupSessionCheck() {
        this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e.type === 'token_received'))).subscribe((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            this.initSessionCheck();
        }));
    }
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param {?=} params Additional parameter to pass
     * @param {?=} listenTo Setup automatic refresh of a specific token type
     * @param {?=} noPrompt
     * @return {?}
     */
    setupAutomaticSilentRefresh(params = {}, listenTo, noPrompt = true) {
        /** @type {?} */
        let shouldRunSilentRefresh = true;
        this.events.pipe(tap((/**
         * @param {?} e
         * @return {?}
         */
        (e) => {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        })), filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e.type === 'token_expires'))).subscribe((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            /** @type {?} */
            const event = (/** @type {?} */ (e));
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) && shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                this.refreshInternal(params, noPrompt).catch((/**
                 * @param {?} _
                 * @return {?}
                 */
                _ => {
                    this.debug('Automatic silent refresh did not work');
                }));
            }
        }));
        this.restartRefreshTimerIfStillLoggedIn();
    }
    /**
     * @protected
     * @param {?} params
     * @param {?} noPrompt
     * @return {?}
     */
    refreshInternal(params, noPrompt) {
        if (this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param {?=} options LoginOptions to pass through to `tryLogin(...)`
     * @return {?}
     */
    loadDiscoveryDocumentAndTryLogin(options = null) {
        return this.loadDiscoveryDocument().then((/**
         * @param {?} doc
         * @return {?}
         */
        doc => {
            return this.tryLogin(options);
        }));
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initImplicitFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param {?=} options LoginOptions to pass through to `tryLogin(...)`
     * @return {?}
     */
    loadDiscoveryDocumentAndLogin(options = null) {
        return this.loadDiscoveryDocumentAndTryLogin(options).then((/**
         * @param {?} _
         * @return {?}
         */
        _ => {
            if (!this.hasValidIdToken() || !this.hasValidAccessToken()) {
                this.initImplicitFlow();
                return false;
            }
            else {
                return true;
            }
        }));
    }
    /**
     * @protected
     * @param {...?} args
     * @return {?}
     */
    debug(...args) {
        if (this.showDebugInformation) {
            this.logger.debug.apply(console, args);
        }
    }
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    validateUrlFromDiscoveryDocument(url) {
        /** @type {?} */
        const errors = [];
        /** @type {?} */
        const httpsCheck = this.validateUrlForHttps(url);
        /** @type {?} */
        const issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    }
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    validateUrlForHttps(url) {
        if (!url) {
            return true;
        }
        /** @type {?} */
        const lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    }
    /**
     * @protected
     * @param {?} url
     * @return {?}
     */
    validateUrlAgainstIssuer(url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    }
    /**
     * @protected
     * @return {?}
     */
    setupRefreshTimer() {
        if (typeof window === 'undefined') {
            this.debug('timer not supported on this plattform');
            return;
        }
        if (this.hasValidIdToken()) {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }
        this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e.type === 'token_received'))).subscribe((/**
         * @param {?} _
         * @return {?}
         */
        _ => {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    setupExpirationTimers() {
        /** @type {?} */
        const idTokenExp = this.getIdTokenExpiration() || Number.MAX_VALUE;
        /** @type {?} */
        const accessTokenExp = this.getAccessTokenExpiration() || Number.MAX_VALUE;
        /** @type {?} */
        const useAccessTokenExp = accessTokenExp <= idTokenExp;
        if (this.hasValidAccessToken() && useAccessTokenExp) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken() && !useAccessTokenExp) {
            this.setupIdTokenTimer();
        }
    }
    /**
     * @protected
     * @return {?}
     */
    setupAccessTokenTimer() {
        /** @type {?} */
        const expiration = this.getAccessTokenExpiration();
        /** @type {?} */
        const storedAt = this.getAccessTokenStoredAt();
        /** @type {?} */
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe((/**
             * @param {?} e
             * @return {?}
             */
            e => {
                this.ngZone.run((/**
                 * @return {?}
                 */
                () => {
                    this.eventsSubject.next(e);
                }));
            }));
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    setupIdTokenTimer() {
        /** @type {?} */
        const expiration = this.getIdTokenExpiration();
        /** @type {?} */
        const storedAt = this.getIdTokenStoredAt();
        /** @type {?} */
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe((/**
             * @param {?} e
             * @return {?}
             */
            e => {
                this.ngZone.run((/**
                 * @return {?}
                 */
                () => {
                    this.eventsSubject.next(e);
                }));
            }));
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    clearAccessTokenTimer() {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    }
    /**
     * @protected
     * @return {?}
     */
    clearIdTokenTimer() {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    }
    /**
     * @protected
     * @param {?} storedAt
     * @param {?} expiration
     * @return {?}
     */
    calcTimeout(storedAt, expiration) {
        /** @type {?} */
        const now = Date.now();
        /** @type {?} */
        const delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    }
    /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param {?} storage
     * @return {?}
     */
    setStorage(storage) {
        this._storage = storage;
        this.configChanged();
    }
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param {?=} fullUrl
     * @return {?}
     */
    loadDiscoveryDocument(fullUrl = null) {
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            if (!fullUrl) {
                fullUrl = this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!this.validateUrlForHttps(fullUrl)) {
                reject('issuer must use https, or config value for property requireHttps must allow http');
                return;
            }
            this.http.get(fullUrl).subscribe((/**
             * @param {?} doc
             * @return {?}
             */
            doc => {
                if (!this.validateDiscoveryDocument(doc)) {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                this.loginUrl = doc.authorization_endpoint;
                this.logoutUrl = doc.end_session_endpoint || this.logoutUrl;
                this.grantTypesSupported = doc.grant_types_supported;
                this.issuer = doc.issuer;
                this.tokenEndpoint = doc.token_endpoint;
                this.userinfoEndpoint = doc.userinfo_endpoint;
                this.jwksUri = doc.jwks_uri;
                this.sessionCheckIFrameUrl = doc.check_session_iframe || this.sessionCheckIFrameUrl;
                this.discoveryDocumentLoaded = true;
                this.discoveryDocumentLoadedSubject.next(doc);
                if (this.sessionChecksEnabled) {
                    this.restartSessionChecksIfStillLoggedIn();
                }
                this.loadJwks()
                    .then((/**
                 * @param {?} jwks
                 * @return {?}
                 */
                jwks => {
                    /** @type {?} */
                    const result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    /** @type {?} */
                    const event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    this.eventsSubject.next(event);
                    resolve(event);
                    return;
                }))
                    .catch((/**
                 * @param {?} err
                 * @return {?}
                 */
                err => {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                }));
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                this.logger.error('error loading discovery document', err);
                this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    loadJwks() {
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            if (this.jwksUri) {
                this.http.get(this.jwksUri).subscribe((/**
                 * @param {?} jwks
                 * @return {?}
                 */
                jwks => {
                    this.jwks = jwks;
                    this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }), (/**
                 * @param {?} err
                 * @return {?}
                 */
                err => {
                    this.logger.error('error loading jwks', err);
                    this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                }));
            }
            else {
                resolve(null);
            }
        }));
    }
    /**
     * @protected
     * @param {?} doc
     * @return {?}
     */
    validateDiscoveryDocument(doc) {
        /** @type {?} */
        let errors;
        if (!this.skipIssuerCheck && doc.issuer !== this.issuer) {
            this.logger.error('invalid issuer in discovery document', 'expected: ' + this.issuer, 'current: ' + doc.issuer);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.authorization_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating authorization_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.end_session_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating end_session_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.token_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating token_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.userinfo_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating userinfo_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.jwks_uri);
        if (errors.length > 0) {
            this.logger.error('error validating jwks_uri in discovery document', errors);
            return false;
        }
        if (this.sessionChecksEnabled && !doc.check_session_iframe) {
            this.logger.warn('sessionChecksEnabled is activated but discovery document' +
                ' does not contain a check_session_iframe field');
        }
        return true;
    }
    /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param {?} userName
     * @param {?} password
     * @param {?=} headers Optional additional http-headers.
     * @return {?}
     */
    fetchTokenUsingPasswordFlowAndLoadUserProfile(userName, password, headers = new HttpHeaders()) {
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then((/**
         * @return {?}
         */
        () => this.loadUserProfile()));
    }
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     * @return {?}
     */
    loadUserProfile() {
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error('userinfoEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            /** @type {?} */
            const headers = new HttpHeaders().set('Authorization', 'Bearer ' + this.getAccessToken());
            this.http.get(this.userinfoEndpoint, { headers }).subscribe((/**
             * @param {?} info
             * @return {?}
             */
            info => {
                this.debug('userinfo received', info);
                /** @type {?} */
                const existingClaims = this.getIdentityClaims() || {};
                if (!this.skipSubjectCheck) {
                    if (this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        /** @type {?} */
                        const err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                this.logger.error('error loading user info', err);
                this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param {?} userName
     * @param {?} password
     * @param {?=} headers Optional additional http-headers.
     * @return {?}
     */
    fetchTokenUsingPasswordFlow(userName, password, headers = new HttpHeaders()) {
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * \@stable
             * @type {?}
             */
            let params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', this.scope)
                .set('username', userName)
                .set('password', password);
            if (this.useHttpBasicAuth) {
                /** @type {?} */
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            tokenResponse => {
                this.debug('tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                this.storeAdditionalParameters(tokenResponse);
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                this.logger.error('Error performing password flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     * @return {?}
     */
    refreshToken() {
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            /** @type {?} */
            let params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('client_id', this.clientId)
                .set('scope', this.scope)
                .set('refresh_token', this._storage.getItem('refresh_token'));
            if (this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            /** @type {?} */
            const headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .pipe(switchMap((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            tokenResponse => {
                if (tokenResponse.id_token) {
                    return from(this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true))
                        .pipe(tap((/**
                     * @param {?} result
                     * @return {?}
                     */
                    result => this.storeIdToken(result))), map((/**
                     * @param {?} _
                     * @return {?}
                     */
                    _ => tokenResponse)));
                }
                else {
                    return of(tokenResponse);
                }
            })))
                .subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                this.storeAdditionalParameters(tokenResponse);
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }), (/**
             * @param {?} err
             * @return {?}
             */
            err => {
                this.logger.error('Error performing password flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    removeSilentRefreshEventListener() {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    }
    /**
     * @protected
     * @return {?}
     */
    setupSilentRefreshEventListener() {
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = (/**
         * @param {?} e
         * @return {?}
         */
        (e) => {
            /** @type {?} */
            const message = this.processMessageEventMessage(e);
            this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                onLoginError: (/**
                 * @param {?} err
                 * @return {?}
                 */
                err => {
                    this.eventsSubject.next(new OAuthErrorEvent('silent_refresh_error', err));
                }),
                onTokenReceived: (/**
                 * @return {?}
                 */
                () => {
                    this.eventsSubject.next(new OAuthSuccessEvent('silently_refreshed'));
                })
            }).catch((/**
             * @param {?} err
             * @return {?}
             */
            err => this.debug('tryLogin during silent refresh failed', err)));
        });
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    }
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     * @param {?=} params
     * @param {?=} noPrompt
     * @return {?}
     */
    silentRefresh(params = {}, noPrompt = true) {
        /** @type {?} */
        const claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('tokenEndpoint must use https, or config value for property requireHttps must allow http');
        }
        if (typeof document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        /** @type {?} */
        const existingIframe = document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        /** @type {?} */
        const iframe = document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        /** @type {?} */
        const redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then((/**
         * @param {?} url
         * @return {?}
         */
        url => {
            iframe.setAttribute('src', url);
            if (!this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            document.body.appendChild(iframe);
        }));
        /** @type {?} */
        const errors = this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e instanceof OAuthErrorEvent)), first());
        /** @type {?} */
        const success = this.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e.type === 'silently_refreshed')), first());
        /** @type {?} */
        const timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(tap((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            if (e.type === 'silent_refresh_timeout') {
                this.eventsSubject.next(e);
            }
        })), map((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            if (e instanceof OAuthErrorEvent) {
                throw e;
            }
            return e;
        })))
            .toPromise();
    }
    /**
     * @param {?=} options
     * @return {?}
     */
    initImplicitFlowInPopup(options) {
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then((/**
         * @param {?} url
         * @return {?}
         */
        url => {
            return new Promise((/**
             * @param {?} resolve
             * @param {?} reject
             * @return {?}
             */
            (resolve, reject) => {
                /** @type {?} */
                let windowRef = window.open(url, '_blank', this.calculatePopupFeatures(options));
                /** @type {?} */
                const cleanup = (/**
                 * @return {?}
                 */
                () => {
                    window.removeEventListener('message', listener);
                    windowRef.close();
                    windowRef = null;
                });
                /** @type {?} */
                const listener = (/**
                 * @param {?} e
                 * @return {?}
                 */
                (e) => {
                    /** @type {?} */
                    const message = this.processMessageEventMessage(e);
                    this.tryLogin({
                        customHashFragment: message,
                        preventClearHashAfterLogin: true,
                    }).then((/**
                     * @return {?}
                     */
                    () => {
                        cleanup();
                        resolve();
                    }), (/**
                     * @param {?} err
                     * @return {?}
                     */
                    err => {
                        cleanup();
                        reject(err);
                    }));
                });
                window.addEventListener('message', listener);
            }));
        }));
    }
    /**
     * @protected
     * @param {?} options
     * @return {?}
     */
    calculatePopupFeatures(options) {
        // Specify an static height and width and calculate centered position
        /** @type {?} */
        const height = options.height || 470;
        /** @type {?} */
        const width = options.width || 500;
        /** @type {?} */
        const left = (screen.width / 2) - (width / 2);
        /** @type {?} */
        const top = (screen.height / 2) - (height / 2);
        return `location=no,toolbar=no,width=${width},height=${height},top=${top},left=${left}`;
    }
    /**
     * @protected
     * @param {?} e
     * @return {?}
     */
    processMessageEventMessage(e) {
        /** @type {?} */
        let expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        /** @type {?} */
        const prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    }
    /**
     * @protected
     * @return {?}
     */
    canPerformSessionCheck() {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        /** @type {?} */
        const sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof document === 'undefined') {
            return false;
        }
        return true;
    }
    /**
     * @protected
     * @return {?}
     */
    setupSessionCheckEventListener() {
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = (/**
         * @param {?} e
         * @return {?}
         */
        (e) => {
            /** @type {?} */
            const origin = e.origin.toLowerCase();
            /** @type {?} */
            const issuer = this.issuer.toLowerCase();
            this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer);
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    this.handleSessionUnchanged();
                    break;
                case 'changed':
                    this.ngZone.run((/**
                     * @return {?}
                     */
                    () => {
                        this.handleSessionChange();
                    }));
                    break;
                case 'error':
                    this.ngZone.run((/**
                     * @return {?}
                     */
                    () => {
                        this.handleSessionError();
                    }));
                    break;
            }
            this.debug('got info from session check inframe', e);
        });
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            window.addEventListener('message', this.sessionCheckEventListener);
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    handleSessionUnchanged() {
        this.debug('session check', 'session unchanged');
    }
    /**
     * @protected
     * @return {?}
     */
    handleSessionChange() {
        /* events: session_changed, relogin, stopTimer, logged_out*/
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch((/**
             * @param {?} _
             * @return {?}
             */
            _ => this.debug('silent refresh failed after session changed')));
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    }
    /**
     * @protected
     * @return {?}
     */
    waitForSilentRefreshAfterSessionChange() {
        this.events
            .pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        (e) => e.type === 'silently_refreshed' ||
            e.type === 'silent_refresh_timeout' ||
            e.type === 'silent_refresh_error')), first())
            .subscribe((/**
         * @param {?} e
         * @return {?}
         */
        e => {
            if (e.type !== 'silently_refreshed') {
                this.debug('silent refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            }
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    handleSessionError() {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    }
    /**
     * @protected
     * @return {?}
     */
    removeSessionCheckEventListener() {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    }
    /**
     * @protected
     * @return {?}
     */
    initSessionCheck() {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        /** @type {?} */
        const existingIframe = document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            document.body.removeChild(existingIframe);
        }
        /** @type {?} */
        const iframe = document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        /** @type {?} */
        const url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    }
    /**
     * @protected
     * @return {?}
     */
    startSessionCheckTimer() {
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular((/**
         * @return {?}
         */
        () => {
            this.sessionCheckTimer = setInterval(this.checkSession.bind(this), this.sessionCheckIntervall);
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    stopSessionCheckTimer() {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    }
    /**
     * @protected
     * @return {?}
     */
    checkSession() {
        /** @type {?} */
        const iframe = document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        /** @type {?} */
        const sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        /** @type {?} */
        const message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    }
    /**
     * @protected
     * @param {?=} state
     * @param {?=} loginHint
     * @param {?=} customRedirectUri
     * @param {?=} noPrompt
     * @param {?=} params
     * @return {?}
     */
    createLoginUrl(state = '', loginHint = '', customRedirectUri = '', noPrompt = false, params = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            /** @type {?} */
            const that = this;
            /** @type {?} */
            let redirectUri;
            if (customRedirectUri) {
                redirectUri = customRedirectUri;
            }
            else {
                redirectUri = this.redirectUri;
            }
            /** @type {?} */
            const nonce = yield this.createAndSaveNonce();
            if (state) {
                state = nonce + this.config.nonceStateSeparator + state;
            }
            else {
                state = nonce;
            }
            if (!this.requestAccessToken && !this.oidc) {
                throw new Error('Either requestAccessToken or oidc or both must be true');
            }
            if (this.config.responseType) {
                this.responseType = this.config.responseType;
            }
            else {
                if (this.oidc && this.requestAccessToken) {
                    this.responseType = 'id_token token';
                }
                else if (this.oidc && !this.requestAccessToken) {
                    this.responseType = 'id_token';
                }
                else {
                    this.responseType = 'token';
                }
            }
            /** @type {?} */
            const seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
            /** @type {?} */
            let scope = that.scope;
            if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                scope = 'openid ' + scope;
            }
            /** @type {?} */
            let url = that.loginUrl +
                seperationChar +
                'response_type=' +
                encodeURIComponent(that.responseType) +
                '&client_id=' +
                encodeURIComponent(that.clientId) +
                '&state=' +
                encodeURIComponent(state) +
                '&redirect_uri=' +
                encodeURIComponent(redirectUri) +
                '&scope=' +
                encodeURIComponent(scope);
            if (this.responseType === 'code' && !this.disablePKCE) {
                const [challenge, verifier] = yield this.createChallangeVerifierPairForPKCE();
                this._storage.setItem('PKCI_verifier', verifier);
                url += '&code_challenge=' + challenge;
                url += '&code_challenge_method=S256';
            }
            if (loginHint) {
                url += '&login_hint=' + encodeURIComponent(loginHint);
            }
            if (that.resource) {
                url += '&resource=' + encodeURIComponent(that.resource);
            }
            if (that.oidc) {
                url += '&nonce=' + encodeURIComponent(nonce);
            }
            if (noPrompt) {
                url += '&prompt=none';
            }
            for (const key of Object.keys(params)) {
                url +=
                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    url +=
                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                }
            }
            return url;
        });
    }
    /**
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    initImplicitFlowInternal(additionalState = '', params = '') {
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl must use https, or config value for property requireHttps must allow http');
        }
        /** @type {?} */
        let addParams = {};
        /** @type {?} */
        let loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error('Error in initImplicitFlow', error);
            this.inImplicitFlow = false;
        }));
    }
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param {?=} additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param {?=} params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     * @return {?}
     */
    initImplicitFlow(additionalState = '', params = '') {
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter((/**
             * @param {?} e
             * @return {?}
             */
            e => e.type === 'discovery_document_loaded')))
                .subscribe((/**
             * @param {?} _
             * @return {?}
             */
            _ => this.initImplicitFlowInternal(additionalState, params)));
        }
    }
    /**
     * Reset current implicit flow
     *
     * \@description This method allows resetting the current implict flow in order to be initialized again.
     * @return {?}
     */
    resetImplicitFlow() {
        this.inImplicitFlow = false;
    }
    /**
     * @protected
     * @param {?} options
     * @return {?}
     */
    callOnTokenReceivedIfExists(options) {
        /** @type {?} */
        const that = this;
        if (options.onTokenReceived) {
            /** @type {?} */
            const tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    }
    /**
     * @protected
     * @param {?} accessToken
     * @param {?} refreshToken
     * @param {?} expiresIn
     * @param {?} grantedScopes
     * @return {?}
     */
    storeAccessTokenResponse(accessToken, refreshToken, expiresIn, grantedScopes) {
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            /** @type {?} */
            const expiresInMilliSeconds = expiresIn * 1000;
            /** @type {?} */
            const now = new Date();
            /** @type {?} */
            const expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
    }
    /**
     * Store additional parameters received in the tokenResponse
     * @protected
     * @param {?} tokenResponse the parameters from the token post request
     * @return {?}
     */
    storeAdditionalParameters(tokenResponse) {
        /** @type {?} */
        const additionalParams = JSON.parse(this._storage.getItem('additional_params')) || {};
        /** @type {?} */
        const tokenKeys = ['access_token', 'refresh_token', 'expires_in', 'scope'];
        Object.keys(tokenResponse).forEach((/**
         * @param {?} key
         * @return {?}
         */
        (key) => {
            if (!tokenKeys.includes(key)) { // don't store parameters related to token, stored elsewhere
                additionalParams[key] = tokenResponse[key];
            }
        }));
        this._storage.setItem('additional_params', JSON.stringify(additionalParams));
    }
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param {?=} options Optional options.
     * @return {?}
     */
    tryLogin(options = null) {
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow().then((/**
             * @param {?} _
             * @return {?}
             */
            _ => true));
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    }
    /**
     * @private
     * @param {?} queryString
     * @return {?}
     */
    parseQueryString(queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    /**
     * @return {?}
     */
    tryLoginCodeFlow() {
        /** @type {?} */
        const parts = this.parseQueryString(window.location.search);
        /** @type {?} */
        const code = parts['code'];
        /** @type {?} */
        const state = parts['state'];
        /** @type {?} */
        const href = location.href
            .replace(/[&\?]code=[^&\$]*/, '')
            .replace(/[&\?]scope=[^&\$]*/, '')
            .replace(/[&\?]state=[^&\$]*/, '')
            .replace(/[&\?]session_state=[^&\$]*/, '');
        history.replaceState(null, window.name, href);
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            /** @type {?} */
            const err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        /** @type {?} */
        const success = this.validateNonce(nonceInState);
        if (!success) {
            /** @type {?} */
            const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event);
            return Promise.reject(event);
        }
        if (code) {
            return new Promise((/**
             * @param {?} resolve
             * @param {?} reject
             * @return {?}
             */
            (resolve, reject) => {
                this.getTokenFromCode(code).then((/**
                 * @param {?} result
                 * @return {?}
                 */
                result => {
                    resolve();
                })).catch((/**
                 * @param {?} err
                 * @return {?}
                 */
                err => {
                    reject(err);
                }));
            }));
        }
        else {
            return Promise.resolve();
        }
    }
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     * @private
     * @param {?} code
     * @return {?}
     */
    getTokenFromCode(code) {
        /** @type {?} */
        let params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', this.redirectUri);
        if (!this.disablePKCE) {
            /** @type {?} */
            const pkciVerifier = this._storage.getItem('PKCI_verifier');
            if (!pkciVerifier) {
                console.warn('No PKCI verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', pkciVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    }
    /**
     * @private
     * @param {?} params
     * @return {?}
     */
    fetchAndProcessToken(params) {
        /** @type {?} */
        let headers = new HttpHeaders()
            .set('Content-Type', 'application/x-www-form-urlencoded');
        if (!this.validateUrlForHttps(this.tokenEndpoint)) {
            throw new Error('tokenEndpoint must use Http. Also check property requireHttps.');
        }
        if (this.useHttpBasicAuth) {
            /** @type {?} */
            const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise((/**
         * @param {?} resolve
         * @param {?} reject
         * @return {?}
         */
        (resolve, reject) => {
            if (this.customQueryParams) {
                for (let key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http.post(this.tokenEndpoint, params, { headers }).subscribe((/**
             * @param {?} tokenResponse
             * @return {?}
             */
            (tokenResponse) => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in, tokenResponse.scope);
                this.storeAdditionalParameters(tokenResponse);
                if (this.oidc && tokenResponse.id_token) {
                    this.processIdToken(tokenResponse.id_token, tokenResponse.access_token).
                        then((/**
                     * @param {?} result
                     * @return {?}
                     */
                    result => {
                        this.storeIdToken(result);
                        this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    }))
                        .catch((/**
                     * @param {?} reason
                     * @return {?}
                     */
                    reason => {
                        this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    }));
                }
                else {
                    this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }), (/**
             * @param {?} err
             * @return {?}
             */
            (err) => {
                console.error('Error getting token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            }));
        }));
    }
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param {?=} options Optional options.
     * @return {?}
     */
    tryLoginImplicitFlow(options = null) {
        options = options || {};
        /** @type {?} */
        let parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        /** @type {?} */
        const state = parts['state'];
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            /** @type {?} */
            const err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        /** @type {?} */
        const accessToken = parts['access_token'];
        /** @type {?} */
        const idToken = parts['id_token'];
        /** @type {?} */
        const sessionState = parts['session_state'];
        /** @type {?} */
        const grantedScopes = parts['scope'];
        if (!this.requestAccessToken && !this.oidc) {
            return Promise.reject('Either requestAccessToken or oidc (or both) must be true.');
        }
        if (this.requestAccessToken && !accessToken) {
            return Promise.resolve(false);
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck && !state) {
            return Promise.resolve(false);
        }
        if (this.oidc && !idToken) {
            return Promise.resolve(false);
        }
        if (this.sessionChecksEnabled && !sessionState) {
            this.logger.warn('session checks (Session Status Change Notification) ' +
                'were activated in the configuration but the id_token ' +
                'does not contain a session_state claim');
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck) {
            /** @type {?} */
            const success = this.validateNonce(nonceInState);
            if (!success) {
                /** @type {?} */
                const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event);
                return Promise.reject(event);
            }
        }
        if (this.requestAccessToken) {
            this.storeAccessTokenResponse(accessToken, null, parts['expires_in'] || this.fallbackAccessTokenExpirationTimeInSec, grantedScopes);
        }
        if (!this.oidc) {
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.callOnTokenReceivedIfExists(options);
            return Promise.resolve(true);
        }
        return this.processIdToken(idToken, accessToken)
            .then((/**
         * @param {?} result
         * @return {?}
         */
        result => {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then((/**
                 * @param {?} _
                 * @return {?}
                 */
                _ => result));
            }
            return result;
        }))
            .then((/**
         * @param {?} result
         * @return {?}
         */
        result => {
            this.storeIdToken(result);
            this.storeSessionState(sessionState);
            if (this.clearHashAfterLogin) {
                location.hash = '';
            }
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            this.callOnTokenReceivedIfExists(options);
            this.inImplicitFlow = false;
            return true;
        }))
            .catch((/**
         * @param {?} reason
         * @return {?}
         */
        reason => {
            this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            this.logger.error('Error validating tokens');
            this.logger.error(reason);
            return Promise.reject(reason);
        }));
    }
    /**
     * @private
     * @param {?} state
     * @return {?}
     */
    parseState(state) {
        /** @type {?} */
        let nonce = state;
        /** @type {?} */
        let userState = '';
        if (state) {
            /** @type {?} */
            const idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    }
    /**
     * @protected
     * @param {?} nonceInState
     * @return {?}
     */
    validateNonce(nonceInState) {
        /** @type {?} */
        const savedNonce = this._storage.getItem('nonce');
        if (savedNonce !== nonceInState) {
            /** @type {?} */
            const err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    }
    /**
     * @protected
     * @param {?} idToken
     * @return {?}
     */
    storeIdToken(idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    }
    /**
     * @protected
     * @param {?} sessionState
     * @return {?}
     */
    storeSessionState(sessionState) {
        this._storage.setItem('session_state', sessionState);
    }
    /**
     * @protected
     * @return {?}
     */
    getSessionState() {
        return this._storage.getItem('session_state');
    }
    /**
     * @protected
     * @param {?} options
     * @param {?} parts
     * @return {?}
     */
    handleLoginError(options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin) {
            location.hash = '';
        }
    }
    /**
     * @ignore
     * @param {?} idToken
     * @param {?} accessToken
     * @param {?=} skipNonceCheck
     * @return {?}
     */
    processIdToken(idToken, accessToken, skipNonceCheck = false) {
        /** @type {?} */
        const tokenParts = idToken.split('.');
        /** @type {?} */
        const headerBase64 = this.padBase64(tokenParts[0]);
        /** @type {?} */
        const headerJson = b64DecodeUnicode(headerBase64);
        /** @type {?} */
        const header = JSON.parse(headerJson);
        /** @type {?} */
        const claimsBase64 = this.padBase64(tokenParts[1]);
        /** @type {?} */
        const claimsJson = b64DecodeUnicode(claimsBase64);
        /** @type {?} */
        const claims = JSON.parse(claimsJson);
        /** @type {?} */
        const savedNonce = this._storage.getItem('nonce');
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every((/**
             * @param {?} v
             * @return {?}
             */
            v => v !== this.clientId))) {
                /** @type {?} */
                const err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                /** @type {?} */
                const err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            /** @type {?} */
            const err = 'No sub claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /* For now, we only check whether the sub against
         * silentRefreshSubject when sessionChecksEnabled is on
         * We will reconsider in a later version to do this
         * in every other case too.
         */
        if (this.sessionChecksEnabled &&
            this.silentRefreshSubject &&
            this.silentRefreshSubject !== claims['sub']) {
            /** @type {?} */
            const err = 'After refreshing, we got an id_token for another user (sub). ' +
                `Expected sub: ${this.silentRefreshSubject}, received sub: ${claims['sub']}`;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            /** @type {?} */
            const err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            /** @type {?} */
            const err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            /** @type {?} */
            const err = 'Wrong nonce: ' + claims.nonce;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.disableAtHashCheck &&
            this.requestAccessToken &&
            !claims['at_hash']) {
            /** @type {?} */
            const err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /** @type {?} */
        const now = Date.now();
        /** @type {?} */
        const issuedAtMSec = claims.iat * 1000;
        /** @type {?} */
        const expiresAtMSec = claims.exp * 1000;
        /** @type {?} */
        const clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            /** @type {?} */
            const err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        /** @type {?} */
        const validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: (/**
             * @return {?}
             */
            () => this.loadJwks())
        };
        return this.checkAtHash(validationParams)
            .then((/**
         * @param {?} atHashValid
         * @return {?}
         */
        atHashValid => {
            if (!this.disableAtHashCheck &&
                this.requestAccessToken &&
                !atHashValid) {
                /** @type {?} */
                const err = 'Wrong at_hash';
                this.logger.warn(err);
                return Promise.reject(err);
            }
            return this.checkSignature(validationParams).then((/**
             * @param {?} _
             * @return {?}
             */
            _ => {
                /** @type {?} */
                const result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                return result;
            }));
        }));
    }
    /**
     * Returns the received claims about the user.
     * @return {?}
     */
    getIdentityClaims() {
        /** @type {?} */
        const claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    }
    /**
     * Returns the granted scopes from the server.
     * @return {?}
     */
    getGrantedScopes() {
        /** @type {?} */
        const scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    }
    /**
     * Returns the current id_token.
     * @return {?}
     */
    getIdToken() {
        return this._storage
            ? this._storage.getItem('id_token')
            : null;
    }
    /**
     * @protected
     * @param {?} base64data
     * @return {?}
     */
    padBase64(base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    }
    /**
     * Returns the current access_token.
     * @return {?}
     */
    getAccessToken() {
        return this._storage
            ? this._storage.getItem('access_token')
            : null;
    }
    /**
     * @return {?}
     */
    getRefreshToken() {
        return this._storage
            ? this._storage.getItem('refresh_token')
            : null;
    }
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     * @return {?}
     */
    getAccessTokenExpiration() {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    }
    /**
     * @protected
     * @return {?}
     */
    getAccessTokenStoredAt() {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    }
    /**
     * @protected
     * @return {?}
     */
    getIdTokenStoredAt() {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    }
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     * @return {?}
     */
    getIdTokenExpiration() {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    }
    /**
     * Get additional parameters that have been saved after a log in
     * @return {?} key:value pairs of additional parameters from oAuth login
     */
    getAdditionalParameters() {
        if (!this._storage.getItem('additional_params')) {
            return null;
        }
        return JSON.parse(this._storage.getItem('additional_params'));
    }
    /**
     * Checkes, whether there is a valid access_token.
     * @return {?}
     */
    hasValidAccessToken() {
        if (this.getAccessToken()) {
            /** @type {?} */
            const expiresAt = this._storage.getItem('expires_at');
            /** @type {?} */
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Checks whether there is a valid id_token.
     * @return {?}
     */
    hasValidIdToken() {
        if (this.getIdToken()) {
            /** @type {?} */
            const expiresAt = this._storage.getItem('id_token_expires_at');
            /** @type {?} */
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     * @return {?}
     */
    authorizationHeader() {
        return 'Bearer ' + this.getAccessToken();
    }
    /**
     * Removes all tokens and logs the user out.
     * If a logout url is configured, the user is
     * redirected to it.
     * @param {?=} noRedirectToLogoutUrl
     * @return {?}
     */
    logOut(noRedirectToLogoutUrl = false) {
        /** @type {?} */
        const id_token = this.getIdToken();
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        this._storage.removeItem('nonce');
        this._storage.removeItem('expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');
        this._storage.removeItem('id_token_stored_at');
        this._storage.removeItem('access_token_stored_at');
        this._storage.removeItem('granted_scopes');
        this._storage.removeItem('session_state');
        this.silentRefreshSubject = null;
        this.eventsSubject.next(new OAuthInfoEvent('logout'));
        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }
        if (!id_token && !this.postLogoutRedirectUri) {
            return;
        }
        /** @type {?} */
        let logoutUrl;
        if (!this.validateUrlForHttps(this.logoutUrl)) {
            throw new Error('logoutUrl must use https, or config value for property requireHttps must allow http');
        }
        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl
                .replace(/\{\{id_token\}\}/, id_token)
                .replace(/\{\{client_id\}\}/, this.clientId);
        }
        else {
            /** @type {?} */
            let params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            /** @type {?} */
            const postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    }
    /**
     * @ignore
     * @return {?}
     */
    createAndSaveNonce() {
        /** @type {?} */
        const that = this;
        return this.createNonce().then((/**
         * @param {?} nonce
         * @return {?}
         */
        function (nonce) {
            that._storage.setItem('nonce', nonce);
            return nonce;
        }));
    }
    /**
     * @ignore
     * @return {?}
     */
    ngOnDestroy() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
    }
    /**
     * @protected
     * @return {?}
     */
    createNonce() {
        return new Promise((/**
         * @param {?} resolve
         * @return {?}
         */
        (resolve) => {
            if (this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
                         * This alphabet uses a-z A-Z 0-9 _- symbols.
                         * Symbols order was changed for better gzip compression.
                         */
            /** @type {?} */
            const url = 'Uint8ArdomValuesObj012345679BCDEFGHIJKLMNPQRSTWXYZ_cfghkpqvwxyz-';
            /** @type {?} */
            let size = 45;
            /** @type {?} */
            let id = '';
            /** @type {?} */
            const crypto = self.crypto || self['msCrypto'];
            if (crypto) {
                /** @type {?} */
                const bytes = crypto.getRandomValues(new Uint8Array(size));
                while (0 < size--) {
                    id += url[bytes[size] & 63];
                }
            }
            else {
                while (0 < size--) {
                    id += url[Math.random() * 64 | 0];
                }
            }
            resolve(id);
        }));
    }
    /**
     * @protected
     * @param {?} params
     * @return {?}
     */
    checkAtHash(params) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.tokenValidationHandler) {
                this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                return true;
            }
            return this.tokenValidationHandler.validateAtHash(params);
        });
    }
    /**
     * @protected
     * @param {?} params
     * @return {?}
     */
    checkSignature(params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    }
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    initLoginFlow(additionalState = '', params = {}) {
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    }
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    initCodeFlow(additionalState = '', params = {}) {
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events.pipe(filter((/**
             * @param {?} e
             * @return {?}
             */
            e => e.type === 'discovery_document_loaded')))
                .subscribe((/**
             * @param {?} _
             * @return {?}
             */
            _ => this.initCodeFlowInternal(additionalState, params)));
        }
    }
    /**
     * @private
     * @param {?=} additionalState
     * @param {?=} params
     * @return {?}
     */
    initCodeFlowInternal(additionalState = '', params = {}) {
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error('loginUrl must use Http. Also check property requireHttps.');
        }
        this.createLoginUrl(additionalState, '', null, false, params).then((/**
         * @param {?} url
         * @return {?}
         */
        function (url) {
            location.href = url;
        }))
            .catch((/**
         * @param {?} error
         * @return {?}
         */
        error => {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        }));
    }
    /**
     * @protected
     * @return {?}
     */
    createChallangeVerifierPairForPKCE() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.crypto) {
                throw new Error('PKCI support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
            }
            /** @type {?} */
            const verifier = yield this.createNonce();
            /** @type {?} */
            const challengeRaw = yield this.crypto.calcHash(verifier, 'sha-256');
            /** @type {?} */
            const challange = base64UrlEncode(challengeRaw);
            return [challange, verifier];
        });
    }
}
OAuthService.decorators = [
    { type: Injectable }
];
/** @nocollapse */
OAuthService.ctorParameters = () => [
    { type: NgZone },
    { type: HttpClient },
    { type: OAuthStorage, decorators: [{ type: Optional }] },
    { type: ValidationHandler, decorators: [{ type: Optional }] },
    { type: AuthConfig, decorators: [{ type: Optional }] },
    { type: UrlHelperService },
    { type: OAuthLogger },
    { type: CryptoHandler, decorators: [{ type: Optional }] }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * @abstract
 */
class OAuthModuleConfig {
}
/**
 * @abstract
 */
class OAuthResourceServerConfig {
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * @abstract
 */
class OAuthResourceServerErrorHandler {
}
class OAuthNoopResourceServerErrorHandler {
    /**
     * @param {?} err
     * @return {?}
     */
    handleError(err) {
        return throwError(err);
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/** @type {?} */
const WAIT_FOR_TOKEN_RECEIVED = 1000;
class DefaultOAuthInterceptor {
    /**
     * @param {?} authStorage
     * @param {?} oAuthService
     * @param {?} errorHandler
     * @param {?} moduleConfig
     */
    constructor(authStorage, oAuthService, errorHandler, moduleConfig) {
        this.authStorage = authStorage;
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    /**
     * @private
     * @param {?} url
     * @return {?}
     */
    checkUrl(url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find((/**
             * @param {?} u
             * @return {?}
             */
            u => url.startsWith(u)));
        }
        return true;
    }
    /**
     * @param {?} req
     * @param {?} next
     * @return {?}
     */
    intercept(req, next) {
        /** @type {?} */
        const url = req.url.toLowerCase();
        if (!this.moduleConfig) {
            return next.handle(req);
        }
        if (!this.moduleConfig.resourceServer) {
            return next.handle(req);
        }
        if (this.moduleConfig.resourceServer.allowedUrls && !this.checkUrl(url)) {
            return next.handle(req);
        }
        /** @type {?} */
        const sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError((/**
             * @param {?} err
             * @return {?}
             */
            err => this.errorHandler.handleError(err))));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter((/**
         * @param {?} token
         * @return {?}
         */
        token => token ? true : false))), this.oAuthService.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        e => e.type === 'token_received')), timeout(WAIT_FOR_TOKEN_RECEIVED), map((/**
         * @param {?} _
         * @return {?}
         */
        _ => this.oAuthService.getAccessToken())))).pipe(take(1), mergeMap((/**
         * @param {?} token
         * @return {?}
         */
        token => {
            if (token) {
                /** @type {?} */
                const header = 'Bearer ' + token;
                /** @type {?} */
                const headers = req.headers.set('Authorization', header);
                req = req.clone({ headers });
            }
            return next
                .handle(req)
                .pipe(catchError((/**
             * @param {?} err
             * @return {?}
             */
            err => this.errorHandler.handleError(err))));
        })));
    }
}
DefaultOAuthInterceptor.decorators = [
    { type: Injectable }
];
/** @nocollapse */
DefaultOAuthInterceptor.ctorParameters = () => [
    { type: OAuthStorage },
    { type: OAuthService },
    { type: OAuthResourceServerErrorHandler },
    { type: OAuthModuleConfig, decorators: [{ type: Optional }] }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * A validation handler that isn't validating nothing.
 * Can be used to skip validation (at your own risk).
 */
class NullValidationHandler {
    /**
     * @param {?} validationParams
     * @return {?}
     */
    validateSignature(validationParams) {
        return Promise.resolve(null);
    }
    /**
     * @param {?} validationParams
     * @return {?}
     */
    validateAtHash(validationParams) {
        return Promise.resolve(true);
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * @return {?}
 */
function createDefaultLogger() {
    return console;
}
/**
 * @return {?}
 */
function createDefaultStorage() {
    return typeof sessionStorage !== 'undefined' ? sessionStorage : null;
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
class JwksValidationHandler extends AbstractValidationHandler {
    constructor() {
        super(...arguments);
        /**
         * Allowed algorithms
         */
        this.allowedAlgorithms = [
            'HS256',
            'HS384',
            'HS512',
            'RS256',
            'RS384',
            'RS512',
            'ES256',
            'ES384',
            'PS256',
            'PS384',
            'PS512'
        ];
        /**
         * Time period in seconds the timestamp in the signature can
         * differ from the current time.
         */
        this.gracePeriodInSec = 600;
    }
    /**
     * @param {?} params
     * @param {?=} retry
     * @return {?}
     */
    validateSignature(params, retry = false) {
        if (!params.idToken)
            throw new Error('Parameter idToken expected!');
        if (!params.idTokenHeader)
            throw new Error('Parameter idTokenHandler expected.');
        if (!params.jwks)
            throw new Error('Parameter jwks expected!');
        if (!params.jwks['keys'] ||
            !Array.isArray(params.jwks['keys']) ||
            params.jwks['keys'].length === 0) {
            throw new Error('Array keys in jwks missing!');
        }
        // console.debug('validateSignature: retry', retry);
        /** @type {?} */
        let kid = params.idTokenHeader['kid'];
        /** @type {?} */
        let keys = params.jwks['keys'];
        /** @type {?} */
        let key;
        /** @type {?} */
        let alg = params.idTokenHeader['alg'];
        if (kid) {
            key = keys.find((/**
             * @param {?} k
             * @return {?}
             */
            k => k['kid'] === kid /* && k['use'] === 'sig' */));
        }
        else {
            /** @type {?} */
            let kty = this.alg2kty(alg);
            /** @type {?} */
            let matchingKeys = keys.filter((/**
             * @param {?} k
             * @return {?}
             */
            k => k['kty'] === kty && k['use'] === 'sig'));
            /*
                  if (matchingKeys.length == 0) {
                      let error = 'No matching key found.';
                      console.error(error);
                      return Promise.reject(error);
                  }*/
            if (matchingKeys.length > 1) {
                /** @type {?} */
                let error = 'More than one matching key found. Please specify a kid in the id_token header.';
                console.error(error);
                return Promise.reject(error);
            }
            else if (matchingKeys.length === 1) {
                key = matchingKeys[0];
            }
        }
        if (!key && !retry && params.loadKeys) {
            return params
                .loadKeys()
                .then((/**
             * @param {?} loadedKeys
             * @return {?}
             */
            loadedKeys => (params.jwks = loadedKeys)))
                .then((/**
             * @param {?} _
             * @return {?}
             */
            _ => this.validateSignature(params, true)));
        }
        if (!key && retry && !kid) {
            /** @type {?} */
            let error = 'No matching key found.';
            console.error(error);
            return Promise.reject(error);
        }
        if (!key && retry && kid) {
            /** @type {?} */
            let error = 'expected key not found in property jwks. ' +
                'This property is most likely loaded with the ' +
                'discovery document. ' +
                'Expected key id (kid): ' +
                kid;
            console.error(error);
            return Promise.reject(error);
        }
        /** @type {?} */
        let keyObj = KEYUTIL.getKey(key);
        /** @type {?} */
        let validationOptions = {
            alg: this.allowedAlgorithms,
            gracePeriod: this.gracePeriodInSec
        };
        /** @type {?} */
        let isValid = KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, validationOptions);
        if (isValid) {
            return Promise.resolve();
        }
        else {
            return Promise.reject('Signature not valid');
        }
    }
    /**
     * @private
     * @param {?} alg
     * @return {?}
     */
    alg2kty(alg) {
        switch (alg.charAt(0)) {
            case 'R':
                return 'RSA';
            case 'E':
                return 'EC';
            default:
                throw new Error('Cannot infer kty from alg: ' + alg);
        }
    }
    /**
     * @param {?} valueToHash
     * @param {?} algorithm
     * @return {?}
     */
    calcHash(valueToHash, algorithm) {
        /** @type {?} */
        let hashAlg = new KJUR.crypto.MessageDigest({ alg: algorithm });
        /** @type {?} */
        let result = hashAlg.digestString(valueToHash);
        /** @type {?} */
        let byteArrayAsString = this.toByteArrayAsString(result);
        return Promise.resolve(byteArrayAsString);
    }
    /**
     * @param {?} hexString
     * @return {?}
     */
    toByteArrayAsString(hexString) {
        /** @type {?} */
        let result = '';
        for (let i = 0; i < hexString.length; i += 2) {
            /** @type {?} */
            let hexDigit = hexString.charAt(i) + hexString.charAt(i + 1);
            /** @type {?} */
            let num = parseInt(hexDigit, 16);
            result += String.fromCharCode(num);
        }
        return result;
    }
}

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
class OAuthModule {
    /**
     * @param {?=} config
     * @param {?=} validationHandlerClass
     * @return {?}
     */
    static forRoot(config = null, validationHandlerClass = NullValidationHandler) {
        return {
            ngModule: OAuthModule,
            providers: [
                OAuthService,
                UrlHelperService,
                { provide: OAuthLogger, useFactory: createDefaultLogger },
                { provide: OAuthStorage, useFactory: createDefaultStorage },
                { provide: ValidationHandler, useClass: validationHandlerClass },
                { provide: CryptoHandler, useClass: JwksValidationHandler },
                {
                    provide: OAuthResourceServerErrorHandler,
                    useClass: OAuthNoopResourceServerErrorHandler
                },
                { provide: OAuthModuleConfig, useValue: config },
                {
                    provide: HTTP_INTERCEPTORS,
                    useClass: DefaultOAuthInterceptor,
                    multi: true
                }
            ]
        };
    }
}
OAuthModule.decorators = [
    { type: NgModule, args: [{
                imports: [CommonModule],
                declarations: [],
                exports: []
            },] }
];

/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/** @type {?} */
const AUTH_CONFIG = new InjectionToken('AUTH_CONFIG');

export { AUTH_CONFIG, AbstractValidationHandler, AuthConfig, DefaultOAuthInterceptor, JwksValidationHandler, LoginOptions, NullValidationHandler, OAuthErrorEvent, OAuthEvent, OAuthInfoEvent, OAuthLogger, OAuthModule, OAuthModuleConfig, OAuthNoopResourceServerErrorHandler, OAuthResourceServerConfig, OAuthResourceServerErrorHandler, OAuthService, OAuthStorage, OAuthSuccessEvent, ReceivedTokens, UrlHelperService, ValidationHandler, CryptoHandler as ɵa, createDefaultLogger as ɵb, createDefaultStorage as ɵc };
//# sourceMappingURL=angular-oauth2-oidc.js.map
