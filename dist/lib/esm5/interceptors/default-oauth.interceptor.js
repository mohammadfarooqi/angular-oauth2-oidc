/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout } from 'rxjs/operators';
import { OAuthResourceServerErrorHandler } from './resource-server-error-handler';
import { OAuthModuleConfig } from '../oauth-module.config';
import { OAuthStorage } from '../types';
import { OAuthService } from '../oauth-service';
/** @type {?} */
var WAIT_FOR_TOKEN_RECEIVED = 1000;
var DefaultOAuthInterceptor = /** @class */ (function () {
    function DefaultOAuthInterceptor(authStorage, oAuthService, errorHandler, moduleConfig) {
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
    DefaultOAuthInterceptor.prototype.checkUrl = /**
     * @private
     * @param {?} url
     * @return {?}
     */
    function (url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find((/**
             * @param {?} u
             * @return {?}
             */
            function (u) { return url.startsWith(u); }));
        }
        return true;
    };
    /**
     * @param {?} req
     * @param {?} next
     * @return {?}
     */
    DefaultOAuthInterceptor.prototype.intercept = /**
     * @param {?} req
     * @param {?} next
     * @return {?}
     */
    function (req, next) {
        var _this = this;
        /** @type {?} */
        var url = req.url.toLowerCase();
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
        var sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError((/**
             * @param {?} err
             * @return {?}
             */
            function (err) { return _this.errorHandler.handleError(err); })));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter((/**
         * @param {?} token
         * @return {?}
         */
        function (token) { return token ? true : false; }))), this.oAuthService.events.pipe(filter((/**
         * @param {?} e
         * @return {?}
         */
        function (e) { return e.type === 'token_received'; })), timeout(WAIT_FOR_TOKEN_RECEIVED), map((/**
         * @param {?} _
         * @return {?}
         */
        function (_) { return _this.oAuthService.getAccessToken(); })))).pipe(take(1), mergeMap((/**
         * @param {?} token
         * @return {?}
         */
        function (token) {
            if (token) {
                /** @type {?} */
                var header = 'Bearer ' + token;
                /** @type {?} */
                var headers = req.headers.set('Authorization', header);
                req = req.clone({ headers: headers });
            }
            return next
                .handle(req)
                .pipe(catchError((/**
             * @param {?} err
             * @return {?}
             */
            function (err) { return _this.errorHandler.handleError(err); })));
        })));
    };
    DefaultOAuthInterceptor.decorators = [
        { type: Injectable }
    ];
    /** @nocollapse */
    DefaultOAuthInterceptor.ctorParameters = function () { return [
        { type: OAuthStorage },
        { type: OAuthService },
        { type: OAuthResourceServerErrorHandler },
        { type: OAuthModuleConfig, decorators: [{ type: Optional }] }
    ]; };
    return DefaultOAuthInterceptor;
}());
export { DefaultOAuthInterceptor };
if (false) {
    /**
     * @type {?}
     * @private
     */
    DefaultOAuthInterceptor.prototype.authStorage;
    /**
     * @type {?}
     * @private
     */
    DefaultOAuthInterceptor.prototype.oAuthService;
    /**
     * @type {?}
     * @private
     */
    DefaultOAuthInterceptor.prototype.errorHandler;
    /**
     * @type {?}
     * @private
     */
    DefaultOAuthInterceptor.prototype.moduleConfig;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJpbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsT0FBTyxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFDbEYsT0FBTyxFQUFFLCtCQUErQixFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFDbEYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFDM0QsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLFVBQVUsQ0FBQztBQUN4QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7O0lBRTFDLHVCQUF1QixHQUFHLElBQUk7QUFFcEM7SUFHSSxpQ0FDWSxXQUF5QixFQUN6QixZQUEwQixFQUMxQixZQUE2QyxFQUNqQyxZQUErQjtRQUgzQyxnQkFBVyxHQUFYLFdBQVcsQ0FBYztRQUN6QixpQkFBWSxHQUFaLFlBQVksQ0FBYztRQUMxQixpQkFBWSxHQUFaLFlBQVksQ0FBaUM7UUFDakMsaUJBQVksR0FBWixZQUFZLENBQW1CO0lBQ25ELENBQUM7Ozs7OztJQUVHLDBDQUFROzs7OztJQUFoQixVQUFpQixHQUFXO1FBQ3hCLElBQUksSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsbUJBQW1CLEVBQUU7WUFDdEQsT0FBTyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLENBQUMs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O2dCQXRFRixVQUFVOzs7O2dCQUxGLFlBQVk7Z0JBQ1osWUFBWTtnQkFIWiwrQkFBK0I7Z0JBQy9CLGlCQUFpQix1QkFhakIsUUFBUTs7SUFnRWpCLDhCQUFDO0NBQUEsQUF2RUQsSUF1RUM7U0F0RVksdUJBQXVCOzs7Ozs7SUFHNUIsOENBQWlDOzs7OztJQUNqQywrQ0FBa0M7Ozs7O0lBQ2xDLCtDQUFxRDs7Ozs7SUFDckQsK0NBQW1EIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgT3B0aW9uYWwgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcblxuaW1wb3J0IHtcbiAgSHR0cEV2ZW50LFxuICBIdHRwSGFuZGxlcixcbiAgSHR0cEludGVyY2VwdG9yLFxuICBIdHRwUmVxdWVzdCxcbn0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgb2YsIG1lcmdlIH0gZnJvbSAncnhqcyc7XG5pbXBvcnQgeyBjYXRjaEVycm9yLCBmaWx0ZXIsIG1hcCwgdGFrZSwgbWVyZ2VNYXAsIHRpbWVvdXQgfSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyIH0gZnJvbSAnLi9yZXNvdXJjZS1zZXJ2ZXItZXJyb3ItaGFuZGxlcic7XG5pbXBvcnQgeyBPQXV0aE1vZHVsZUNvbmZpZyB9IGZyb20gJy4uL29hdXRoLW1vZHVsZS5jb25maWcnO1xuaW1wb3J0IHsgT0F1dGhTdG9yYWdlIH0gZnJvbSAnLi4vdHlwZXMnO1xuaW1wb3J0IHsgT0F1dGhTZXJ2aWNlIH0gZnJvbSAnLi4vb2F1dGgtc2VydmljZSc7XG5cbmNvbnN0IFdBSVRfRk9SX1RPS0VOX1JFQ0VJVkVEID0gMTAwMDtcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIERlZmF1bHRPQXV0aEludGVyY2VwdG9yIGltcGxlbWVudHMgSHR0cEludGVyY2VwdG9yIHtcblxuICAgIGNvbnN0cnVjdG9yKFxuICAgICAgICBwcml2YXRlIGF1dGhTdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXG4gICAgICAgIHByaXZhdGUgb0F1dGhTZXJ2aWNlOiBPQXV0aFNlcnZpY2UsXG4gICAgICAgIHByaXZhdGUgZXJyb3JIYW5kbGVyOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICAgICAgICBAT3B0aW9uYWwoKSBwcml2YXRlIG1vZHVsZUNvbmZpZzogT0F1dGhNb2R1bGVDb25maWdcbiAgICApIHsgfVxuXG4gICAgcHJpdmF0ZSBjaGVja1VybCh1cmw6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgICAgICBpZiAodGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuY3VzdG9tVXJsVmFsaWRhdGlvbikge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmN1c3RvbVVybFZhbGlkYXRpb24odXJsKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICh0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5hbGxvd2VkVXJscykge1xuICAgICAgICAgICAgcmV0dXJuICEhdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuYWxsb3dlZFVybHMuZmluZCh1ID0+IHVybC5zdGFydHNXaXRoKHUpKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICBwdWJsaWMgaW50ZXJjZXB0KFxuICAgIHJlcTogSHR0cFJlcXVlc3Q8YW55PixcbiAgICBuZXh0OiBIdHRwSGFuZGxlclxuICApOiBPYnNlcnZhYmxlPEh0dHBFdmVudDxhbnk+PiB7XG4gICAgY29uc3QgdXJsID0gcmVxLnVybC50b0xvd2VyQ2FzZSgpO1xuXG5cbiAgICBpZiAoIXRoaXMubW9kdWxlQ29uZmlnKSB7XG4gICAgICByZXR1cm4gbmV4dC5oYW5kbGUocmVxKTtcbiAgICB9XG4gICAgaWYgKCF0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlcikge1xuICAgICAgcmV0dXJuIG5leHQuaGFuZGxlKHJlcSk7XG4gICAgfVxuICAgIGlmICh0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5hbGxvd2VkVXJscyAmJiAhdGhpcy5jaGVja1VybCh1cmwpKSB7XG4gICAgICByZXR1cm4gbmV4dC5oYW5kbGUocmVxKTtcbiAgICB9XG5cbiAgICBjb25zdCBzZW5kQWNjZXNzVG9rZW4gPSB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5zZW5kQWNjZXNzVG9rZW47XG5cbiAgICBpZiAoIXNlbmRBY2Nlc3NUb2tlbikge1xuICAgICAgcmV0dXJuIG5leHRcbiAgICAgICAgLmhhbmRsZShyZXEpXG4gICAgICAgIC5waXBlKGNhdGNoRXJyb3IoZXJyID0+IHRoaXMuZXJyb3JIYW5kbGVyLmhhbmRsZUVycm9yKGVycikpKTtcbiAgICB9XG5cbiAgICByZXR1cm4gbWVyZ2UoXG4gICAgICBvZih0aGlzLm9BdXRoU2VydmljZS5nZXRBY2Nlc3NUb2tlbigpKS5waXBlKFxuICAgICAgICBmaWx0ZXIodG9rZW4gPT4gdG9rZW4gPyB0cnVlIDogZmFsc2UpLFxuICAgICAgKSxcbiAgICAgIHRoaXMub0F1dGhTZXJ2aWNlLmV2ZW50cy5waXBlKFxuICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpLFxuICAgICAgICB0aW1lb3V0KFdBSVRfRk9SX1RPS0VOX1JFQ0VJVkVEKSxcbiAgICAgICAgbWFwKF8gPT4gdGhpcy5vQXV0aFNlcnZpY2UuZ2V0QWNjZXNzVG9rZW4oKSksXG4gICAgICApLFxuICAgICkucGlwZShcbiAgICAgIHRha2UoMSksXG4gICAgICBtZXJnZU1hcCh0b2tlbiA9PiB7XG4gICAgICAgIGlmICh0b2tlbikge1xuICAgICAgICAgIGNvbnN0IGhlYWRlciA9ICdCZWFyZXIgJyArIHRva2VuO1xuICAgICAgICAgIGNvbnN0IGhlYWRlcnMgPSByZXEuaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCBoZWFkZXIpO1xuICAgICAgICAgIHJlcSA9IHJlcS5jbG9uZSh7IGhlYWRlcnMgfSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gbmV4dFxuICAgICAgICAgIC5oYW5kbGUocmVxKVxuICAgICAgICAgIC5waXBlKGNhdGNoRXJyb3IoZXJyID0+IHRoaXMuZXJyb3JIYW5kbGVyLmhhbmRsZUVycm9yKGVycikpKTtcbiAgICAgIH0pLFxuICAgICk7XG4gIH1cbn1cbiJdfQ==