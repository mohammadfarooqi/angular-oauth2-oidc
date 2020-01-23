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
const WAIT_FOR_TOKEN_RECEIVED = 1000;
export class DefaultOAuthInterceptor {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJpbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsT0FBTyxFQUFFLE1BQU0sZ0JBQWdCLENBQUM7QUFDbEYsT0FBTyxFQUFFLCtCQUErQixFQUFFLE1BQU0saUNBQWlDLENBQUM7QUFDbEYsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sd0JBQXdCLENBQUM7QUFDM0QsT0FBTyxFQUFFLFlBQVksRUFBRSxNQUFNLFVBQVUsQ0FBQztBQUN4QyxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0sa0JBQWtCLENBQUM7O01BRTFDLHVCQUF1QixHQUFHLElBQUk7QUFHcEMsTUFBTSxPQUFPLHVCQUF1Qjs7Ozs7OztJQUVoQyxZQUNZLFdBQXlCLEVBQ3pCLFlBQTBCLEVBQzFCLFlBQTZDLEVBQ2pDLFlBQStCO1FBSDNDLGdCQUFXLEdBQVgsV0FBVyxDQUFjO1FBQ3pCLGlCQUFZLEdBQVosWUFBWSxDQUFjO1FBQzFCLGlCQUFZLEdBQVosWUFBWSxDQUFpQztRQUNqQyxpQkFBWSxHQUFaLFlBQVksQ0FBbUI7SUFDbkQsQ0FBQzs7Ozs7O0lBRUcsUUFBUSxDQUFDLEdBQVc7UUFDeEIsSUFBSSxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxtQkFBbUIsRUFBRTtZQUN0RCxPQUFPLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLG1CQUFtQixDQUFD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QUFpQzs7Ozs7SUFDakMsK0NBQWtDOzs7OztJQUNsQywrQ0FBcUQ7Ozs7O0lBQ3JELCtDQUFtRCIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUsIE9wdGlvbmFsIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5cbmltcG9ydCB7XG4gIEh0dHBFdmVudCxcbiAgSHR0cEhhbmRsZXIsXG4gIEh0dHBJbnRlcmNlcHRvcixcbiAgSHR0cFJlcXVlc3QsXG59IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcbmltcG9ydCB7IE9ic2VydmFibGUsIG9mLCBtZXJnZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0IHsgY2F0Y2hFcnJvciwgZmlsdGVyLCBtYXAsIHRha2UsIG1lcmdlTWFwLCB0aW1lb3V0IH0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xuaW1wb3J0IHsgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlciB9IGZyb20gJy4vcmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXInO1xuaW1wb3J0IHsgT0F1dGhNb2R1bGVDb25maWcgfSBmcm9tICcuLi9vYXV0aC1tb2R1bGUuY29uZmlnJztcbmltcG9ydCB7IE9BdXRoU3RvcmFnZSB9IGZyb20gJy4uL3R5cGVzJztcbmltcG9ydCB7IE9BdXRoU2VydmljZSB9IGZyb20gJy4uL29hdXRoLXNlcnZpY2UnO1xuXG5jb25zdCBXQUlUX0ZPUl9UT0tFTl9SRUNFSVZFRCA9IDEwMDA7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvciBpbXBsZW1lbnRzIEh0dHBJbnRlcmNlcHRvciB7XG5cbiAgICBjb25zdHJ1Y3RvcihcbiAgICAgICAgcHJpdmF0ZSBhdXRoU3RvcmFnZTogT0F1dGhTdG9yYWdlLFxuICAgICAgICBwcml2YXRlIG9BdXRoU2VydmljZTogT0F1dGhTZXJ2aWNlLFxuICAgICAgICBwcml2YXRlIGVycm9ySGFuZGxlcjogT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcixcbiAgICAgICAgQE9wdGlvbmFsKCkgcHJpdmF0ZSBtb2R1bGVDb25maWc6IE9BdXRoTW9kdWxlQ29uZmlnXG4gICAgKSB7IH1cblxuICAgIHByaXZhdGUgY2hlY2tVcmwodXJsOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgICAgaWYgKHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmN1c3RvbVVybFZhbGlkYXRpb24pIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5jdXN0b21VcmxWYWxpZGF0aW9uKHVybCk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAodGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuYWxsb3dlZFVybHMpIHtcbiAgICAgICAgICAgIHJldHVybiAhIXRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmFsbG93ZWRVcmxzLmZpbmQodSA9PiB1cmwuc3RhcnRzV2l0aCh1KSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgcHVibGljIGludGVyY2VwdChcbiAgICByZXE6IEh0dHBSZXF1ZXN0PGFueT4sXG4gICAgbmV4dDogSHR0cEhhbmRsZXJcbiAgKTogT2JzZXJ2YWJsZTxIdHRwRXZlbnQ8YW55Pj4ge1xuICAgIGNvbnN0IHVybCA9IHJlcS51cmwudG9Mb3dlckNhc2UoKTtcblxuXG4gICAgaWYgKCF0aGlzLm1vZHVsZUNvbmZpZykge1xuICAgICAgcmV0dXJuIG5leHQuaGFuZGxlKHJlcSk7XG4gICAgfVxuICAgIGlmICghdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIpIHtcbiAgICAgIHJldHVybiBuZXh0LmhhbmRsZShyZXEpO1xuICAgIH1cbiAgICBpZiAodGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuYWxsb3dlZFVybHMgJiYgIXRoaXMuY2hlY2tVcmwodXJsKSkge1xuICAgICAgcmV0dXJuIG5leHQuaGFuZGxlKHJlcSk7XG4gICAgfVxuXG4gICAgY29uc3Qgc2VuZEFjY2Vzc1Rva2VuID0gdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIuc2VuZEFjY2Vzc1Rva2VuO1xuXG4gICAgaWYgKCFzZW5kQWNjZXNzVG9rZW4pIHtcbiAgICAgIHJldHVybiBuZXh0XG4gICAgICAgIC5oYW5kbGUocmVxKVxuICAgICAgICAucGlwZShjYXRjaEVycm9yKGVyciA9PiB0aGlzLmVycm9ySGFuZGxlci5oYW5kbGVFcnJvcihlcnIpKSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG1lcmdlKFxuICAgICAgb2YodGhpcy5vQXV0aFNlcnZpY2UuZ2V0QWNjZXNzVG9rZW4oKSkucGlwZShcbiAgICAgICAgZmlsdGVyKHRva2VuID0+IHRva2VuID8gdHJ1ZSA6IGZhbHNlKSxcbiAgICAgICksXG4gICAgICB0aGlzLm9BdXRoU2VydmljZS5ldmVudHMucGlwZShcbiAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcbiAgICAgICAgdGltZW91dChXQUlUX0ZPUl9UT0tFTl9SRUNFSVZFRCksXG4gICAgICAgIG1hcChfID0+IHRoaXMub0F1dGhTZXJ2aWNlLmdldEFjY2Vzc1Rva2VuKCkpLFxuICAgICAgKSxcbiAgICApLnBpcGUoXG4gICAgICB0YWtlKDEpLFxuICAgICAgbWVyZ2VNYXAodG9rZW4gPT4ge1xuICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICBjb25zdCBoZWFkZXIgPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICBjb25zdCBoZWFkZXJzID0gcmVxLmhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgaGVhZGVyKTtcbiAgICAgICAgICByZXEgPSByZXEuY2xvbmUoeyBoZWFkZXJzIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5leHRcbiAgICAgICAgICAuaGFuZGxlKHJlcSlcbiAgICAgICAgICAucGlwZShjYXRjaEVycm9yKGVyciA9PiB0aGlzLmVycm9ySGFuZGxlci5oYW5kbGVFcnJvcihlcnIpKSk7XG4gICAgICB9KSxcbiAgICApO1xuICB9XG59XG4iXX0=