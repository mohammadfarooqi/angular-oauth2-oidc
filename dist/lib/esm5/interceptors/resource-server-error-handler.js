/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { throwError } from 'rxjs';
/**
 * @abstract
 */
var /**
 * @abstract
 */
OAuthResourceServerErrorHandler = /** @class */ (function () {
    function OAuthResourceServerErrorHandler() {
    }
    return OAuthResourceServerErrorHandler;
}());
/**
 * @abstract
 */
export { OAuthResourceServerErrorHandler };
if (false) {
    /**
     * @abstract
     * @param {?} err
     * @return {?}
     */
    OAuthResourceServerErrorHandler.prototype.handleError = function (err) { };
}
var OAuthNoopResourceServerErrorHandler = /** @class */ (function () {
    function OAuthNoopResourceServerErrorHandler() {
    }
    /**
     * @param {?} err
     * @return {?}
     */
    OAuthNoopResourceServerErrorHandler.prototype.handleError = /**
     * @param {?} err
     * @return {?}
     */
    function (err) {
        return throwError(err);
    };
    return OAuthNoopResourceServerErrorHandler;
}());
export { OAuthNoopResourceServerErrorHandler };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsiaW50ZXJjZXB0b3JzL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFDQSxPQUFPLEVBQWMsVUFBVSxFQUFFLE1BQU0sTUFBTSxDQUFDOzs7O0FBRTlDOzs7O0lBQUE7SUFFQSxDQUFDO0lBQUQsc0NBQUM7QUFBRCxDQUFDLEFBRkQsSUFFQzs7Ozs7Ozs7Ozs7SUFEQywyRUFBOEQ7O0FBR2hFO0lBQUE7SUFLQSxDQUFDOzs7OztJQUhDLHlEQUFXOzs7O0lBQVgsVUFBWSxHQUFzQjtRQUNoQyxPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN6QixDQUFDO0lBQ0gsMENBQUM7QUFBRCxDQUFDLEFBTEQsSUFLQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEh0dHBSZXNwb25zZSB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcbmltcG9ydCB7IE9ic2VydmFibGUsIHRocm93RXJyb3IgfSBmcm9tICdyeGpzJztcblxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIge1xuICBhYnN0cmFjdCBoYW5kbGVFcnJvcihlcnI6IEh0dHBSZXNwb25zZTxhbnk+KTogT2JzZXJ2YWJsZTxhbnk+O1xufVxuXG5leHBvcnQgY2xhc3MgT0F1dGhOb29wUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXJcbiAgaW1wbGVtZW50cyBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyIHtcbiAgaGFuZGxlRXJyb3IoZXJyOiBIdHRwUmVzcG9uc2U8YW55Pik6IE9ic2VydmFibGU8YW55PiB7XG4gICAgcmV0dXJuIHRocm93RXJyb3IoZXJyKTtcbiAgfVxufVxuIl19