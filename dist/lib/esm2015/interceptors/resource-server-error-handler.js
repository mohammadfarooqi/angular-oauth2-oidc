/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { throwError } from 'rxjs';
/**
 * @abstract
 */
export class OAuthResourceServerErrorHandler {
}
if (false) {
    /**
     * @abstract
     * @param {?} err
     * @return {?}
     */
    OAuthResourceServerErrorHandler.prototype.handleError = function (err) { };
}
export class OAuthNoopResourceServerErrorHandler {
    /**
     * @param {?} err
     * @return {?}
     */
    handleError(err) {
        return throwError(err);
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsiaW50ZXJjZXB0b3JzL3Jlc291cmNlLXNlcnZlci1lcnJvci1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFDQSxPQUFPLEVBQWMsVUFBVSxFQUFFLE1BQU0sTUFBTSxDQUFDOzs7O0FBRTlDLE1BQU0sT0FBZ0IsK0JBQStCO0NBRXBEOzs7Ozs7O0lBREMsMkVBQThEOztBQUdoRSxNQUFNLE9BQU8sbUNBQW1DOzs7OztJQUU5QyxXQUFXLENBQUMsR0FBc0I7UUFDaEMsT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUM7SUFDekIsQ0FBQztDQUNGIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cFJlc3BvbnNlIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuaW1wb3J0IHsgT2JzZXJ2YWJsZSwgdGhyb3dFcnJvciB9IGZyb20gJ3J4anMnO1xuXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlciB7XG4gIGFic3RyYWN0IGhhbmRsZUVycm9yKGVycjogSHR0cFJlc3BvbnNlPGFueT4pOiBPYnNlcnZhYmxlPGFueT47XG59XG5cbmV4cG9ydCBjbGFzcyBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlclxuICBpbXBsZW1lbnRzIE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIge1xuICBoYW5kbGVFcnJvcihlcnI6IEh0dHBSZXNwb25zZTxhbnk+KTogT2JzZXJ2YWJsZTxhbnk+IHtcbiAgICByZXR1cm4gdGhyb3dFcnJvcihlcnIpO1xuICB9XG59XG4iXX0=