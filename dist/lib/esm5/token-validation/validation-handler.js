/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import * as tslib_1 from "tslib";
import { base64UrlEncode } from "../base64-helper";
/**
 * @record
 */
export function ValidationParams() { }
if (false) {
    /** @type {?} */
    ValidationParams.prototype.idToken;
    /** @type {?} */
    ValidationParams.prototype.accessToken;
    /** @type {?} */
    ValidationParams.prototype.idTokenHeader;
    /** @type {?} */
    ValidationParams.prototype.idTokenClaims;
    /** @type {?} */
    ValidationParams.prototype.jwks;
    /** @type {?} */
    ValidationParams.prototype.loadKeys;
}
/**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 * @abstract
 */
var /**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 * @abstract
 */
ValidationHandler = /** @class */ (function () {
    function ValidationHandler() {
    }
    return ValidationHandler;
}());
/**
 * Interface for Handlers that are hooked in to
 * validate tokens.
 * @abstract
 */
export { ValidationHandler };
if (false) {
    /**
     * Validates the signature of an id_token.
     * @abstract
     * @param {?} validationParams
     * @return {?}
     */
    ValidationHandler.prototype.validateSignature = function (validationParams) { };
    /**
     * Validates the at_hash in an id_token against the received access_token.
     * @abstract
     * @param {?} validationParams
     * @return {?}
     */
    ValidationHandler.prototype.validateAtHash = function (validationParams) { };
}
/**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 * @abstract
 */
var /**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 * @abstract
 */
AbstractValidationHandler = /** @class */ (function () {
    function AbstractValidationHandler() {
    }
    /**
     * Validates the at_hash in an id_token against the received access_token.
     */
    /**
     * Validates the at_hash in an id_token against the received access_token.
     * @param {?} params
     * @return {?}
     */
    AbstractValidationHandler.prototype.validateAtHash = /**
     * Validates the at_hash in an id_token against the received access_token.
     * @param {?} params
     * @return {?}
     */
    function (params) {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var hashAlg, tokenHash, leftMostHalf, atHash, claimsAtHash;
            return tslib_1.__generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        hashAlg = this.inferHashAlgorithm(params.idTokenHeader);
                        return [4 /*yield*/, this.calcHash(params.accessToken, hashAlg)];
                    case 1:
                        tokenHash = _a.sent();
                        // sha256(accessToken, { asString: true });
                        leftMostHalf = tokenHash.substr(0, tokenHash.length / 2);
                        atHash = base64UrlEncode(leftMostHalf);
                        claimsAtHash = params.idTokenClaims['at_hash'].replace(/=/g, '');
                        if (atHash !== claimsAtHash) {
                            console.error('exptected at_hash: ' + atHash);
                            console.error('actual at_hash: ' + claimsAtHash);
                        }
                        return [2 /*return*/, atHash === claimsAtHash];
                }
            });
        });
    };
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @param jwtHeader the id_token's parsed header
     */
    /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @protected
     * @param {?} jwtHeader the id_token's parsed header
     * @return {?}
     */
    AbstractValidationHandler.prototype.inferHashAlgorithm = /**
     * Infers the name of the hash algorithm to use
     * from the alg field of an id_token.
     *
     * @protected
     * @param {?} jwtHeader the id_token's parsed header
     * @return {?}
     */
    function (jwtHeader) {
        /** @type {?} */
        var alg = jwtHeader['alg'];
        if (!alg.match(/^.S[0-9]{3}$/)) {
            throw new Error('Algorithm not supported: ' + alg);
        }
        return 'sha-' + alg.substr(2);
    };
    return AbstractValidationHandler;
}());
/**
 * This abstract implementation of ValidationHandler already implements
 * the method validateAtHash. However, to make use of it,
 * you have to override the method calcHash.
 * @abstract
 */
export { AbstractValidationHandler };
if (false) {
    /**
     * Validates the signature of an id_token.
     * @abstract
     * @param {?} validationParams
     * @return {?}
     */
    AbstractValidationHandler.prototype.validateSignature = function (validationParams) { };
    /**
     * Calculates the hash for the passed value by using
     * the passed hash algorithm.
     *
     * @abstract
     * @protected
     * @param {?} valueToHash
     * @param {?} algorithm
     * @return {?}
     */
    AbstractValidationHandler.prototype.calcHash = function (valueToHash, algorithm) { };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGlvbi1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsT0FBTyxFQUFFLGVBQWUsRUFBRSxNQUFNLGtCQUFrQixDQUFDOzs7O0FBRW5ELHNDQU9DOzs7SUFOQyxtQ0FBZ0I7O0lBQ2hCLHVDQUFvQjs7SUFDcEIseUNBQXNCOztJQUN0Qix5Q0FBc0I7O0lBQ3RCLGdDQUFhOztJQUNiLG9DQUFnQzs7Ozs7OztBQU9sQzs7Ozs7O0lBQUE7SUFZQSxDQUFDO0lBQUQsd0JBQUM7QUFBRCxDQUFDLEFBWkQsSUFZQzs7Ozs7Ozs7Ozs7Ozs7SUFSQyxnRkFFZ0I7Ozs7Ozs7SUFLaEIsNkVBQXFGOzs7Ozs7OztBQVF2Rjs7Ozs7OztJQUFBO0lBb0RBLENBQUM7SUE5Q0M7O09BRUc7Ozs7OztJQUNHLGtEQUFjOzs7OztJQUFwQixVQUFxQixNQUF3Qjs7Ozs7O3dCQUN2QyxPQUFPLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUM7d0JBRTNDLHFCQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxPQUFPLENBQUMsRUFBQTs7d0JBQTVELFNBQVMsR0FBRyxTQUFnRDs7d0JBRTVELFlBQVksR0FBRyxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxTQUFTLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQzt3QkFFeEQsTUFBTSxHQUFHLGVBQWUsQ0FBQyxZQUFZLENBQUM7d0JBRXRDLFlBQVksR0FBRyxNQUFNLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxJQUFJLEVBQUUsRUFBRSxDQUFDO3dCQUVwRSxJQUFJLE1BQU0sS0FBSyxZQUFZLEVBQUU7NEJBQzNCLE9BQU8sQ0FBQyxLQUFLLENBQUMscUJBQXFCLEdBQUcsTUFBTSxDQUFDLENBQUM7NEJBQzlDLE9BQU8sQ0FBQyxLQUFLLENBQUMsa0JBQWtCLEdBQUcsWUFBWSxDQUFDLENBQUM7eUJBQ2xEO3dCQUVELHNCQUFPLE1BQU0sS0FBSyxZQUFZLEVBQUM7Ozs7S0FDaEM7SUFFRDs7Ozs7T0FLRzs7Ozs7Ozs7O0lBQ08sc0RBQWtCOzs7Ozs7OztJQUE1QixVQUE2QixTQUFpQjs7WUFDeEMsR0FBRyxHQUFXLFNBQVMsQ0FBQyxLQUFLLENBQUM7UUFFbEMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsY0FBYyxDQUFDLEVBQUU7WUFDOUIsTUFBTSxJQUFJLEtBQUssQ0FBQywyQkFBMkIsR0FBRyxHQUFHLENBQUMsQ0FBQztTQUNwRDtRQUVELE9BQU8sTUFBTSxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDaEMsQ0FBQztJQVVILGdDQUFDO0FBQUQsQ0FBQyxBQXBERCxJQW9EQzs7Ozs7Ozs7Ozs7Ozs7O0lBaERDLHdGQUE2RTs7Ozs7Ozs7Ozs7SUErQzdFLHFGQUFxRiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IGJhc2U2NFVybEVuY29kZSB9IGZyb20gXCIuLi9iYXNlNjQtaGVscGVyXCI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgVmFsaWRhdGlvblBhcmFtcyB7XG4gIGlkVG9rZW46IHN0cmluZztcbiAgYWNjZXNzVG9rZW46IHN0cmluZztcbiAgaWRUb2tlbkhlYWRlcjogb2JqZWN0O1xuICBpZFRva2VuQ2xhaW1zOiBvYmplY3Q7XG4gIGp3a3M6IG9iamVjdDtcbiAgbG9hZEtleXM6ICgpID0+IFByb21pc2U8b2JqZWN0Pjtcbn1cblxuLyoqXG4gKiBJbnRlcmZhY2UgZm9yIEhhbmRsZXJzIHRoYXQgYXJlIGhvb2tlZCBpbiB0b1xuICogdmFsaWRhdGUgdG9rZW5zLlxuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgVmFsaWRhdGlvbkhhbmRsZXIge1xuICAvKipcbiAgICogVmFsaWRhdGVzIHRoZSBzaWduYXR1cmUgb2YgYW4gaWRfdG9rZW4uXG4gICAqL1xuICBwdWJsaWMgYWJzdHJhY3QgdmFsaWRhdGVTaWduYXR1cmUoXG4gICAgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtc1xuICApOiBQcm9taXNlPGFueT47XG5cbiAgLyoqXG4gICAqIFZhbGlkYXRlcyB0aGUgYXRfaGFzaCBpbiBhbiBpZF90b2tlbiBhZ2FpbnN0IHRoZSByZWNlaXZlZCBhY2Nlc3NfdG9rZW4uXG4gICAqL1xuICBwdWJsaWMgYWJzdHJhY3QgdmFsaWRhdGVBdEhhc2godmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj47XG59XG5cbi8qKlxuICogVGhpcyBhYnN0cmFjdCBpbXBsZW1lbnRhdGlvbiBvZiBWYWxpZGF0aW9uSGFuZGxlciBhbHJlYWR5IGltcGxlbWVudHNcbiAqIHRoZSBtZXRob2QgdmFsaWRhdGVBdEhhc2guIEhvd2V2ZXIsIHRvIG1ha2UgdXNlIG9mIGl0LFxuICogeW91IGhhdmUgdG8gb3ZlcnJpZGUgdGhlIG1ldGhvZCBjYWxjSGFzaC5cbiAqL1xuZXhwb3J0IGFic3RyYWN0IGNsYXNzIEFic3RyYWN0VmFsaWRhdGlvbkhhbmRsZXIgaW1wbGVtZW50cyBWYWxpZGF0aW9uSGFuZGxlciB7XG4gIC8qKlxuICAgKiBWYWxpZGF0ZXMgdGhlIHNpZ25hdHVyZSBvZiBhbiBpZF90b2tlbi5cbiAgICovXG4gIGFic3RyYWN0IHZhbGlkYXRlU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT47XG5cbiAgLyoqXG4gICAqIFZhbGlkYXRlcyB0aGUgYXRfaGFzaCBpbiBhbiBpZF90b2tlbiBhZ2FpbnN0IHRoZSByZWNlaXZlZCBhY2Nlc3NfdG9rZW4uXG4gICAqL1xuICBhc3luYyB2YWxpZGF0ZUF0SGFzaChwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGJvb2xlYW4+IHtcbiAgICBsZXQgaGFzaEFsZyA9IHRoaXMuaW5mZXJIYXNoQWxnb3JpdGhtKHBhcmFtcy5pZFRva2VuSGVhZGVyKTtcblxuICAgIGxldCB0b2tlbkhhc2ggPSBhd2FpdCB0aGlzLmNhbGNIYXNoKHBhcmFtcy5hY2Nlc3NUb2tlbiwgaGFzaEFsZyk7IC8vIHNoYTI1NihhY2Nlc3NUb2tlbiwgeyBhc1N0cmluZzogdHJ1ZSB9KTtcblxuICAgIGxldCBsZWZ0TW9zdEhhbGYgPSB0b2tlbkhhc2guc3Vic3RyKDAsIHRva2VuSGFzaC5sZW5ndGggLyAyKTtcblxuICAgIGxldCBhdEhhc2ggPSBiYXNlNjRVcmxFbmNvZGUobGVmdE1vc3RIYWxmKTtcblxuICAgIGxldCBjbGFpbXNBdEhhc2ggPSBwYXJhbXMuaWRUb2tlbkNsYWltc1snYXRfaGFzaCddLnJlcGxhY2UoLz0vZywgJycpO1xuXG4gICAgaWYgKGF0SGFzaCAhPT0gY2xhaW1zQXRIYXNoKSB7XG4gICAgICBjb25zb2xlLmVycm9yKCdleHB0ZWN0ZWQgYXRfaGFzaDogJyArIGF0SGFzaCk7XG4gICAgICBjb25zb2xlLmVycm9yKCdhY3R1YWwgYXRfaGFzaDogJyArIGNsYWltc0F0SGFzaCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGF0SGFzaCA9PT0gY2xhaW1zQXRIYXNoO1xuICB9XG5cbiAgLyoqXG4gICAqIEluZmVycyB0aGUgbmFtZSBvZiB0aGUgaGFzaCBhbGdvcml0aG0gdG8gdXNlXG4gICAqIGZyb20gdGhlIGFsZyBmaWVsZCBvZiBhbiBpZF90b2tlbi5cbiAgICpcbiAgICogQHBhcmFtIGp3dEhlYWRlciB0aGUgaWRfdG9rZW4ncyBwYXJzZWQgaGVhZGVyXG4gICAqL1xuICBwcm90ZWN0ZWQgaW5mZXJIYXNoQWxnb3JpdGhtKGp3dEhlYWRlcjogb2JqZWN0KTogc3RyaW5nIHtcbiAgICBsZXQgYWxnOiBzdHJpbmcgPSBqd3RIZWFkZXJbJ2FsZyddO1xuXG4gICAgaWYgKCFhbGcubWF0Y2goL14uU1swLTldezN9JC8pKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0FsZ29yaXRobSBub3Qgc3VwcG9ydGVkOiAnICsgYWxnKTtcbiAgICB9XG5cbiAgICByZXR1cm4gJ3NoYS0nICsgYWxnLnN1YnN0cigyKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDYWxjdWxhdGVzIHRoZSBoYXNoIGZvciB0aGUgcGFzc2VkIHZhbHVlIGJ5IHVzaW5nXG4gICAqIHRoZSBwYXNzZWQgaGFzaCBhbGdvcml0aG0uXG4gICAqXG4gICAqIEBwYXJhbSB2YWx1ZVRvSGFzaFxuICAgKiBAcGFyYW0gYWxnb3JpdGhtXG4gICAqL1xuICBwcm90ZWN0ZWQgYWJzdHJhY3QgY2FsY0hhc2godmFsdWVUb0hhc2g6IHN0cmluZywgYWxnb3JpdGhtOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz47XG59XG4iXX0=