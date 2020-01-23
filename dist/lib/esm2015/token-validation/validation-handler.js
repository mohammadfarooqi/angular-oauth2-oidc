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
export class ValidationHandler {
}
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
export class AbstractValidationHandler {
    /**
     * Validates the at_hash in an id_token against the received access_token.
     * @param {?} params
     * @return {?}
     */
    validateAtHash(params) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidmFsaWRhdGlvbi1oYW5kbGVyLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInRva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7O0FBQUEsT0FBTyxFQUFFLGVBQWUsRUFBRSxNQUFNLGtCQUFrQixDQUFDOzs7O0FBRW5ELHNDQU9DOzs7SUFOQyxtQ0FBZ0I7O0lBQ2hCLHVDQUFvQjs7SUFDcEIseUNBQXNCOztJQUN0Qix5Q0FBc0I7O0lBQ3RCLGdDQUFhOztJQUNiLG9DQUFnQzs7Ozs7OztBQU9sQyxNQUFNLE9BQWdCLGlCQUFpQjtDQVl0Qzs7Ozs7Ozs7SUFSQyxnRkFFZ0I7Ozs7Ozs7SUFLaEIsNkVBQXFGOzs7Ozs7OztBQVF2RixNQUFNLE9BQWdCLHlCQUF5Qjs7Ozs7O0lBU3ZDLGNBQWMsQ0FBQyxNQUF3Qjs7O2dCQUN2QyxPQUFPLEdBQUcsSUFBSSxDQUFDLGtCQUFrQixDQUFDLE1BQU0sQ0FBQyxhQUFhLENBQUM7O2dCQUV2RCxTQUFTLEdBQUcsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxXQUFXLEVBQUUsT0FBTyxDQUFDOzs7Z0JBRTVELFlBQVksR0FBRyxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxTQUFTLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQzs7Z0JBRXhELE1BQU0sR0FBRyxlQUFlLENBQUMsWUFBWSxDQUFDOztnQkFFdEMsWUFBWSxHQUFHLE1BQU0sQ0FBQyxhQUFhLENBQUMsU0FBUyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxFQUFFLENBQUM7WUFFcEUsSUFBSSxNQUFNLEtBQUssWUFBWSxFQUFFO2dCQUMzQixPQUFPLENBQUMsS0FBSyxDQUFDLHFCQUFxQixHQUFHLE1BQU0sQ0FBQyxDQUFDO2dCQUM5QyxPQUFPLENBQUMsS0FBSyxDQUFDLGtCQUFrQixHQUFHLFlBQVksQ0FBQyxDQUFDO2FBQ2xEO1lBRUQsT0FBTyxNQUFNLEtBQUssWUFBWSxDQUFDO1FBQ2pDLENBQUM7S0FBQTs7Ozs7Ozs7O0lBUVMsa0JBQWtCLENBQUMsU0FBaUI7O1lBQ3hDLEdBQUcsR0FBVyxTQUFTLENBQUMsS0FBSyxDQUFDO1FBRWxDLElBQUksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLGNBQWMsQ0FBQyxFQUFFO1lBQzlCLE1BQU0sSUFBSSxLQUFLLENBQUMsMkJBQTJCLEdBQUcsR0FBRyxDQUFDLENBQUM7U0FDcEQ7UUFFRCxPQUFPLE1BQU0sR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQ2hDLENBQUM7Q0FVRjs7Ozs7Ozs7SUFoREMsd0ZBQTZFOzs7Ozs7Ozs7OztJQStDN0UscUZBQXFGIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgYmFzZTY0VXJsRW5jb2RlIH0gZnJvbSBcIi4uL2Jhc2U2NC1oZWxwZXJcIjtcblxuZXhwb3J0IGludGVyZmFjZSBWYWxpZGF0aW9uUGFyYW1zIHtcbiAgaWRUb2tlbjogc3RyaW5nO1xuICBhY2Nlc3NUb2tlbjogc3RyaW5nO1xuICBpZFRva2VuSGVhZGVyOiBvYmplY3Q7XG4gIGlkVG9rZW5DbGFpbXM6IG9iamVjdDtcbiAgandrczogb2JqZWN0O1xuICBsb2FkS2V5czogKCkgPT4gUHJvbWlzZTxvYmplY3Q+O1xufVxuXG4vKipcbiAqIEludGVyZmFjZSBmb3IgSGFuZGxlcnMgdGhhdCBhcmUgaG9va2VkIGluIHRvXG4gKiB2YWxpZGF0ZSB0b2tlbnMuXG4gKi9cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBWYWxpZGF0aW9uSGFuZGxlciB7XG4gIC8qKlxuICAgKiBWYWxpZGF0ZXMgdGhlIHNpZ25hdHVyZSBvZiBhbiBpZF90b2tlbi5cbiAgICovXG4gIHB1YmxpYyBhYnN0cmFjdCB2YWxpZGF0ZVNpZ25hdHVyZShcbiAgICB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zXG4gICk6IFByb21pc2U8YW55PjtcblxuICAvKipcbiAgICogVmFsaWRhdGVzIHRoZSBhdF9oYXNoIGluIGFuIGlkX3Rva2VuIGFnYWluc3QgdGhlIHJlY2VpdmVkIGFjY2Vzc190b2tlbi5cbiAgICovXG4gIHB1YmxpYyBhYnN0cmFjdCB2YWxpZGF0ZUF0SGFzaCh2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxib29sZWFuPjtcbn1cblxuLyoqXG4gKiBUaGlzIGFic3RyYWN0IGltcGxlbWVudGF0aW9uIG9mIFZhbGlkYXRpb25IYW5kbGVyIGFscmVhZHkgaW1wbGVtZW50c1xuICogdGhlIG1ldGhvZCB2YWxpZGF0ZUF0SGFzaC4gSG93ZXZlciwgdG8gbWFrZSB1c2Ugb2YgaXQsXG4gKiB5b3UgaGF2ZSB0byBvdmVycmlkZSB0aGUgbWV0aG9kIGNhbGNIYXNoLlxuICovXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgQWJzdHJhY3RWYWxpZGF0aW9uSGFuZGxlciBpbXBsZW1lbnRzIFZhbGlkYXRpb25IYW5kbGVyIHtcbiAgLyoqXG4gICAqIFZhbGlkYXRlcyB0aGUgc2lnbmF0dXJlIG9mIGFuIGlkX3Rva2VuLlxuICAgKi9cbiAgYWJzdHJhY3QgdmFsaWRhdGVTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8YW55PjtcblxuICAvKipcbiAgICogVmFsaWRhdGVzIHRoZSBhdF9oYXNoIGluIGFuIGlkX3Rva2VuIGFnYWluc3QgdGhlIHJlY2VpdmVkIGFjY2Vzc190b2tlbi5cbiAgICovXG4gIGFzeW5jIHZhbGlkYXRlQXRIYXNoKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIGxldCBoYXNoQWxnID0gdGhpcy5pbmZlckhhc2hBbGdvcml0aG0ocGFyYW1zLmlkVG9rZW5IZWFkZXIpO1xuXG4gICAgbGV0IHRva2VuSGFzaCA9IGF3YWl0IHRoaXMuY2FsY0hhc2gocGFyYW1zLmFjY2Vzc1Rva2VuLCBoYXNoQWxnKTsgLy8gc2hhMjU2KGFjY2Vzc1Rva2VuLCB7IGFzU3RyaW5nOiB0cnVlIH0pO1xuXG4gICAgbGV0IGxlZnRNb3N0SGFsZiA9IHRva2VuSGFzaC5zdWJzdHIoMCwgdG9rZW5IYXNoLmxlbmd0aCAvIDIpO1xuXG4gICAgbGV0IGF0SGFzaCA9IGJhc2U2NFVybEVuY29kZShsZWZ0TW9zdEhhbGYpO1xuXG4gICAgbGV0IGNsYWltc0F0SGFzaCA9IHBhcmFtcy5pZFRva2VuQ2xhaW1zWydhdF9oYXNoJ10ucmVwbGFjZSgvPS9nLCAnJyk7XG5cbiAgICBpZiAoYXRIYXNoICE9PSBjbGFpbXNBdEhhc2gpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ2V4cHRlY3RlZCBhdF9oYXNoOiAnICsgYXRIYXNoKTtcbiAgICAgIGNvbnNvbGUuZXJyb3IoJ2FjdHVhbCBhdF9oYXNoOiAnICsgY2xhaW1zQXRIYXNoKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYXRIYXNoID09PSBjbGFpbXNBdEhhc2g7XG4gIH1cblxuICAvKipcbiAgICogSW5mZXJzIHRoZSBuYW1lIG9mIHRoZSBoYXNoIGFsZ29yaXRobSB0byB1c2VcbiAgICogZnJvbSB0aGUgYWxnIGZpZWxkIG9mIGFuIGlkX3Rva2VuLlxuICAgKlxuICAgKiBAcGFyYW0gand0SGVhZGVyIHRoZSBpZF90b2tlbidzIHBhcnNlZCBoZWFkZXJcbiAgICovXG4gIHByb3RlY3RlZCBpbmZlckhhc2hBbGdvcml0aG0oand0SGVhZGVyOiBvYmplY3QpOiBzdHJpbmcge1xuICAgIGxldCBhbGc6IHN0cmluZyA9IGp3dEhlYWRlclsnYWxnJ107XG5cbiAgICBpZiAoIWFsZy5tYXRjaCgvXi5TWzAtOV17M30kLykpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQWxnb3JpdGhtIG5vdCBzdXBwb3J0ZWQ6ICcgKyBhbGcpO1xuICAgIH1cblxuICAgIHJldHVybiAnc2hhLScgKyBhbGcuc3Vic3RyKDIpO1xuICB9XG5cbiAgLyoqXG4gICAqIENhbGN1bGF0ZXMgdGhlIGhhc2ggZm9yIHRoZSBwYXNzZWQgdmFsdWUgYnkgdXNpbmdcbiAgICogdGhlIHBhc3NlZCBoYXNoIGFsZ29yaXRobS5cbiAgICpcbiAgICogQHBhcmFtIHZhbHVlVG9IYXNoXG4gICAqIEBwYXJhbSBhbGdvcml0aG1cbiAgICovXG4gIHByb3RlY3RlZCBhYnN0cmFjdCBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPjtcbn1cbiJdfQ==