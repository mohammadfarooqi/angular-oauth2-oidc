/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import * as tslib_1 from "tslib";
import { AbstractValidationHandler } from './validation-handler';
// declare var require: any;
// let rs = require('jsrsasign');
import * as rs from 'jsrsasign';
/**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
var /**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
JwksValidationHandler = /** @class */ (function (_super) {
    tslib_1.__extends(JwksValidationHandler, _super);
    function JwksValidationHandler() {
        var _this = _super !== null && _super.apply(this, arguments) || this;
        /**
         * Allowed algorithms
         */
        _this.allowedAlgorithms = [
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
        _this.gracePeriodInSec = 600;
        return _this;
    }
    /**
     * @param {?} params
     * @param {?=} retry
     * @return {?}
     */
    JwksValidationHandler.prototype.validateSignature = /**
     * @param {?} params
     * @param {?=} retry
     * @return {?}
     */
    function (params, retry) {
        var _this = this;
        if (retry === void 0) { retry = false; }
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
        var kid = params.idTokenHeader['kid'];
        /** @type {?} */
        var keys = params.jwks['keys'];
        /** @type {?} */
        var key;
        /** @type {?} */
        var alg = params.idTokenHeader['alg'];
        if (kid) {
            key = keys.find((/**
             * @param {?} k
             * @return {?}
             */
            function (k) { return k['kid'] === kid; } /* && k['use'] === 'sig' */));
        }
        else {
            /** @type {?} */
            var kty_1 = this.alg2kty(alg);
            /** @type {?} */
            var matchingKeys = keys.filter((/**
             * @param {?} k
             * @return {?}
             */
            function (k) { return k['kty'] === kty_1 && k['use'] === 'sig'; }));
            /*
                  if (matchingKeys.length == 0) {
                      let error = 'No matching key found.';
                      console.error(error);
                      return Promise.reject(error);
                  }*/
            if (matchingKeys.length > 1) {
                /** @type {?} */
                var error = 'More than one matching key found. Please specify a kid in the id_token header.';
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
            function (loadedKeys) { return (params.jwks = loadedKeys); }))
                .then((/**
             * @param {?} _
             * @return {?}
             */
            function (_) { return _this.validateSignature(params, true); }));
        }
        if (!key && retry && !kid) {
            /** @type {?} */
            var error = 'No matching key found.';
            console.error(error);
            return Promise.reject(error);
        }
        if (!key && retry && kid) {
            /** @type {?} */
            var error = 'expected key not found in property jwks. ' +
                'This property is most likely loaded with the ' +
                'discovery document. ' +
                'Expected key id (kid): ' +
                kid;
            console.error(error);
            return Promise.reject(error);
        }
        /** @type {?} */
        var keyObj = rs.KEYUTIL.getKey(key);
        /** @type {?} */
        var validationOptions = {
            alg: this.allowedAlgorithms,
            gracePeriod: this.gracePeriodInSec
        };
        /** @type {?} */
        var isValid = rs.KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, validationOptions);
        if (isValid) {
            return Promise.resolve();
        }
        else {
            return Promise.reject('Signature not valid');
        }
    };
    /**
     * @private
     * @param {?} alg
     * @return {?}
     */
    JwksValidationHandler.prototype.alg2kty = /**
     * @private
     * @param {?} alg
     * @return {?}
     */
    function (alg) {
        switch (alg.charAt(0)) {
            case 'R':
                return 'RSA';
            case 'E':
                return 'EC';
            default:
                throw new Error('Cannot infer kty from alg: ' + alg);
        }
    };
    /**
     * @param {?} valueToHash
     * @param {?} algorithm
     * @return {?}
     */
    JwksValidationHandler.prototype.calcHash = /**
     * @param {?} valueToHash
     * @param {?} algorithm
     * @return {?}
     */
    function (valueToHash, algorithm) {
        /** @type {?} */
        var hashAlg = new rs.KJUR.crypto.MessageDigest({ alg: algorithm });
        /** @type {?} */
        var result = hashAlg.digestString(valueToHash);
        /** @type {?} */
        var byteArrayAsString = this.toByteArrayAsString(result);
        return Promise.resolve(byteArrayAsString);
    };
    /**
     * @param {?} hexString
     * @return {?}
     */
    JwksValidationHandler.prototype.toByteArrayAsString = /**
     * @param {?} hexString
     * @return {?}
     */
    function (hexString) {
        /** @type {?} */
        var result = '';
        for (var i = 0; i < hexString.length; i += 2) {
            /** @type {?} */
            var hexDigit = hexString.charAt(i) + hexString.charAt(i + 1);
            /** @type {?} */
            var num = parseInt(hexDigit, 16);
            result += String.fromCharCode(num);
        }
        return result;
    };
    return JwksValidationHandler;
}(AbstractValidationHandler));
/**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
export { JwksValidationHandler };
if (false) {
    /**
     * Allowed algorithms
     * @type {?}
     */
    JwksValidationHandler.prototype.allowedAlgorithms;
    /**
     * Time period in seconds the timestamp in the signature can
     * differ from the current time.
     * @type {?}
     */
    JwksValidationHandler.prototype.gracePeriodInSec;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiandrcy12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9qd2tzLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLE9BQU8sRUFDTCx5QkFBeUIsRUFFMUIsTUFBTSxzQkFBc0IsQ0FBQzs7O0FBSzlCLE9BQU8sS0FBSyxFQUFFLE1BQU0sV0FBVyxDQUFDOzs7Ozs7O0FBUWhDOzs7Ozs7O0lBQTJDLGlEQUF5QjtJQUFwRTtRQUFBLHFFQTRJQzs7OztRQXhJQyx1QkFBaUIsR0FBYTtZQUM1QixPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztTQUNSLENBQUM7Ozs7O1FBTUYsc0JBQWdCLEdBQUcsR0FBRyxDQUFDOztJQXNIekIsQ0FBQzs7Ozs7O0lBcEhDLGlEQUFpQjs7Ozs7SUFBakIsVUFBa0IsTUFBd0IsRUFBRSxLQUFhO1FBQXpELGlCQXVGQztRQXZGMkMsc0JBQUEsRUFBQSxhQUFhO1FBQ3ZELElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTztZQUFFLE1BQU0sSUFBSSxLQUFLLENBQUMsNkJBQTZCLENBQUMsQ0FBQztRQUNwRSxJQUFJLENBQUMsTUFBTSxDQUFDLGFBQWE7WUFDdkIsTUFBTSxJQUFJLEtBQUssQ0FBQyxvQ0FBb0MsQ0FBQyxDQUFDO1FBQ3hELElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSTtZQUFFLE1BQU0sSUFBSSxLQUFLLENBQUMsMEJBQTBCLENBQUMsQ0FBQztRQUU5RCxJQUNFLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUM7WUFDcEIsQ0FBQyxLQUFLLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFB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QUFHLENBQUMsQ0FBQzs7Z0JBQ3hELEdBQUcsR0FBRyxRQUFRLENBQUMsUUFBUSxFQUFFLEVBQUUsQ0FBQztZQUNoQyxNQUFNLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUNwQztRQUNELE9BQU8sTUFBTSxDQUFDO0lBQ2hCLENBQUM7SUFDSCw0QkFBQztBQUFELENBQUMsQUE1SUQsQ0FBMkMseUJBQXlCLEdBNEluRTs7Ozs7Ozs7Ozs7OztJQXhJQyxrREFZRTs7Ozs7O0lBTUYsaURBQXVCIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHtcbiAgQWJzdHJhY3RWYWxpZGF0aW9uSGFuZGxlcixcbiAgVmFsaWRhdGlvblBhcmFtc1xufSBmcm9tICcuL3ZhbGlkYXRpb24taGFuZGxlcic7XG5cbi8vIGRlY2xhcmUgdmFyIHJlcXVpcmU6IGFueTtcbi8vIGxldCBycyA9IHJlcXVpcmUoJ2pzcnNhc2lnbicpO1xuXG5pbXBvcnQgKiBhcyBycyBmcm9tICdqc3JzYXNpZ24nO1xuXG4vKipcbiAqIFZhbGlkYXRlcyB0aGUgc2lnbmF0dXJlIG9mIGFuIGlkX3Rva2VuIGFnYWluc3Qgb25lXG4gKiBvZiB0aGUga2V5cyBvZiBhbiBKU09OIFdlYiBLZXkgU2V0IChqd2tzKS5cbiAqXG4gKiBUaGlzIGp3a3MgY2FuIGJlIHByb3ZpZGVkIGJ5IHRoZSBkaXNjb3ZlcnkgZG9jdW1lbnQuXG4gKi9cbmV4cG9ydCBjbGFzcyBKd2tzVmFsaWRhdGlvbkhhbmRsZXIgZXh0ZW5kcyBBYnN0cmFjdFZhbGlkYXRpb25IYW5kbGVyIHtcbiAgLyoqXG4gICAqIEFsbG93ZWQgYWxnb3JpdGhtc1xuICAgKi9cbiAgYWxsb3dlZEFsZ29yaXRobXM6IHN0cmluZ1tdID0gW1xuICAgICdIUzI1NicsXG4gICAgJ0hTMzg0JyxcbiAgICAnSFM1MTInLFxuICAgICdSUzI1NicsXG4gICAgJ1JTMzg0JyxcbiAgICAnUlM1MTInLFxuICAgICdFUzI1NicsXG4gICAgJ0VTMzg0JyxcbiAgICAnUFMyNTYnLFxuICAgICdQUzM4NCcsXG4gICAgJ1BTNTEyJ1xuICBdO1xuXG4gIC8qKlxuICAgKiBUaW1lIHBlcmlvZCBpbiBzZWNvbmRzIHRoZSB0aW1lc3RhbXAgaW4gdGhlIHNpZ25hdHVyZSBjYW5cbiAgICogZGlmZmVyIGZyb20gdGhlIGN1cnJlbnQgdGltZS5cbiAgICovXG4gIGdyYWNlUGVyaW9kSW5TZWMgPSA2MDA7XG5cbiAgdmFsaWRhdGVTaWduYXR1cmUocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zLCByZXRyeSA9IGZhbHNlKTogUHJvbWlzZTxhbnk+IHtcbiAgICBpZiAoIXBhcmFtcy5pZFRva2VuKSB0aHJvdyBuZXcgRXJyb3IoJ1BhcmFtZXRlciBpZFRva2VuIGV4cGVjdGVkIScpO1xuICAgIGlmICghcGFyYW1zLmlkVG9rZW5IZWFkZXIpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1BhcmFtZXRlciBpZFRva2VuSGFuZGxlciBleHBlY3RlZC4nKTtcbiAgICBpZiAoIXBhcmFtcy5qd2tzKSB0aHJvdyBuZXcgRXJyb3IoJ1BhcmFtZXRlciBqd2tzIGV4cGVjdGVkIScpO1xuXG4gICAgaWYgKFxuICAgICAgIXBhcmFtcy5qd2tzWydrZXlzJ10gfHxcbiAgICAgICFBcnJheS5pc0FycmF5KHBhcmFtcy5qd2tzWydrZXlzJ10pIHx8XG4gICAgICBwYXJhbXMuandrc1sna2V5cyddLmxlbmd0aCA9PT0gMFxuICAgICkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdBcnJheSBrZXlzIGluIGp3a3MgbWlzc2luZyEnKTtcbiAgICB9XG5cbiAgICAvLyBjb25zb2xlLmRlYnVnKCd2YWxpZGF0ZVNpZ25hdHVyZTogcmV0cnknLCByZXRyeSk7XG5cbiAgICBsZXQga2lkOiBzdHJpbmcgPSBwYXJhbXMuaWRUb2tlbkhlYWRlclsna2lkJ107XG4gICAgbGV0IGtleXM6IG9iamVjdFtdID0gcGFyYW1zLmp3a3NbJ2tleXMnXTtcbiAgICBsZXQga2V5OiBvYmplY3Q7XG5cbiAgICBsZXQgYWxnID0gcGFyYW1zLmlkVG9rZW5IZWFkZXJbJ2FsZyddO1xuXG4gICAgaWYgKGtpZCkge1xuICAgICAga2V5ID0ga2V5cy5maW5kKGsgPT4ga1sna2lkJ10gPT09IGtpZCAvKiAmJiBrWyd1c2UnXSA9PT0gJ3NpZycgKi8pO1xuICAgIH0gZWxzZSB7XG4gICAgICBsZXQga3R5ID0gdGhpcy5hbGcya3R5KGFsZyk7XG4gICAgICBsZXQgbWF0Y2hpbmdLZXlzID0ga2V5cy5maWx0ZXIoXG4gICAgICAgIGsgPT4ga1sna3R5J10gPT09IGt0eSAmJiBrWyd1c2UnXSA9PT0gJ3NpZydcbiAgICAgICk7XG5cbiAgICAgIC8qXG4gICAgICAgICAgICBpZiAobWF0Y2hpbmdLZXlzLmxlbmd0aCA9PSAwKSB7XG4gICAgICAgICAgICAgICAgbGV0IGVycm9yID0gJ05vIG1hdGNoaW5nIGtleSBmb3VuZC4nO1xuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgICAgICAgICB9Ki9cbiAgICAgIGlmIChtYXRjaGluZ0tleXMubGVuZ3RoID4gMSkge1xuICAgICAgICBsZXQgZXJyb3IgPVxuICAgICAgICAgICdNb3JlIHRoYW4gb25lIG1hdGNoaW5nIGtleSBmb3VuZC4gUGxlYXNlIHNwZWNpZnkgYSBraWQgaW4gdGhlIGlkX3Rva2VuIGhlYWRlci4nO1xuICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICAgIH0gZWxzZSBpZiAobWF0Y2hpbmdLZXlzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICBrZXkgPSBtYXRjaGluZ0tleXNbMF07XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKCFrZXkgJiYgIXJldHJ5ICYmIHBhcmFtcy5sb2FkS2V5cykge1xuICAgICAgcmV0dXJuIHBhcmFtc1xuICAgICAgICAubG9hZEtleXMoKVxuICAgICAgICAudGhlbihsb2FkZWRLZXlzID0+IChwYXJhbXMuandrcyA9IGxvYWRlZEtleXMpKVxuICAgICAgICAudGhlbihfID0+IHRoaXMudmFsaWRhdGVTaWduYXR1cmUocGFyYW1zLCB0cnVlKSk7XG4gICAgfVxuXG4gICAgaWYgKCFrZXkgJiYgcmV0cnkgJiYgIWtpZCkge1xuICAgICAgbGV0IGVycm9yID0gJ05vIG1hdGNoaW5nIGtleSBmb3VuZC4nO1xuICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cblxuICAgIGlmICgha2V5ICYmIHJldHJ5ICYmIGtpZCkge1xuICAgICAgbGV0IGVycm9yID1cbiAgICAgICAgJ2V4cGVjdGVkIGtleSBub3QgZm91bmQgaW4gcHJvcGVydHkgandrcy4gJyArXG4gICAgICAgICdUaGlzIHByb3BlcnR5IGlzIG1vc3QgbGlrZWx5IGxvYWRlZCB3aXRoIHRoZSAnICtcbiAgICAgICAgJ2Rpc2NvdmVyeSBkb2N1bWVudC4gJyArXG4gICAgICAgICdFeHBlY3RlZCBrZXkgaWQgKGtpZCk6ICcgK1xuICAgICAgICBraWQ7XG5cbiAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG5cbiAgICBsZXQga2V5T2JqID0gcnMuS0VZVVRJTC5nZXRLZXkoa2V5KTtcbiAgICBsZXQgdmFsaWRhdGlvbk9wdGlvbnMgPSB7XG4gICAgICBhbGc6IHRoaXMuYWxsb3dlZEFsZ29yaXRobXMsXG4gICAgICBncmFjZVBlcmlvZDogdGhpcy5ncmFjZVBlcmlvZEluU2VjXG4gICAgfTtcbiAgICBsZXQgaXNWYWxpZCA9IHJzLktKVVIuandzLkpXUy52ZXJpZnlKV1QoXG4gICAgICBwYXJhbXMuaWRUb2tlbixcbiAgICAgIGtleU9iaixcbiAgICAgIHZhbGlkYXRpb25PcHRpb25zXG4gICAgKTtcblxuICAgIGlmIChpc1ZhbGlkKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdCgnU2lnbmF0dXJlIG5vdCB2YWxpZCcpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgYWxnMmt0eShhbGc6IHN0cmluZykge1xuICAgIHN3aXRjaCAoYWxnLmNoYXJBdCgwKSkge1xuICAgICAgY2FzZSAnUic6XG4gICAgICAgIHJldHVybiAnUlNBJztcbiAgICAgIGNhc2UgJ0UnOlxuICAgICAgICByZXR1cm4gJ0VDJztcbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignQ2Fubm90IGluZmVyIGt0eSBmcm9tIGFsZzogJyArIGFsZyk7XG4gICAgfVxuICB9XG5cbiAgY2FsY0hhc2godmFsdWVUb0hhc2g6IHN0cmluZywgYWxnb3JpdGhtOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGxldCBoYXNoQWxnID0gbmV3IHJzLktKVVIuY3J5cHRvLk1lc3NhZ2VEaWdlc3QoeyBhbGc6IGFsZ29yaXRobSB9KTtcbiAgICBsZXQgcmVzdWx0ID0gaGFzaEFsZy5kaWdlc3RTdHJpbmcodmFsdWVUb0hhc2gpO1xuICAgIGxldCBieXRlQXJyYXlBc1N0cmluZyA9IHRoaXMudG9CeXRlQXJyYXlBc1N0cmluZyhyZXN1bHQpO1xuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoYnl0ZUFycmF5QXNTdHJpbmcpO1xuICB9XG5cbiAgdG9CeXRlQXJyYXlBc1N0cmluZyhoZXhTdHJpbmc6IHN0cmluZykge1xuICAgIGxldCByZXN1bHQgPSAnJztcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGhleFN0cmluZy5sZW5ndGg7IGkgKz0gMikge1xuICAgICAgbGV0IGhleERpZ2l0ID0gaGV4U3RyaW5nLmNoYXJBdChpKSArIGhleFN0cmluZy5jaGFyQXQoaSArIDEpO1xuICAgICAgbGV0IG51bSA9IHBhcnNlSW50KGhleERpZ2l0LCAxNik7XG4gICAgICByZXN1bHQgKz0gU3RyaW5nLmZyb21DaGFyQ29kZShudW0pO1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG59Il19