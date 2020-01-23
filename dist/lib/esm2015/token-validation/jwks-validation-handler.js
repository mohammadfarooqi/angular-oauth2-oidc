/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
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
export class JwksValidationHandler extends AbstractValidationHandler {
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
        let keyObj = rs.KEYUTIL.getKey(key);
        /** @type {?} */
        let validationOptions = {
            alg: this.allowedAlgorithms,
            gracePeriod: this.gracePeriodInSec
        };
        /** @type {?} */
        let isValid = rs.KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, validationOptions);
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
        let hashAlg = new rs.KJUR.crypto.MessageDigest({ alg: algorithm });
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiandrcy12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9qd2tzLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUNMLHlCQUF5QixFQUUxQixNQUFNLHNCQUFzQixDQUFDOzs7QUFLOUIsT0FBTyxLQUFLLEVBQUUsTUFBTSxXQUFXLENBQUM7Ozs7Ozs7QUFRaEMsTUFBTSxPQUFPLHFCQUFzQixTQUFRLHlCQUF5QjtJQUFwRTs7Ozs7UUFJRSxzQkFBaUIsR0FBYTtZQUM1QixPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztTQUNSLENBQUM7Ozs7O1FBTUYscUJBQWdCLEdBQUcsR0FBRyxDQUFDO0lBc0h6QixDQUFDOzs7Ozs7SUFwSEMsaUJBQWlCLENBQUMsTUFBd0IsRUFBRSxLQUFLLEdBQUcsS0FBSztRQUN2RCxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU87WUFBRSxNQUFNLElBQUksS0FBSyxDQUFDLDZCQUE2QixDQUFDLENBQUM7UUFDcEUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxhQUFhO1lBQ3ZCLE1BQU0sSUFBSSxLQUFLLENBQUMsb0NBQW9DLENBQUMsQ0FBQztRQUN4RCxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUk7WUFBRSxNQUFNLElBQUksS0FBSyxDQUFDLDBCQUEwQixDQUFDLENBQUM7UUFFOUQsSUFDRSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDO1lBQ3BCLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDO1lBQ25DLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFB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QUNELE9BQU8sTUFBTSxDQUFDO0lBQ2hCLENBQUM7Q0FDRjs7Ozs7O0lBeElDLGtEQVlFOzs7Ozs7SUFNRixpREFBdUIiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQge1xuICBBYnN0cmFjdFZhbGlkYXRpb25IYW5kbGVyLFxuICBWYWxpZGF0aW9uUGFyYW1zXG59IGZyb20gJy4vdmFsaWRhdGlvbi1oYW5kbGVyJztcblxuLy8gZGVjbGFyZSB2YXIgcmVxdWlyZTogYW55O1xuLy8gbGV0IHJzID0gcmVxdWlyZSgnanNyc2FzaWduJyk7XG5cbmltcG9ydCAqIGFzIHJzIGZyb20gJ2pzcnNhc2lnbic7XG5cbi8qKlxuICogVmFsaWRhdGVzIHRoZSBzaWduYXR1cmUgb2YgYW4gaWRfdG9rZW4gYWdhaW5zdCBvbmVcbiAqIG9mIHRoZSBrZXlzIG9mIGFuIEpTT04gV2ViIEtleSBTZXQgKGp3a3MpLlxuICpcbiAqIFRoaXMgandrcyBjYW4gYmUgcHJvdmlkZWQgYnkgdGhlIGRpc2NvdmVyeSBkb2N1bWVudC5cbiAqL1xuZXhwb3J0IGNsYXNzIEp3a3NWYWxpZGF0aW9uSGFuZGxlciBleHRlbmRzIEFic3RyYWN0VmFsaWRhdGlvbkhhbmRsZXIge1xuICAvKipcbiAgICogQWxsb3dlZCBhbGdvcml0aG1zXG4gICAqL1xuICBhbGxvd2VkQWxnb3JpdGhtczogc3RyaW5nW10gPSBbXG4gICAgJ0hTMjU2JyxcbiAgICAnSFMzODQnLFxuICAgICdIUzUxMicsXG4gICAgJ1JTMjU2JyxcbiAgICAnUlMzODQnLFxuICAgICdSUzUxMicsXG4gICAgJ0VTMjU2JyxcbiAgICAnRVMzODQnLFxuICAgICdQUzI1NicsXG4gICAgJ1BTMzg0JyxcbiAgICAnUFM1MTInXG4gIF07XG5cbiAgLyoqXG4gICAqIFRpbWUgcGVyaW9kIGluIHNlY29uZHMgdGhlIHRpbWVzdGFtcCBpbiB0aGUgc2lnbmF0dXJlIGNhblxuICAgKiBkaWZmZXIgZnJvbSB0aGUgY3VycmVudCB0aW1lLlxuICAgKi9cbiAgZ3JhY2VQZXJpb2RJblNlYyA9IDYwMDtcblxuICB2YWxpZGF0ZVNpZ25hdHVyZShwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMsIHJldHJ5ID0gZmFsc2UpOiBQcm9taXNlPGFueT4ge1xuICAgIGlmICghcGFyYW1zLmlkVG9rZW4pIHRocm93IG5ldyBFcnJvcignUGFyYW1ldGVyIGlkVG9rZW4gZXhwZWN0ZWQhJyk7XG4gICAgaWYgKCFwYXJhbXMuaWRUb2tlbkhlYWRlcilcbiAgICAgIHRocm93IG5ldyBFcnJvcignUGFyYW1ldGVyIGlkVG9rZW5IYW5kbGVyIGV4cGVjdGVkLicpO1xuICAgIGlmICghcGFyYW1zLmp3a3MpIHRocm93IG5ldyBFcnJvcignUGFyYW1ldGVyIGp3a3MgZXhwZWN0ZWQhJyk7XG5cbiAgICBpZiAoXG4gICAgICAhcGFyYW1zLmp3a3NbJ2tleXMnXSB8fFxuICAgICAgIUFycmF5LmlzQXJyYXkocGFyYW1zLmp3a3NbJ2tleXMnXSkgfHxcbiAgICAgIHBhcmFtcy5qd2tzWydrZXlzJ10ubGVuZ3RoID09PSAwXG4gICAgKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0FycmF5IGtleXMgaW4gandrcyBtaXNzaW5nIScpO1xuICAgIH1cblxuICAgIC8vIGNvbnNvbGUuZGVidWcoJ3ZhbGlkYXRlU2lnbmF0dXJlOiByZXRyeScsIHJldHJ5KTtcblxuICAgIGxldCBraWQ6IHN0cmluZyA9IHBhcmFtcy5pZFRva2VuSGVhZGVyWydraWQnXTtcbiAgICBsZXQga2V5czogb2JqZWN0W10gPSBwYXJhbXMuandrc1sna2V5cyddO1xuICAgIGxldCBrZXk6IG9iamVjdDtcblxuICAgIGxldCBhbGcgPSBwYXJhbXMuaWRUb2tlbkhlYWRlclsnYWxnJ107XG5cbiAgICBpZiAoa2lkKSB7XG4gICAgICBrZXkgPSBrZXlzLmZpbmQoayA9PiBrWydraWQnXSA9PT0ga2lkIC8qICYmIGtbJ3VzZSddID09PSAnc2lnJyAqLyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGxldCBrdHkgPSB0aGlzLmFsZzJrdHkoYWxnKTtcbiAgICAgIGxldCBtYXRjaGluZ0tleXMgPSBrZXlzLmZpbHRlcihcbiAgICAgICAgayA9PiBrWydrdHknXSA9PT0ga3R5ICYmIGtbJ3VzZSddID09PSAnc2lnJ1xuICAgICAgKTtcblxuICAgICAgLypcbiAgICAgICAgICAgIGlmIChtYXRjaGluZ0tleXMubGVuZ3RoID09IDApIHtcbiAgICAgICAgICAgICAgICBsZXQgZXJyb3IgPSAnTm8gbWF0Y2hpbmcga2V5IGZvdW5kLic7XG4gICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICAgICAgICAgIH0qL1xuICAgICAgaWYgKG1hdGNoaW5nS2V5cy5sZW5ndGggPiAxKSB7XG4gICAgICAgIGxldCBlcnJvciA9XG4gICAgICAgICAgJ01vcmUgdGhhbiBvbmUgbWF0Y2hpbmcga2V5IGZvdW5kLiBQbGVhc2Ugc3BlY2lmeSBhIGtpZCBpbiB0aGUgaWRfdG9rZW4gaGVhZGVyLic7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgICAgfSBlbHNlIGlmIChtYXRjaGluZ0tleXMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgIGtleSA9IG1hdGNoaW5nS2V5c1swXTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoIWtleSAmJiAhcmV0cnkgJiYgcGFyYW1zLmxvYWRLZXlzKSB7XG4gICAgICByZXR1cm4gcGFyYW1zXG4gICAgICAgIC5sb2FkS2V5cygpXG4gICAgICAgIC50aGVuKGxvYWRlZEtleXMgPT4gKHBhcmFtcy5qd2tzID0gbG9hZGVkS2V5cykpXG4gICAgICAgIC50aGVuKF8gPT4gdGhpcy52YWxpZGF0ZVNpZ25hdHVyZShwYXJhbXMsIHRydWUpKTtcbiAgICB9XG5cbiAgICBpZiAoIWtleSAmJiByZXRyeSAmJiAha2lkKSB7XG4gICAgICBsZXQgZXJyb3IgPSAnTm8gbWF0Y2hpbmcga2V5IGZvdW5kLic7XG4gICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuXG4gICAgaWYgKCFrZXkgJiYgcmV0cnkgJiYga2lkKSB7XG4gICAgICBsZXQgZXJyb3IgPVxuICAgICAgICAnZXhwZWN0ZWQga2V5IG5vdCBmb3VuZCBpbiBwcm9wZXJ0eSBqd2tzLiAnICtcbiAgICAgICAgJ1RoaXMgcHJvcGVydHkgaXMgbW9zdCBsaWtlbHkgbG9hZGVkIHdpdGggdGhlICcgK1xuICAgICAgICAnZGlzY292ZXJ5IGRvY3VtZW50LiAnICtcbiAgICAgICAgJ0V4cGVjdGVkIGtleSBpZCAoa2lkKTogJyArXG4gICAgICAgIGtpZDtcblxuICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cblxuICAgIGxldCBrZXlPYmogPSBycy5LRVlVVElMLmdldEtleShrZXkpO1xuICAgIGxldCB2YWxpZGF0aW9uT3B0aW9ucyA9IHtcbiAgICAgIGFsZzogdGhpcy5hbGxvd2VkQWxnb3JpdGhtcyxcbiAgICAgIGdyYWNlUGVyaW9kOiB0aGlzLmdyYWNlUGVyaW9kSW5TZWNcbiAgICB9O1xuICAgIGxldCBpc1ZhbGlkID0gcnMuS0pVUi5qd3MuSldTLnZlcmlmeUpXVChcbiAgICAgIHBhcmFtcy5pZFRva2VuLFxuICAgICAga2V5T2JqLFxuICAgICAgdmFsaWRhdGlvbk9wdGlvbnNcbiAgICApO1xuXG4gICAgaWYgKGlzVmFsaWQpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KCdTaWduYXR1cmUgbm90IHZhbGlkJyk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBhbGcya3R5KGFsZzogc3RyaW5nKSB7XG4gICAgc3dpdGNoIChhbGcuY2hhckF0KDApKSB7XG4gICAgICBjYXNlICdSJzpcbiAgICAgICAgcmV0dXJuICdSU0EnO1xuICAgICAgY2FzZSAnRSc6XG4gICAgICAgIHJldHVybiAnRUMnO1xuICAgICAgZGVmYXVsdDpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdDYW5ub3QgaW5mZXIga3R5IGZyb20gYWxnOiAnICsgYWxnKTtcbiAgICB9XG4gIH1cblxuICBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgbGV0IGhhc2hBbGcgPSBuZXcgcnMuS0pVUi5jcnlwdG8uTWVzc2FnZURpZ2VzdCh7IGFsZzogYWxnb3JpdGhtIH0pO1xuICAgIGxldCByZXN1bHQgPSBoYXNoQWxnLmRpZ2VzdFN0cmluZyh2YWx1ZVRvSGFzaCk7XG4gICAgbGV0IGJ5dGVBcnJheUFzU3RyaW5nID0gdGhpcy50b0J5dGVBcnJheUFzU3RyaW5nKHJlc3VsdCk7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShieXRlQXJyYXlBc1N0cmluZyk7XG4gIH1cblxuICB0b0J5dGVBcnJheUFzU3RyaW5nKGhleFN0cmluZzogc3RyaW5nKSB7XG4gICAgbGV0IHJlc3VsdCA9ICcnO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgaGV4U3RyaW5nLmxlbmd0aDsgaSArPSAyKSB7XG4gICAgICBsZXQgaGV4RGlnaXQgPSBoZXhTdHJpbmcuY2hhckF0KGkpICsgaGV4U3RyaW5nLmNoYXJBdChpICsgMSk7XG4gICAgICBsZXQgbnVtID0gcGFyc2VJbnQoaGV4RGlnaXQsIDE2KTtcbiAgICAgIHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKG51bSk7XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cbn0iXX0=