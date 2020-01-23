/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * A validation handler that isn't validating nothing.
 * Can be used to skip validation (at your own risk).
 */
export class NullValidationHandler {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibnVsbC12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290Ijoibmc6Ly9hbmd1bGFyLW9hdXRoMi1vaWRjLyIsInNvdXJjZXMiOlsidG9rZW4tdmFsaWRhdGlvbi9udWxsLXZhbGlkYXRpb24taGFuZGxlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7OztBQU1BLE1BQU0sT0FBTyxxQkFBcUI7Ozs7O0lBQ2hDLGlCQUFpQixDQUFDLGdCQUFrQztRQUNsRCxPQUFPLE9BQU8sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLENBQUM7SUFDL0IsQ0FBQzs7Ozs7SUFDRCxjQUFjLENBQUMsZ0JBQWtDO1FBQy9DLE9BQU8sT0FBTyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUMvQixDQUFDO0NBQ0YiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBWYWxpZGF0aW9uSGFuZGxlciwgVmFsaWRhdGlvblBhcmFtcyB9IGZyb20gJy4vdmFsaWRhdGlvbi1oYW5kbGVyJztcblxuLyoqXG4gKiBBIHZhbGlkYXRpb24gaGFuZGxlciB0aGF0IGlzbid0IHZhbGlkYXRpbmcgbm90aGluZy5cbiAqIENhbiBiZSB1c2VkIHRvIHNraXAgdmFsaWRhdGlvbiAoYXQgeW91ciBvd24gcmlzaykuXG4gKi9cbmV4cG9ydCBjbGFzcyBOdWxsVmFsaWRhdGlvbkhhbmRsZXIgaW1wbGVtZW50cyBWYWxpZGF0aW9uSGFuZGxlciB7XG4gIHZhbGlkYXRlU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT4ge1xuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUobnVsbCk7XG4gIH1cbiAgdmFsaWRhdGVBdEhhc2godmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodHJ1ZSk7XG4gIH1cbn1cbiJdfQ==