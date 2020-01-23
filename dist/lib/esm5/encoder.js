/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * This custom encoder allows charactes like +, % and / to be used in passwords
 */
var /**
 * This custom encoder allows charactes like +, % and / to be used in passwords
 */
WebHttpUrlEncodingCodec = /** @class */ (function () {
    function WebHttpUrlEncodingCodec() {
    }
    /**
     * @param {?} k
     * @return {?}
     */
    WebHttpUrlEncodingCodec.prototype.encodeKey = /**
     * @param {?} k
     * @return {?}
     */
    function (k) {
        return encodeURIComponent(k);
    };
    /**
     * @param {?} v
     * @return {?}
     */
    WebHttpUrlEncodingCodec.prototype.encodeValue = /**
     * @param {?} v
     * @return {?}
     */
    function (v) {
        return encodeURIComponent(v);
    };
    /**
     * @param {?} k
     * @return {?}
     */
    WebHttpUrlEncodingCodec.prototype.decodeKey = /**
     * @param {?} k
     * @return {?}
     */
    function (k) {
        return decodeURIComponent(k);
    };
    /**
     * @param {?} v
     * @return {?}
     */
    WebHttpUrlEncodingCodec.prototype.decodeValue = /**
     * @param {?} v
     * @return {?}
     */
    function (v) {
        return decodeURIComponent(v);
    };
    return WebHttpUrlEncodingCodec;
}());
/**
 * This custom encoder allows charactes like +, % and / to be used in passwords
 */
export { WebHttpUrlEncodingCodec };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZW5jb2Rlci5qcyIsInNvdXJjZVJvb3QiOiJuZzovL2FuZ3VsYXItb2F1dGgyLW9pZGMvIiwic291cmNlcyI6WyJlbmNvZGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFJQTs7OztJQUFBO0lBZ0JBLENBQUM7Ozs7O0lBZkMsMkNBQVM7Ozs7SUFBVCxVQUFVLENBQVM7UUFDakIsT0FBTyxrQkFBa0IsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMvQixDQUFDOzs7OztJQUVELDZDQUFXOzs7O0lBQVgsVUFBWSxDQUFTO1FBQ25CLE9BQU8sa0JBQWtCLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDL0IsQ0FBQzs7Ozs7SUFFRCwyQ0FBUzs7OztJQUFULFVBQVUsQ0FBUztRQUNqQixPQUFPLGtCQUFrQixDQUFDLENBQUMsQ0FBQyxDQUFDO0lBQy9CLENBQUM7Ozs7O0lBRUQsNkNBQVc7Ozs7SUFBWCxVQUFZLENBQVM7UUFDbkIsT0FBTyxrQkFBa0IsQ0FBQyxDQUFDLENBQUMsQ0FBQztJQUMvQixDQUFDO0lBQ0gsOEJBQUM7QUFBRCxDQUFDLEFBaEJELElBZ0JDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSHR0cFBhcmFtZXRlckNvZGVjIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuLyoqXG4gKiBUaGlzIGN1c3RvbSBlbmNvZGVyIGFsbG93cyBjaGFyYWN0ZXMgbGlrZSArLCAlIGFuZCAvIHRvIGJlIHVzZWQgaW4gcGFzc3dvcmRzXG4gKi9cbmV4cG9ydCBjbGFzcyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYyBpbXBsZW1lbnRzIEh0dHBQYXJhbWV0ZXJDb2RlYyB7XG4gIGVuY29kZUtleShrOiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQoayk7XG4gIH1cblxuICBlbmNvZGVWYWx1ZSh2OiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQodik7XG4gIH1cblxuICBkZWNvZGVLZXkoazogc3RyaW5nKTogc3RyaW5nIHtcbiAgICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KGspO1xuICB9XG5cbiAgZGVjb2RlVmFsdWUodjogc3RyaW5nKSB7XG4gICAgcmV0dXJuIGRlY29kZVVSSUNvbXBvbmVudCh2KTtcbiAgfVxufVxuIl19