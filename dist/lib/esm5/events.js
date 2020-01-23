/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import * as tslib_1 from "tslib";
/**
 * @abstract
 */
var /**
 * @abstract
 */
OAuthEvent = /** @class */ (function () {
    function OAuthEvent(type) {
        this.type = type;
    }
    return OAuthEvent;
}());
/**
 * @abstract
 */
export { OAuthEvent };
if (false) {
    /** @type {?} */
    OAuthEvent.prototype.type;
}
var OAuthSuccessEvent = /** @class */ (function (_super) {
    tslib_1.__extends(OAuthSuccessEvent, _super);
    function OAuthSuccessEvent(type, info) {
        if (info === void 0) { info = null; }
        var _this = _super.call(this, type) || this;
        _this.info = info;
        return _this;
    }
    return OAuthSuccessEvent;
}(OAuthEvent));
export { OAuthSuccessEvent };
if (false) {
    /** @type {?} */
    OAuthSuccessEvent.prototype.info;
}
var OAuthInfoEvent = /** @class */ (function (_super) {
    tslib_1.__extends(OAuthInfoEvent, _super);
    function OAuthInfoEvent(type, info) {
        if (info === void 0) { info = null; }
        var _this = _super.call(this, type) || this;
        _this.info = info;
        return _this;
    }
    return OAuthInfoEvent;
}(OAuthEvent));
export { OAuthInfoEvent };
if (false) {
    /** @type {?} */
    OAuthInfoEvent.prototype.info;
}
var OAuthErrorEvent = /** @class */ (function (_super) {
    tslib_1.__extends(OAuthErrorEvent, _super);
    function OAuthErrorEvent(type, reason, params) {
        if (params === void 0) { params = null; }
        var _this = _super.call(this, type) || this;
        _this.reason = reason;
        _this.params = params;
        return _this;
    }
    return OAuthErrorEvent;
}(OAuthEvent));
export { OAuthErrorEvent };
if (false) {
    /** @type {?} */
    OAuthErrorEvent.prototype.reason;
    /** @type {?} */
    OAuthErrorEvent.prototype.params;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXZlbnRzLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbImV2ZW50cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7OztBQXdCQTs7OztJQUNFLG9CQUFxQixJQUFlO1FBQWYsU0FBSSxHQUFKLElBQUksQ0FBVztJQUFHLENBQUM7SUFDMUMsaUJBQUM7QUFBRCxDQUFDLEFBRkQsSUFFQzs7Ozs7OztJQURhLDBCQUF3Qjs7QUFHdEM7SUFBdUMsNkNBQVU7SUFDL0MsMkJBQVksSUFBZSxFQUFXLElBQWdCO1FBQWhCLHFCQUFBLEVBQUEsV0FBZ0I7UUFBdEQsWUFDRSxrQkFBTSxJQUFJLENBQUMsU0FDWjtRQUZxQyxVQUFJLEdBQUosSUFBSSxDQUFZOztJQUV0RCxDQUFDO0lBQ0gsd0JBQUM7QUFBRCxDQUFDLEFBSkQsQ0FBdUMsVUFBVSxHQUloRDs7OztJQUg4QixpQ0FBeUI7O0FBS3hEO0lBQW9DLDBDQUFVO0lBQzVDLHdCQUFZLElBQWUsRUFBVyxJQUFnQjtRQUFoQixxQkFBQSxFQUFBLFdBQWdCO1FBQXRELFlBQ0Usa0JBQU0sSUFBSSxDQUFDLFNBQ1o7UUFGcUMsVUFBSSxHQUFKLElBQUksQ0FBWTs7SUFFdEQsQ0FBQztJQUNILHFCQUFDO0FBQUQsQ0FBQyxBQUpELENBQW9DLFVBQVUsR0FJN0M7Ozs7SUFIOEIsOEJBQXlCOztBQUt4RDtJQUFxQywyQ0FBVTtJQUM3Qyx5QkFDRSxJQUFlLEVBQ04sTUFBYyxFQUNkLE1BQXFCO1FBQXJCLHVCQUFBLEVBQUEsYUFBcUI7UUFIaEMsWUFLRSxrQkFBTSxJQUFJLENBQUMsU0FDWjtRQUpVLFlBQU0sR0FBTixNQUFNLENBQVE7UUFDZCxZQUFNLEdBQU4sTUFBTSxDQUFlOztJQUdoQyxDQUFDO0lBQ0gsc0JBQUM7QUFBRCxDQUFDLEFBUkQsQ0FBcUMsVUFBVSxHQVE5Qzs7OztJQUxHLGlDQUF1Qjs7SUFDdkIsaUNBQThCIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IHR5cGUgRXZlbnRUeXBlID1cbiAgfCAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCdcbiAgfCAncmVjZWl2ZWRfZmlyc3RfdG9rZW4nXG4gIHwgJ2p3a3NfbG9hZF9lcnJvcidcbiAgfCAnaW52YWxpZF9ub25jZV9pbl9zdGF0ZSdcbiAgfCAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRfZXJyb3InXG4gIHwgJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJ1xuICB8ICd1c2VyX3Byb2ZpbGVfbG9hZGVkJ1xuICB8ICd1c2VyX3Byb2ZpbGVfbG9hZF9lcnJvcidcbiAgfCAndG9rZW5fcmVjZWl2ZWQnXG4gIHwgJ3Rva2VuX2Vycm9yJ1xuICB8ICdjb2RlX2Vycm9yJ1xuICB8ICd0b2tlbl9yZWZyZXNoZWQnXG4gIHwgJ3Rva2VuX3JlZnJlc2hfZXJyb3InXG4gIHwgJ3NpbGVudF9yZWZyZXNoX2Vycm9yJ1xuICB8ICdzaWxlbnRseV9yZWZyZXNoZWQnXG4gIHwgJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnXG4gIHwgJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InXG4gIHwgJ3Rva2VuX2V4cGlyZXMnXG4gIHwgJ3Nlc3Npb25fY2hhbmdlZCdcbiAgfCAnc2Vzc2lvbl9lcnJvcidcbiAgfCAnc2Vzc2lvbl90ZXJtaW5hdGVkJ1xuICB8ICdsb2dvdXQnO1xuXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgT0F1dGhFdmVudCB7XG4gIGNvbnN0cnVjdG9yKHJlYWRvbmx5IHR5cGU6IEV2ZW50VHlwZSkge31cbn1cblxuZXhwb3J0IGNsYXNzIE9BdXRoU3VjY2Vzc0V2ZW50IGV4dGVuZHMgT0F1dGhFdmVudCB7XG4gIGNvbnN0cnVjdG9yKHR5cGU6IEV2ZW50VHlwZSwgcmVhZG9ubHkgaW5mbzogYW55ID0gbnVsbCkge1xuICAgIHN1cGVyKHR5cGUpO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBPQXV0aEluZm9FdmVudCBleHRlbmRzIE9BdXRoRXZlbnQge1xuICBjb25zdHJ1Y3Rvcih0eXBlOiBFdmVudFR5cGUsIHJlYWRvbmx5IGluZm86IGFueSA9IG51bGwpIHtcbiAgICBzdXBlcih0eXBlKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgT0F1dGhFcnJvckV2ZW50IGV4dGVuZHMgT0F1dGhFdmVudCB7XG4gIGNvbnN0cnVjdG9yKFxuICAgIHR5cGU6IEV2ZW50VHlwZSxcbiAgICByZWFkb25seSByZWFzb246IG9iamVjdCxcbiAgICByZWFkb25seSBwYXJhbXM6IG9iamVjdCA9IG51bGxcbiAgKSB7XG4gICAgc3VwZXIodHlwZSk7XG4gIH1cbn1cbiJdfQ==