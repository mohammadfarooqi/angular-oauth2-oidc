/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
/**
 * @abstract
 */
export class OAuthEvent {
    /**
     * @param {?} type
     */
    constructor(type) {
        this.type = type;
    }
}
if (false) {
    /** @type {?} */
    OAuthEvent.prototype.type;
}
export class OAuthSuccessEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?=} info
     */
    constructor(type, info = null) {
        super(type);
        this.info = info;
    }
}
if (false) {
    /** @type {?} */
    OAuthSuccessEvent.prototype.info;
}
export class OAuthInfoEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?=} info
     */
    constructor(type, info = null) {
        super(type);
        this.info = info;
    }
}
if (false) {
    /** @type {?} */
    OAuthInfoEvent.prototype.info;
}
export class OAuthErrorEvent extends OAuthEvent {
    /**
     * @param {?} type
     * @param {?} reason
     * @param {?=} params
     */
    constructor(type, reason, params = null) {
        super(type);
        this.reason = reason;
        this.params = params;
    }
}
if (false) {
    /** @type {?} */
    OAuthErrorEvent.prototype.reason;
    /** @type {?} */
    OAuthErrorEvent.prototype.params;
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZXZlbnRzLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbImV2ZW50cy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBd0JBLE1BQU0sT0FBZ0IsVUFBVTs7OztJQUM5QixZQUFxQixJQUFlO1FBQWYsU0FBSSxHQUFKLElBQUksQ0FBVztJQUFHLENBQUM7Q0FDekM7OztJQURhLDBCQUF3Qjs7QUFHdEMsTUFBTSxPQUFPLGlCQUFrQixTQUFRLFVBQVU7Ozs7O0lBQy9DLFlBQVksSUFBZSxFQUFXLE9BQVksSUFBSTtRQUNwRCxLQUFLLENBQUMsSUFBSSxDQUFDLENBQUM7UUFEd0IsU0FBSSxHQUFKLElBQUksQ0FBWTtJQUV0RCxDQUFDO0NBQ0Y7OztJQUg4QixpQ0FBeUI7O0FBS3hELE1BQU0sT0FBTyxjQUFlLFNBQVEsVUFBVTs7Ozs7SUFDNUMsWUFBWSxJQUFlLEVBQVcsT0FBWSxJQUFJO1FBQ3BELEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUR3QixTQUFJLEdBQUosSUFBSSxDQUFZO0lBRXRELENBQUM7Q0FDRjs7O0lBSDhCLDhCQUF5Qjs7QUFLeEQsTUFBTSxPQUFPLGVBQWdCLFNBQVEsVUFBVTs7Ozs7O0lBQzdDLFlBQ0UsSUFBZSxFQUNOLE1BQWMsRUFDZCxTQUFpQixJQUFJO1FBRTlCLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUhILFdBQU0sR0FBTixNQUFNLENBQVE7UUFDZCxXQUFNLEdBQU4sTUFBTSxDQUFlO0lBR2hDLENBQUM7Q0FDRjs7O0lBTEcsaUNBQXVCOztJQUN2QixpQ0FBOEIiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgdHlwZSBFdmVudFR5cGUgPVxuICB8ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJ1xuICB8ICdyZWNlaXZlZF9maXJzdF90b2tlbidcbiAgfCAnandrc19sb2FkX2Vycm9yJ1xuICB8ICdpbnZhbGlkX25vbmNlX2luX3N0YXRlJ1xuICB8ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcidcbiAgfCAnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InXG4gIHwgJ3VzZXJfcHJvZmlsZV9sb2FkZWQnXG4gIHwgJ3VzZXJfcHJvZmlsZV9sb2FkX2Vycm9yJ1xuICB8ICd0b2tlbl9yZWNlaXZlZCdcbiAgfCAndG9rZW5fZXJyb3InXG4gIHwgJ2NvZGVfZXJyb3InXG4gIHwgJ3Rva2VuX3JlZnJlc2hlZCdcbiAgfCAndG9rZW5fcmVmcmVzaF9lcnJvcidcbiAgfCAnc2lsZW50X3JlZnJlc2hfZXJyb3InXG4gIHwgJ3NpbGVudGx5X3JlZnJlc2hlZCdcbiAgfCAnc2lsZW50X3JlZnJlc2hfdGltZW91dCdcbiAgfCAndG9rZW5fdmFsaWRhdGlvbl9lcnJvcidcbiAgfCAndG9rZW5fZXhwaXJlcydcbiAgfCAnc2Vzc2lvbl9jaGFuZ2VkJ1xuICB8ICdzZXNzaW9uX2Vycm9yJ1xuICB8ICdzZXNzaW9uX3Rlcm1pbmF0ZWQnXG4gIHwgJ2xvZ291dCc7XG5cbmV4cG9ydCBhYnN0cmFjdCBjbGFzcyBPQXV0aEV2ZW50IHtcbiAgY29uc3RydWN0b3IocmVhZG9ubHkgdHlwZTogRXZlbnRUeXBlKSB7fVxufVxuXG5leHBvcnQgY2xhc3MgT0F1dGhTdWNjZXNzRXZlbnQgZXh0ZW5kcyBPQXV0aEV2ZW50IHtcbiAgY29uc3RydWN0b3IodHlwZTogRXZlbnRUeXBlLCByZWFkb25seSBpbmZvOiBhbnkgPSBudWxsKSB7XG4gICAgc3VwZXIodHlwZSk7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIE9BdXRoSW5mb0V2ZW50IGV4dGVuZHMgT0F1dGhFdmVudCB7XG4gIGNvbnN0cnVjdG9yKHR5cGU6IEV2ZW50VHlwZSwgcmVhZG9ubHkgaW5mbzogYW55ID0gbnVsbCkge1xuICAgIHN1cGVyKHR5cGUpO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBPQXV0aEVycm9yRXZlbnQgZXh0ZW5kcyBPQXV0aEV2ZW50IHtcbiAgY29uc3RydWN0b3IoXG4gICAgdHlwZTogRXZlbnRUeXBlLFxuICAgIHJlYWRvbmx5IHJlYXNvbjogb2JqZWN0LFxuICAgIHJlYWRvbmx5IHBhcmFtczogb2JqZWN0ID0gbnVsbFxuICApIHtcbiAgICBzdXBlcih0eXBlKTtcbiAgfVxufVxuIl19