/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
var UrlHelperService = /** @class */ (function () {
    function UrlHelperService() {
    }
    /**
     * @param {?=} customHashFragment
     * @return {?}
     */
    UrlHelperService.prototype.getHashFragmentParams = /**
     * @param {?=} customHashFragment
     * @return {?}
     */
    function (customHashFragment) {
        /** @type {?} */
        var hash = customHashFragment || window.location.hash;
        hash = decodeURIComponent(hash);
        if (hash.indexOf('#') !== 0) {
            return {};
        }
        /** @type {?} */
        var questionMarkPosition = hash.indexOf('?');
        if (questionMarkPosition > -1) {
            hash = hash.substr(questionMarkPosition + 1);
        }
        else {
            hash = hash.substr(1);
        }
        return this.parseQueryString(hash);
    };
    /**
     * @param {?} queryString
     * @return {?}
     */
    UrlHelperService.prototype.parseQueryString = /**
     * @param {?} queryString
     * @return {?}
     */
    function (queryString) {
        /** @type {?} */
        var data = {};
        /** @type {?} */
        var pairs;
        /** @type {?} */
        var pair;
        /** @type {?} */
        var separatorIndex;
        /** @type {?} */
        var escapedKey;
        /** @type {?} */
        var escapedValue;
        /** @type {?} */
        var key;
        /** @type {?} */
        var value;
        if (queryString === null) {
            return data;
        }
        pairs = queryString.split('&');
        for (var i = 0; i < pairs.length; i++) {
            pair = pairs[i];
            separatorIndex = pair.indexOf('=');
            if (separatorIndex === -1) {
                escapedKey = pair;
                escapedValue = null;
            }
            else {
                escapedKey = pair.substr(0, separatorIndex);
                escapedValue = pair.substr(separatorIndex + 1);
            }
            key = decodeURIComponent(escapedKey);
            value = decodeURIComponent(escapedValue);
            if (key.substr(0, 1) === '/') {
                key = key.substr(1);
            }
            data[key] = value;
        }
        return data;
    };
    UrlHelperService.decorators = [
        { type: Injectable }
    ];
    return UrlHelperService;
}());
export { UrlHelperService };
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXJsLWhlbHBlci5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInVybC1oZWxwZXIuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUUzQztJQUFBO0lBNkRBLENBQUM7Ozs7O0lBM0RRLGdEQUFxQjs7OztJQUE1QixVQUE2QixrQkFBMkI7O1lBQ2xELElBQUksR0FBRyxrQkFBa0IsSUFBSSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUk7UUFFckQsSUFBSSxHQUFHLGtCQUFrQixDQUFDLElBQUksQ0FBQyxDQUFDO1FBRWhDLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDM0IsT0FBTyxFQUFFLENBQUM7U0FDWDs7WUFFSyxvQkFBb0IsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQztRQUU5QyxJQUFJLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxFQUFFO1lBQzdCLElBQUksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxDQUFDO1NBQzlDO2FBQU07WUFDTCxJQUFJLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztTQUN2QjtRQUVELE9BQU8sSUFBSSxDQUFDLGdCQUFnQixDQUFDLElBQUksQ0FBQyxDQUFDO0lBQ3JDLENBQUM7Ozs7O0lBRU0sMkNBQWdCOzs7O0lBQXZCLFVBQXdCLFdBQW1COztZQUNuQyxJQUFJLEdBQUcsRUFBRTs7WUFFYixLQUFLOztZQUNMLElBQUk7O1lBQ0osY0FBYzs7WUFDZCxVQUFVOztZQUNWLFlBQVk7O1lBQ1osR0FBRzs7WUFDSCxLQUFLO1FBRVAsSUFBSSxXQUFXLEtBQUssSUFBSSxFQUFFO1lBQ3hCLE9BQU8sSUFBSSxDQUFDO1NBQ2I7UUFFRCxLQUFLLEdBQUcsV0FBVyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQztRQUUvQixLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsS0FBSyxDQUFDLE1BQU0sRUFBRSxDQUFDLEVBQUUsRUFBRTtZQUNyQyxJQUFJLEdBQUcsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ2hCLGNBQWMsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBRW5DLElBQUksY0FBYyxLQUFLLENBQUMsQ0FBQyxFQUFFO2dCQUN6QixVQUFVLEdBQUcsSUFBSSxDQUFDO2dCQUNsQixZQUFZLEdBQUcsSUFBSSxDQUFDO2FBQ3JCO2lCQUFNO2dCQUNMLFVBQVUsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsRUFBRSxjQUFjLENBQUMsQ0FBQztnQkFDNUMsWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsY0FBYyxHQUFHLENBQUMsQ0FBQyxDQUFDO2FBQ2hEO1lBRUQsR0FBRyxHQUFHLGtCQUFrQixDQUFDLFVBQVUsQ0FBQyxDQUFDO1lBQ3JDLEtBQUssR0FBRyxrQkFBa0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztZQUV6QyxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxLQUFLLEdBQUcsRUFBRTtnQkFBRSxHQUFHLEdBQUcsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQzthQUFFO1lBRXRELElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxLQUFLLENBQUM7U0FDbkI7UUFFRCxPQUFPLElBQUksQ0FBQztJQUNkLENBQUM7O2dCQTVERixVQUFVOztJQTZEWCx1QkFBQztDQUFBLEFBN0RELElBNkRDO1NBNURZLGdCQUFnQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcblxuQEluamVjdGFibGUoKVxuZXhwb3J0IGNsYXNzIFVybEhlbHBlclNlcnZpY2Uge1xuICBwdWJsaWMgZ2V0SGFzaEZyYWdtZW50UGFyYW1zKGN1c3RvbUhhc2hGcmFnbWVudD86IHN0cmluZyk6IG9iamVjdCB7XG4gICAgbGV0IGhhc2ggPSBjdXN0b21IYXNoRnJhZ21lbnQgfHwgd2luZG93LmxvY2F0aW9uLmhhc2g7XG5cbiAgICBoYXNoID0gZGVjb2RlVVJJQ29tcG9uZW50KGhhc2gpO1xuXG4gICAgaWYgKGhhc2guaW5kZXhPZignIycpICE9PSAwKSB7XG4gICAgICByZXR1cm4ge307XG4gICAgfVxuXG4gICAgY29uc3QgcXVlc3Rpb25NYXJrUG9zaXRpb24gPSBoYXNoLmluZGV4T2YoJz8nKTtcblxuICAgIGlmIChxdWVzdGlvbk1hcmtQb3NpdGlvbiA+IC0xKSB7XG4gICAgICBoYXNoID0gaGFzaC5zdWJzdHIocXVlc3Rpb25NYXJrUG9zaXRpb24gKyAxKTtcbiAgICB9IGVsc2Uge1xuICAgICAgaGFzaCA9IGhhc2guc3Vic3RyKDEpO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnBhcnNlUXVlcnlTdHJpbmcoaGFzaCk7XG4gIH1cblxuICBwdWJsaWMgcGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcbiAgICBjb25zdCBkYXRhID0ge307XG4gICAgbGV0XG4gICAgICBwYWlycyxcbiAgICAgIHBhaXIsXG4gICAgICBzZXBhcmF0b3JJbmRleCxcbiAgICAgIGVzY2FwZWRLZXksXG4gICAgICBlc2NhcGVkVmFsdWUsXG4gICAgICBrZXksXG4gICAgICB2YWx1ZTtcblxuICAgIGlmIChxdWVyeVN0cmluZyA9PT0gbnVsbCkge1xuICAgICAgcmV0dXJuIGRhdGE7XG4gICAgfVxuXG4gICAgcGFpcnMgPSBxdWVyeVN0cmluZy5zcGxpdCgnJicpO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBwYWlycy5sZW5ndGg7IGkrKykge1xuICAgICAgcGFpciA9IHBhaXJzW2ldO1xuICAgICAgc2VwYXJhdG9ySW5kZXggPSBwYWlyLmluZGV4T2YoJz0nKTtcblxuICAgICAgaWYgKHNlcGFyYXRvckluZGV4ID09PSAtMSkge1xuICAgICAgICBlc2NhcGVkS2V5ID0gcGFpcjtcbiAgICAgICAgZXNjYXBlZFZhbHVlID0gbnVsbDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGVzY2FwZWRLZXkgPSBwYWlyLnN1YnN0cigwLCBzZXBhcmF0b3JJbmRleCk7XG4gICAgICAgIGVzY2FwZWRWYWx1ZSA9IHBhaXIuc3Vic3RyKHNlcGFyYXRvckluZGV4ICsgMSk7XG4gICAgICB9XG5cbiAgICAgIGtleSA9IGRlY29kZVVSSUNvbXBvbmVudChlc2NhcGVkS2V5KTtcbiAgICAgIHZhbHVlID0gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZWRWYWx1ZSk7XG5cbiAgICAgIGlmIChrZXkuc3Vic3RyKDAsIDEpID09PSAnLycpIHsga2V5ID0ga2V5LnN1YnN0cigxKTsgfVxuXG4gICAgICBkYXRhW2tleV0gPSB2YWx1ZTtcbiAgICB9XG5cbiAgICByZXR1cm4gZGF0YTtcbiAgfVxufVxuIl19