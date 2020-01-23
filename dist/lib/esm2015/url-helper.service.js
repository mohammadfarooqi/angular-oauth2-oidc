/**
 * @fileoverview added by tsickle
 * @suppress {checkTypes,extraRequire,missingOverride,missingReturn,unusedPrivateMembers,uselessCode} checked by tsc
 */
import { Injectable } from '@angular/core';
export class UrlHelperService {
    /**
     * @param {?=} customHashFragment
     * @return {?}
     */
    getHashFragmentParams(customHashFragment) {
        /** @type {?} */
        let hash = customHashFragment || window.location.hash;
        hash = decodeURIComponent(hash);
        if (hash.indexOf('#') !== 0) {
            return {};
        }
        /** @type {?} */
        const questionMarkPosition = hash.indexOf('?');
        if (questionMarkPosition > -1) {
            hash = hash.substr(questionMarkPosition + 1);
        }
        else {
            hash = hash.substr(1);
        }
        return this.parseQueryString(hash);
    }
    /**
     * @param {?} queryString
     * @return {?}
     */
    parseQueryString(queryString) {
        /** @type {?} */
        const data = {};
        /** @type {?} */
        let pairs;
        /** @type {?} */
        let pair;
        /** @type {?} */
        let separatorIndex;
        /** @type {?} */
        let escapedKey;
        /** @type {?} */
        let escapedValue;
        /** @type {?} */
        let key;
        /** @type {?} */
        let value;
        if (queryString === null) {
            return data;
        }
        pairs = queryString.split('&');
        for (let i = 0; i < pairs.length; i++) {
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
    }
}
UrlHelperService.decorators = [
    { type: Injectable }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXJsLWhlbHBlci5zZXJ2aWNlLmpzIiwic291cmNlUm9vdCI6Im5nOi8vYW5ndWxhci1vYXV0aDItb2lkYy8iLCJzb3VyY2VzIjpbInVybC1oZWxwZXIuc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7O0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUczQyxNQUFNLE9BQU8sZ0JBQWdCOzs7OztJQUNwQixxQkFBcUIsQ0FBQyxrQkFBMkI7O1lBQ2xELElBQUksR0FBRyxrQkFBa0IsSUFBSSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUk7UUFFckQsSUFBSSxHQUFHLGtCQUFrQixDQUFDLElBQUksQ0FBQyxDQUFDO1FBRWhDLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLEVBQUU7WUFDM0IsT0FBTyxFQUFFLENBQUM7U0FDWDs7Y0FFSyxvQkFBb0IsR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQztRQUU5QyxJQUFJLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxFQUFFO1lBQzdCLElBQUksR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLG9CQUFvQixHQUFHLENBQUMsQ0FBQyxDQUFDO1NBQzlDO2FBQU07WUFDTCxJQUFJLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztTQUN2QjtRQUVELE9BQU8sSUFBSSxDQUFDLGdCQUFnQixDQUFDLElBQUksQ0FBQyxDQUFDO0lBQ3JDLENBQUM7Ozs7O0lBRU0sZ0JBQWdCLENBQUMsV0FBbUI7O2NBQ25DLElBQUksR0FBRyxFQUFFOztZQUViLEtBQUs7O1lBQ0wsSUFBSTs7WUFDSixjQUFjOztZQUNkLFVBQVU7O1lBQ1YsWUFBWTs7WUFDWixHQUFHOztZQUNILEtBQUs7UUFFUCxJQUFJLFdBQVcsS0FBSyxJQUFJLEVBQUU7WUFDeEIsT0FBTyxJQUFJLENBQUM7U0FDYjtRQUVELEtBQUssR0FBRyxXQUFXLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBRS9CLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxLQUFLLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRSxFQUFFO1lBQ3JDLElBQUksR0FBRyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDaEIsY0FBYyxHQUFHLElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUM7WUFFbkMsSUFBSSxjQUFjLEtBQUssQ0FBQyxDQUFDLEVBQUU7Z0JBQ3pCLFVBQVUsR0FBRyxJQUFJLENBQUM7Z0JBQ2xCLFlBQVksR0FBRyxJQUFJLENBQUM7YUFDckI7aUJBQU07Z0JBQ0wsVUFBVSxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxFQUFFLGNBQWMsQ0FBQyxDQUFDO2dCQUM1QyxZQUFZLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxjQUFjLEdBQUcsQ0FBQyxDQUFDLENBQUM7YUFDaEQ7WUFFRCxHQUFHLEdBQUcsa0JBQWtCLENBQUMsVUFBVSxDQUFDLENBQUM7WUFDckMsS0FBSyxHQUFHLGtCQUFrQixDQUFDLFlBQVksQ0FBQyxDQUFDO1lBRXpDLElBQUksR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLEtBQUssR0FBRyxFQUFFO2dCQUFFLEdBQUcsR0FBRyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO2FBQUU7WUFFdEQsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLEtBQUssQ0FBQztTQUNuQjtRQUVELE9BQU8sSUFBSSxDQUFDO0lBQ2QsQ0FBQzs7O1lBNURGLFVBQVUiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBJbmplY3RhYmxlIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBVcmxIZWxwZXJTZXJ2aWNlIHtcbiAgcHVibGljIGdldEhhc2hGcmFnbWVudFBhcmFtcyhjdXN0b21IYXNoRnJhZ21lbnQ/OiBzdHJpbmcpOiBvYmplY3Qge1xuICAgIGxldCBoYXNoID0gY3VzdG9tSGFzaEZyYWdtZW50IHx8IHdpbmRvdy5sb2NhdGlvbi5oYXNoO1xuXG4gICAgaGFzaCA9IGRlY29kZVVSSUNvbXBvbmVudChoYXNoKTtcblxuICAgIGlmIChoYXNoLmluZGV4T2YoJyMnKSAhPT0gMCkge1xuICAgICAgcmV0dXJuIHt9O1xuICAgIH1cblxuICAgIGNvbnN0IHF1ZXN0aW9uTWFya1Bvc2l0aW9uID0gaGFzaC5pbmRleE9mKCc/Jyk7XG5cbiAgICBpZiAocXVlc3Rpb25NYXJrUG9zaXRpb24gPiAtMSkge1xuICAgICAgaGFzaCA9IGhhc2guc3Vic3RyKHF1ZXN0aW9uTWFya1Bvc2l0aW9uICsgMSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGhhc2ggPSBoYXNoLnN1YnN0cigxKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5wYXJzZVF1ZXJ5U3RyaW5nKGhhc2gpO1xuICB9XG5cbiAgcHVibGljIHBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XG4gICAgY29uc3QgZGF0YSA9IHt9O1xuICAgIGxldFxuICAgICAgcGFpcnMsXG4gICAgICBwYWlyLFxuICAgICAgc2VwYXJhdG9ySW5kZXgsXG4gICAgICBlc2NhcGVkS2V5LFxuICAgICAgZXNjYXBlZFZhbHVlLFxuICAgICAga2V5LFxuICAgICAgdmFsdWU7XG5cbiAgICBpZiAocXVlcnlTdHJpbmcgPT09IG51bGwpIHtcbiAgICAgIHJldHVybiBkYXRhO1xuICAgIH1cblxuICAgIHBhaXJzID0gcXVlcnlTdHJpbmcuc3BsaXQoJyYnKTtcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgcGFpcnMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHBhaXIgPSBwYWlyc1tpXTtcbiAgICAgIHNlcGFyYXRvckluZGV4ID0gcGFpci5pbmRleE9mKCc9Jyk7XG5cbiAgICAgIGlmIChzZXBhcmF0b3JJbmRleCA9PT0gLTEpIHtcbiAgICAgICAgZXNjYXBlZEtleSA9IHBhaXI7XG4gICAgICAgIGVzY2FwZWRWYWx1ZSA9IG51bGw7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBlc2NhcGVkS2V5ID0gcGFpci5zdWJzdHIoMCwgc2VwYXJhdG9ySW5kZXgpO1xuICAgICAgICBlc2NhcGVkVmFsdWUgPSBwYWlyLnN1YnN0cihzZXBhcmF0b3JJbmRleCArIDEpO1xuICAgICAgfVxuXG4gICAgICBrZXkgPSBkZWNvZGVVUklDb21wb25lbnQoZXNjYXBlZEtleSk7XG4gICAgICB2YWx1ZSA9IGRlY29kZVVSSUNvbXBvbmVudChlc2NhcGVkVmFsdWUpO1xuXG4gICAgICBpZiAoa2V5LnN1YnN0cigwLCAxKSA9PT0gJy8nKSB7IGtleSA9IGtleS5zdWJzdHIoMSk7IH1cblxuICAgICAgZGF0YVtrZXldID0gdmFsdWU7XG4gICAgfVxuXG4gICAgcmV0dXJuIGRhdGE7XG4gIH1cbn1cbiJdfQ==