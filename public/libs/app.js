'use strict';

this.$$ = {
    /**
     * Overrides an `object` with another one.
     * @param {Object} parent
     * @param {Object} child
     * @return {Object} combined
     */
    Extend: Object.assign,

    // Fetch's Default Options
    _fetchOptions: {},

    /**
     * Sets (and sanitizes) the default `Fetch` options.
     * @param {Object} options
     */
    SetDefaultFetchOptions: function(options) {
        if (!options) return;
        if (options.headers) options.headers = new Map(options.headers);
        $$._fetchOptions = options;
    },

    /**
     * Sets (and sanitizes) the default `Fetch` options.
     * @param {Object} options
     */
    OverrideDefaultFetchOptions: function(options) {
        return $$.Extend({}, $$._fetchOptions, options);
    },

    /**
     * Builds a `XMLHttpRequest` using `options` or the default fetch options previously set using `SetDefaultFetchOption`.
     * @param {String} uri
     * @param {Object} options
     * @return {XMLHttpRequest} xhr
     */
    Fetch: function(uri, options) {
        if (!options) options = $$._fetchOptions;
        if (!options.method) options.method = !options.data ? 'GET' : 'POST';
        var xhr = new XMLHttpRequest();
        if (options.onSuccess || options.onFailure || options.onComplete) {
            xhr.onreadystatechange = function() {
                if (xhr.readyState !== 4) return;
                if (xhr.status === 200) {
                    if (options.onSuccess) options.onSuccess(xhr, uri, options);
                } else if (options.onFailure) {
                    options.onFailure(xhr, uri, options);
                }
                if (options.onComplete) options.onComplete(xhr, uri, options);
            };
        }
        xhr.open(options.method, uri);
        if (options.headers) {
            options.headers.forEach(function(value, key) {
                xhr.setRequestHeader(key, value);
            });
        }
        if (options.data) {
            xhr.send(JSON.stringify(options.data));
        } else {
            xhr.send();
        }
        return xhr;
    }
};