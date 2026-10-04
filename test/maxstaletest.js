'use strict';

const assert = require('assert');
const CachePolicy = require('..');

// GHSA-ch52-4w7c-c8xp / CVE-2026-93748: a request's max-stale must not make
// a response reusable when the response itself forbids reuse without validation.

const request = {
    method: 'GET',
    headers: { host: 'www.w3c.org' },
    url: '/Protocols/rfc2616/rfc2616-sec14.html',
};

function requestWithMaxStale(value) {
    return Object.assign({}, request, { headers: Object.assign({}, request.headers, { 'cache-control': value }) });
}

function policyFor(responseHeaders, options) {
    return new CachePolicy(request, { status: 200, headers: Object.assign({ age: '100' }, responseHeaders) }, options);
}

function isHit(policy, req) {
    return !!policy.evaluateRequest(req).response;
}

describe('max-stale cannot override reuse restrictions', function() {
    for (const maxStale of ['max-stale', 'max-stale=1000000']) {
        const req = requestWithMaxStale(maxStale);

        it(`shared cache: Set-Cookie without public is not reused (${maxStale})`, function() {
            const policy = policyFor({ 'cache-control': 'max-age=60', 'set-cookie': 'session=abc' }, { shared: true });
            assert.strictEqual(isHit(policy, req), false);
        });

        it(`shared cache: no-cache is not reused (${maxStale})`, function() {
            const policy = policyFor({ 'cache-control': 'max-age=60, no-cache' }, { shared: true });
            assert.strictEqual(isHit(policy, req), false);
        });

        it(`shared cache: proxy-revalidate is not reused (${maxStale})`, function() {
            const policy = policyFor({ 'cache-control': 'max-age=60, proxy-revalidate' }, { shared: true });
            assert.strictEqual(isHit(policy, req), false);
        });

        it(`non-storable response is not reused (${maxStale})`, function() {
            const policy = policyFor({ 'cache-control': 'no-store' }, { shared: true });
            assert.strictEqual(isHit(policy, req), false);
        });

        it(`private cache: Set-Cookie response may still be served stale (${maxStale})`, function() {
            const policy = policyFor({ 'cache-control': 'max-age=60', 'set-cookie': 'session=abc' }, { shared: false });
            assert.strictEqual(isHit(policy, req), true);
        });

        it(`shared cache: ordinary stale response is still served (${maxStale})`, function() {
            const policy = policyFor({ 'cache-control': 'max-age=60' }, { shared: true });
            assert.strictEqual(isHit(policy, req), true);
        });
    }

    it('shared cache: public Set-Cookie response may be served stale', function() {
        const policy = policyFor({ 'cache-control': 'public, max-age=60', 'set-cookie': 'a=b' }, { shared: true });
        assert.strictEqual(isHit(policy, requestWithMaxStale('max-stale=1000000')), true);
    });
});
