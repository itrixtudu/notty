import { describe, expect, it } from 'vitest';

import {
    fetchPolicyReviewRuntimeAttestation,
    normalizeManagedReviewGraphUrl,
    parsePolicyReviewRuntimeAttestation,
} from '../policy-review/runtimeAttestation';

describe('Policy Review runtime attestation', () => {
    it('accepts one strict pair of distinct Docker bridge origins', () => {
        expect(parsePolicyReviewRuntimeAttestation({
            schemaVersion: 1,
            uiOrigin: 'http://172.24.0.2:3000',
            graphOrigin: 'http://172.24.0.3:43117',
        })).toEqual({
            schemaVersion: 1,
            uiOrigin: 'http://172.24.0.2:3000',
            graphOrigin: 'http://172.24.0.3:43117',
        });
    });

    it('rejects public, unrelated private, loopback, same-container, and expanded documents', () => {
        for (const document of [
            {
                schemaVersion: 1,
                uiOrigin: 'http://172.24.0.2:3000',
                graphOrigin: 'http://example.test:43117',
            },
            {
                schemaVersion: 1,
                uiOrigin: 'http://172.24.0.2:3000',
                graphOrigin: 'http://10.0.0.3:43117',
            },
            {
                schemaVersion: 1,
                uiOrigin: 'http://127.0.0.1:3000',
                graphOrigin: 'http://172.24.0.3:43117',
            },
            {
                schemaVersion: 1,
                uiOrigin: 'http://172.24.0.2:3000',
                graphOrigin: 'http://172.24.0.2:43117',
            },
            {
                schemaVersion: 1,
                uiOrigin: 'http://172.24.0.2:3000',
                graphOrigin: 'http://172.24.0.3:43117',
                extra: true,
            },
        ]) {
            expect(() => parsePolicyReviewRuntimeAttestation(document)).toThrow();
        }
    });

    it('normalizes only loopback diagnostics or the exact attested graph origin', () => {
        const token = 'c'.repeat(64);
        const loopback = `http://127.0.0.1:8765/v1/graph/${token}`;
        const graph = `http://172.24.0.3:43117/v1/graph/${token}`;
        expect(normalizeManagedReviewGraphUrl(loopback)).toBe(loopback);
        expect(normalizeManagedReviewGraphUrl(graph, {
            attestedGraphOrigin: 'http://172.24.0.3:43117',
        })).toBe(graph);
        expect(() => normalizeManagedReviewGraphUrl(graph)).toThrow('requires launcher');
        for (const rejected of [
            `http://172.24.0.4:43117/v1/graph/${token}`,
            `http://192.168.1.4:43117/v1/graph/${token}`,
            `https://172.24.0.3:43117/v1/graph/${token}`,
            `http://172.24.0.3:43117/v1/graph/${token}?copy=1`,
            `http://172.24.0.3:43117/v1/graph/${'C'.repeat(64)}`,
        ]) {
            expect(() => normalizeManagedReviewGraphUrl(rejected, {
                attestedGraphOrigin: 'http://172.24.0.3:43117',
            })).toThrow();
        }
    });

    it('fetches runtime policy with same-origin credentials disabled from caches', async () => {
        let request;
        const result = await fetchPolicyReviewRuntimeAttestation({
            fetchImpl: async (url, options) => {
                request = { url, options };
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        schemaVersion: 1,
                        graphOrigin: 'http://172.24.0.3:43117',
                    }),
                };
            },
        });
        expect(result.graphOrigin).toBe('http://172.24.0.3:43117');
        expect(request).toEqual({
            url: '/api/policy-review-attestation',
            options: {
                method: 'GET',
                credentials: 'same-origin',
                cache: 'no-store',
                redirect: 'error',
                referrerPolicy: 'no-referrer',
                headers: { Accept: 'application/json' },
            },
        });
    });
});
