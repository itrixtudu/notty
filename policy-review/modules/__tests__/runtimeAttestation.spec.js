import { describe, expect, it } from 'vitest';

import {
    fetchPolicyReviewRuntimeAttestation,
    normalizeManagedReviewGraphUrl,
    parsePolicyReviewRuntimeAttestation,
} from '../policy-review/runtimeAttestation';

describe('Policy Review runtime attestation', () => {
    it('accepts distinct Docker bridge origins in each RFC1918 range', () => {
        for (const prefix of ['10.0.0', '10.255.255', '172.16.0', '172.24.0',
            '172.31.255', '192.168.16', '192.168.255']) {
            const document = {
                schemaVersion: 1,
                uiOrigin: `http://${prefix}.2:3000`,
                graphOrigin: `http://${prefix}.3:43117`,
            };
            expect(parsePolicyReviewRuntimeAttestation(document)).toEqual(document);
            const graph = `${document.graphOrigin}/v1/graph/${'c'.repeat(64)}`;
            expect(normalizeManagedReviewGraphUrl(graph, {
                attestedGraphOrigin: document.graphOrigin,
            })).toBe(graph);
            expect(() => normalizeManagedReviewGraphUrl(graph)).toThrow('requires launcher');
            expect(() => normalizeManagedReviewGraphUrl(graph, {
                attestedGraphOrigin: `http://${prefix}.4:43117`,
            })).toThrow('does not match');
        }
    });

    it('rejects public, loopback, same-container, and expanded documents', () => {
        for (const document of [
            {
                schemaVersion: 1,
                uiOrigin: 'http://172.24.0.2:3000',
                graphOrigin: 'http://example.test:43117',
            },
            {
                schemaVersion: 1,
                uiOrigin: 'http://172.24.0.2:3000',
                graphOrigin: 'http://192.169.0.3:43117',
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

    it('rejects addresses outside RFC1918 and malformed IPv4', () => {
        for (const address of ['9.255.255.254', '11.0.0.2', '172.15.255.254',
            '172.32.0.2', '192.167.255.254', '192.169.0.2', '169.254.1.2',
            '100.64.0.2', '10.1.2.256']) {
            expect(() => parsePolicyReviewRuntimeAttestation({
                schemaVersion: 1,
                uiOrigin: 'http://192.168.16.2:3000',
                graphOrigin: `http://${address}:43117`,
            })).toThrow();
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
