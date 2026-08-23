export const POLICY_REVIEW_ATTESTATION_ENDPOINT = '/api/policy-review-attestation';

const TOKENIZED_GRAPH_PATH = /^\/v1\/graph\/[a-f0-9]{64}$/;

const isPlainObject = value => (
    value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
);

const isDockerBridgeIpv4 = value => {
    const match = /^(172)\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/.exec(value);
    if (!match) return false;
    const octets = match.slice(1).map(Number);
    return octets[1] >= 16
        && octets[1] <= 31
        && octets.slice(2).every(octet => octet >= 0 && octet <= 255);
};

const parseUrl = (input, label) => {
    if (typeof input !== 'string' || !input || input.length > 8192) {
        throw new Error(`${label} must be a non-empty bounded URL`);
    }
    try {
        return new URL(input);
    } catch {
        throw new Error(`${label} must be an absolute URL`);
    }
};

export const normalizeDockerBridgeOrigin = (input, label = 'Docker bridge origin') => {
    const url = parseUrl(input, label);
    if (
        url.protocol !== 'http:'
        || !isDockerBridgeIpv4(url.hostname)
        || !url.port
        || url.username
        || url.password
        || url.pathname !== '/'
        || url.search
        || url.hash
    ) {
        throw new Error(`${label} must be an exact Docker bridge HTTP origin`);
    }
    return url.origin;
};

export const parsePolicyReviewRuntimeAttestation = input => {
    if (!isPlainObject(input)) {
        throw new Error('Policy Review runtime attestation must be a JSON object');
    }
    const keys = Object.keys(input).sort();
    if (
        keys.length !== 3
        || keys[0] !== 'graphOrigin'
        || keys[1] !== 'schemaVersion'
        || keys[2] !== 'uiOrigin'
        || input.schemaVersion !== 1
    ) {
        throw new Error('Policy Review runtime attestation has an invalid schema');
    }
    const uiOrigin = normalizeDockerBridgeOrigin(input.uiOrigin, 'Attested Policy Review UI origin');
    const graphOrigin = normalizeDockerBridgeOrigin(
        input.graphOrigin,
        'Attested Policy Review graph origin',
    );
    if (new URL(uiOrigin).hostname === new URL(graphOrigin).hostname) {
        throw new Error('Attested Policy Review services must use distinct container addresses');
    }
    return Object.freeze({ schemaVersion: 1, uiOrigin, graphOrigin });
};

export const parsePolicyReviewAttestationResponse = input => {
    if (!isPlainObject(input)) {
        throw new Error('Policy Review attestation response must be a JSON object');
    }
    const keys = Object.keys(input).sort();
    if (
        keys.length !== 2
        || keys[0] !== 'graphOrigin'
        || keys[1] !== 'schemaVersion'
        || input.schemaVersion !== 1
        || (input.graphOrigin !== null && typeof input.graphOrigin !== 'string')
    ) {
        throw new Error('Policy Review attestation response has an invalid schema');
    }
    return Object.freeze({
        schemaVersion: 1,
        graphOrigin: input.graphOrigin === null
            ? null
            : normalizeDockerBridgeOrigin(
                input.graphOrigin,
                'Attested Policy Review graph origin',
            ),
    });
};

export const normalizeManagedReviewGraphUrl = (
    input,
    { attestedGraphOrigin = null } = {},
) => {
    const invalidUrlMessage = 'Managed graph URL must be an exact tokenized loopback or attested Docker bridge URL';
    let url;
    try {
        url = parseUrl(input, 'Managed graph URL');
    } catch {
        throw new Error(invalidUrlMessage);
    }
    const loopback = url.hostname === '127.0.0.1';
    const bridge = isDockerBridgeIpv4(url.hostname);
    if (
        url.protocol !== 'http:'
        || (!loopback && !bridge)
        || !url.port
        || url.username
        || url.password
        || url.search
        || url.hash
        || !TOKENIZED_GRAPH_PATH.test(url.pathname)
    ) {
        throw new Error(invalidUrlMessage);
    }
    if (bridge) {
        if (attestedGraphOrigin === null) {
            throw new Error('Docker bridge graph URL requires launcher runtime attestation');
        }
        const allowedOrigin = normalizeDockerBridgeOrigin(
            attestedGraphOrigin,
            'Attested Policy Review graph origin',
        );
        if (url.origin !== allowedOrigin) {
            throw new Error('Docker bridge graph URL does not match launcher runtime attestation');
        }
    }
    return url.href;
};

export const fetchPolicyReviewRuntimeAttestation = async ({
    fetchImpl = globalThis.fetch,
} = {}) => {
    if (typeof fetchImpl !== 'function') {
        throw new Error('This browser does not provide fetch');
    }
    const response = await fetchImpl(POLICY_REVIEW_ATTESTATION_ENDPOINT, {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        headers: { Accept: 'application/json' },
    });
    if (!response?.ok) {
        throw new Error(
            response?.status === 503
                ? 'Policy Review launcher attestation is not ready'
                : `Policy Review launcher attestation returned HTTP ${response?.status || 'error'}`,
        );
    }
    if (typeof response.json !== 'function') {
        throw new Error('Policy Review launcher attestation response is not JSON');
    }
    return parsePolicyReviewAttestationResponse(await response.json());
};
