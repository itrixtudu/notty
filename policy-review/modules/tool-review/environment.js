export const LIMITATIONS = Object.freeze(['individual-tools-not-enforced', 'unknown-commands-not-universally-blocked',
    'workspace-writes-not-tool-specific', 'network-policy-independent', 'remote-effects-not-filesystem-controlled']);

export function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
    if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
    return JSON.stringify(value);
}

export function validateEnvironment(value, snapshot, proposalDigest) {
    const keys = ['kind', 'schemaVersion', 'snapshotDigest', 'proposalDigest', 'workspace', 'workload', 'allowImplementation',
        'defaultMode', 'policyReadOnly', 'toolSelectionsInformational', 'limitations', 'reviewer', 'acknowledged', 'approvedAt'];
    if (!value || Object.keys(value).sort().join() !== keys.sort().join()
        || value.kind !== 'NoshEnvironmentPolicy' || value.schemaVersion !== 1
        || value.snapshotDigest !== snapshot.digest || value.proposalDigest !== proposalDigest
        || !snapshot.complete || value.workload !== 'dev' || value.defaultMode !== 'read-only'
        || value.policyReadOnly !== true || value.toolSelectionsInformational !== true || value.acknowledged !== true
        || typeof value.allowImplementation !== 'boolean' || typeof value.workspace !== 'string'
        || !value.workspace.startsWith('/') || /[:,\r\n\0]/.test(value.workspace)
        || value.workspace.split('/').some(part => part === '.' || part === '..')
        || typeof value.reviewer !== 'string' || !value.reviewer.trim() || value.reviewer.length > 200
        || typeof value.approvedAt !== 'string' || !/^\d{4}-\d\d-\d\dT[0-9:.]+Z$/.test(value.approvedAt)
        || JSON.stringify(value.limitations) !== JSON.stringify(LIMITATIONS)) throw new Error('Approve the environment permissions, workspace, and limitations for the current proposal.');
    return value;
}
