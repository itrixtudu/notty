// One writer per mounted review. Never let an older request overtake a newer one.
export function createDraftAutosaver({ save, onSaved, onError, delay = 750 }) {
    let pending = null;
    let running = null;
    let timer = null;
    let disposed = false;
    const clearTimer = () => { clearTimeout(timer); timer = null; };
    const pump = () => {
        if (running) return running;
        running = (async () => {
            while (pending && !disposed) {
                const snapshot = pending;
                pending = null;
                try {
                    await save(snapshot);
                    if (!disposed) onSaved(snapshot);
                } catch (error) {
                    if (!disposed) {
                        pending ||= snapshot;
                        onError(error);
                    }
                    throw error;
                }
            }
        })().finally(() => { running = null; });
        return running;
    };
    return {
        schedule(snapshot) {
            if (disposed) return;
            pending = snapshot;
            clearTimer();
            timer = setTimeout(() => { pump().catch(() => {}); }, delay);
        },
        async flush(snapshot) {
            if (disposed) throw new Error('Review session changed');
            clearTimer();
            pending = snapshot;
            await pump();
            if (disposed) throw new Error('Review session changed');
        },
        dispose() { disposed = true; pending = null; clearTimer(); },
    };
}

export function explainReviewBlocker(blocker, graph) {
    if (blocker.startsWith('decision:')) {
        const proposal = graph.proposals?.find(entry => blocker === `decision:${entry.id}`);
        const peer = proposal?.intent?.peer?.value || proposal?.label || 'this connection';
        return `Choose Allow or Deny and provide a reason for ${peer}.`;
    }
    if (blocker === 'reviewer:identity-required') return 'Enter your reviewer name.';
    if (blocker === 'reviewer:not-acknowledged') return 'Confirm that you reviewed these decisions.';
    if (blocker.startsWith('target:')) return 'Review the selected enforcement target and any required rule acknowledgements.';
    if (blocker.startsWith('coverage:')) return 'Evidence coverage is incomplete. Inspect the coverage details and collect the missing evidence before applying.';
    if (blocker.startsWith('finding:')) {
        const finding = graph.findings.find(entry => `finding:${entry.id}` === blocker);
        return `${finding?.message || 'The evidence contains a blocking finding.'} Resolve this finding before applying; changing Allow/Deny choices does not clear it.`;
    }
    if (blocker.startsWith('profile:')) return 'Learning did not produce complete evidence and a candidate. Complete a new learning run before applying.';
    if (blocker === 'graph:not-frozen') return 'Open a completed learning export to save a review.';
    if (/sbom-source/i.test(blocker)) return 'Source software inventory is missing or incomplete. Reopen review to collect it with the local offline tooling.';
    if (/sbom-image/i.test(blocker)) return 'Workload image software inventory is missing or incomplete. Reopen review to collect the exact image inventory offline.';
    if (/sbom/i.test(blocker)) return 'Software inventory is missing or incomplete. Reopen review to generate source and image inventories offline.';
    if (/signing/i.test(blocker)) return 'Resume the startup wizard to set up signing, then reopen review.';
    return blocker;
}
