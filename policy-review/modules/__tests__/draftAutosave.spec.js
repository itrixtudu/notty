import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDraftAutosaver, explainReviewBlocker } from '../policy-review/draftAutosave';

const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
};
const setup = save => {
    const onSaved = vi.fn(), onError = vi.fn();
    const writer = createDraftAutosaver({ save, onSaved, onError });
    return { writer, onSaved, onError };
};
afterEach(() => vi.useRealTimers());

describe('automatic review draft persistence', () => {
    it('debounces changes and saves only the newest pending snapshot', async () => {
        vi.useFakeTimers();
        const save = vi.fn().mockResolvedValue({});
        const { writer, onSaved } = setup(save);
        writer.schedule({ version: 1 });
        await vi.advanceTimersByTimeAsync(500);
        writer.schedule({ version: 2 });
        await vi.advanceTimersByTimeAsync(749);
        expect(save).not.toHaveBeenCalled();
        await vi.advanceTimersByTimeAsync(1);
        expect(save).toHaveBeenCalledExactlyOnceWith({ version: 2 });
        expect(onSaved).toHaveBeenCalledExactlyOnceWith({ version: 2 });
        writer.dispose();
    });

    it('serializes writes and coalesces edits made during an in-flight save', async () => {
        const first = deferred();
        const save = vi.fn().mockReturnValueOnce(first.promise).mockResolvedValue({});
        const { writer, onSaved } = setup(save);
        const complete = writer.flush({ version: 1 });
        writer.schedule({ version: 2 });
        writer.schedule({ version: 3 });
        expect(save).toHaveBeenCalledTimes(1);
        first.resolve();
        await complete;
        expect(save.mock.calls).toEqual([[{ version: 1 }], [{ version: 3 }]]);
        expect(onSaved.mock.calls).toEqual([[{ version: 1 }], [{ version: 3 }]]);
        writer.dispose();
    });

    it('flushes finalization immediately and waits for persistence', async () => {
        const request = deferred();
        const save = vi.fn().mockReturnValue(request.promise);
        const { writer, onSaved } = setup(save);
        writer.schedule({ version: 1 });
        const complete = writer.flush({ version: 2 });
        expect(save).toHaveBeenCalledExactlyOnceWith({ version: 2 });
        expect(onSaved).not.toHaveBeenCalled();
        request.resolve();
        await complete;
        expect(onSaved).toHaveBeenCalledExactlyOnceWith({ version: 2 });
        writer.dispose();
    });

    it('reports failures, preserves edits, and permits an explicit retry', async () => {
        const error = new Error('disk full');
        const save = vi.fn().mockRejectedValueOnce(error).mockResolvedValue({});
        const { writer, onSaved, onError } = setup(save);
        await expect(writer.flush({ version: 1 })).rejects.toThrow('disk full');
        expect(onSaved).not.toHaveBeenCalled();
        expect(onError).toHaveBeenCalledExactlyOnceWith(error);
        await writer.flush({ version: 2 });
        expect(onSaved).toHaveBeenCalledExactlyOnceWith({ version: 2 });
        writer.dispose();
    });

    it('discards scheduled work and ignores stale responses after session disposal', async () => {
        const request = deferred();
        const save = vi.fn().mockReturnValue(request.promise);
        const { writer, onSaved, onError } = setup(save);
        const complete = writer.flush({ graph: 'old' });
        writer.schedule({ graph: 'pending' });
        writer.dispose();
        request.resolve();
        await expect(complete).rejects.toThrow('session changed');
        expect(save).toHaveBeenCalledTimes(1);
        expect(onSaved).not.toHaveBeenCalled();
        expect(onError).not.toHaveBeenCalled();
    });

    it('never sends a queued draft after leaving the review', async () => {
        vi.useFakeTimers();
        const save = vi.fn();
        const { writer } = setup(save);
        writer.schedule({ graph: 'old' });
        writer.dispose();
        await vi.runAllTimersAsync();
        expect(save).not.toHaveBeenCalled();
    });
});

describe('review requirement explanations', () => {
    const graph = { findings: [{ id: 'dns:1', message: 'DNS observation has no authority.' }] };
    it('keeps evidence blockers distinct from unfinished reviewer choices', () => {
        expect(explainReviewBlocker('reviewer:identity-required', graph)).toContain('reviewer name');
        expect(explainReviewBlocker('finding:dns:1', graph)).toContain('DNS observation has no authority.');
        expect(explainReviewBlocker('coverage:network:degraded', graph)).toContain('collect the missing evidence');
        expect(explainReviewBlocker('new:unrecognized-blocker', graph)).toBe('new:unrecognized-blocker');
    });
});
