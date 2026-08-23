import { useEffect, useMemo } from 'react';

import {
    createTimelineProjection,
    selectTimelineActivity,
    TIMELINE_DOMAINS,
} from '../../modules/policy-review/timelineProjection';
import { usePolicyReviewStore } from '../../modules/policy-review/reviewStore';

import styles from './PolicyReview.module.css';

const PLAYBACK_SPEEDS = [0.25, 0.5, 1, 2];
const HISTOGRAM_BUCKETS = 96;

const instantFormatter = new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'medium',
    hour12: false,
    timeZone: 'UTC',
});

const formatInstant = value => (
    Number.isFinite(value) ? `${instantFormatter.format(new Date(value))} UTC` : 'Time unavailable'
);

const formatDuration = value => {
    const milliseconds = Math.max(0, Number(value) || 0);
    if (milliseconds < 1000) {
        return `${Math.round(milliseconds)} ms`;
    }
    if (milliseconds < 60_000) {
        return `${(milliseconds / 1000).toFixed(milliseconds < 10_000 ? 1 : 0)} s`;
    }
    if (milliseconds < 3_600_000) {
        return `${(milliseconds / 60_000).toFixed(milliseconds < 600_000 ? 1 : 0)} min`;
    }
    return `${(milliseconds / 3_600_000).toFixed(1)} hr`;
};

const formatDomain = domain => (
    domain === 'dns'
        ? 'DNS'
        : String(domain).replaceAll('-', ' ').replace(/\b\w/g, letter => letter.toUpperCase())
);

const buildHistogram = (items, startMs, endMs) => {
    const buckets = Array.from({ length: HISTOGRAM_BUCKETS }, () => 0);
    const durationMs = Math.max(1, endMs - startMs);
    items.forEach(item => {
        if (!Number.isFinite(item.startMs)) {
            return;
        }
        const itemEndMs = Number.isFinite(item.endMs) ? item.endMs : item.startMs;
        const first = Math.max(0, Math.min(
            HISTOGRAM_BUCKETS - 1,
            Math.floor(((item.startMs - startMs) / durationMs) * HISTOGRAM_BUCKETS),
        ));
        const last = Math.max(first, Math.min(
            HISTOGRAM_BUCKETS - 1,
            Math.floor(((itemEndMs - startMs) / durationMs) * HISTOGRAM_BUCKETS),
        ));
        for (let index = first; index <= last; index += 1) {
            buckets[index] += 1;
        }
    });
    const maximum = Math.max(1, ...buckets);
    return buckets.map(count => count / maximum);
};

export default function PolicyReviewTimeline() {
    const { state, dispatch } = usePolicyReviewStore();
    const { timeline } = state;
    const projection = useMemo(() => createTimelineProjection(state.graph), [state.graph]);
    const hasTimeline = Number.isFinite(timeline.startMs) && Number.isFinite(timeline.endMs);
    const durationMs = hasTimeline ? Math.max(0, timeline.endMs - timeline.startMs) : 0;
    const canPlay = hasTimeline && durationMs > 0;
    const cursorProgress = canPlay
        ? Math.max(0, Math.min(1, (timeline.cursorMs - timeline.startMs) / durationMs))
        : 0;
    const windowMaximum = Math.max(1, durationMs);
    const windowStep = Math.max(1, Math.round(windowMaximum / 200));
    const histogram = useMemo(
        () => (hasTimeline ? buildHistogram(
            projection.items.filter(item => (
                item.precision.basis === 'observation-bounds'
                || item.precision.basis === 'structural-metadata'
            )),
            timeline.startMs,
            timeline.endMs,
        ) : []),
        [hasTimeline, projection.items, timeline.endMs, timeline.startMs],
    );
    const availableDomains = useMemo(() => {
        const projected = new Set(projection.domains);
        return [
            ...TIMELINE_DOMAINS.filter(domain => projected.has(domain)),
            ...projection.domains.filter(domain => !TIMELINE_DOMAINS.includes(domain)).sort(),
        ];
    }, [projection.domains]);
    const activity = useMemo(() => selectTimelineActivity(projection, {
        cursorMs: hasTimeline ? timeline.cursorMs : 0,
        mode: timeline.mode,
        windowMs: timeline.windowMs,
        domains: timeline.domains,
        includeUntimed: true,
    }), [hasTimeline, projection, timeline.cursorMs, timeline.domains, timeline.mode, timeline.windowMs]);
    const activeItemCount = activity.itemIds?.length ?? activity.itemIds?.size ?? 0;

    useEffect(() => {
        if (!timeline.playing) {
            return undefined;
        }
        let previous = performance.now();
        const timer = window.setInterval(() => {
            const now = performance.now();
            dispatch({ type: 'ADVANCE_TIMELINE', elapsedMs: now - previous });
            previous = now;
        }, 100);
        return () => window.clearInterval(timer);
    }, [dispatch, timeline.playing]);

    const playbackStatus = !hasTimeline
        ? 'Timeline unavailable.'
        : `Timeline ${timeline.playing ? 'playing' : 'paused'} at ${timeline.speed}× in ${timeline.mode} mode.`;
    const positionStatus = !hasTimeline
        ? 'No timestamped telemetry is available in this graph.'
        : `${formatInstant(timeline.cursorMs)}. ${activeItemCount} of ${projection.items.length} timeline items are in view.`;

    return (
        <section className={styles.timeline} aria-labelledby="policy-review-timeline-heading">
            <div className={styles.timelineHeading}>
                <div>
                    <span>Temporal projection</span>
                    <h2 id="policy-review-timeline-heading">Build profile timeline</h2>
                </div>
                <p className={styles.timelineStatus}>
                    <span role="status" aria-live="polite" aria-atomic="true">{playbackStatus}</span>
                    <span>{positionStatus}</span>
                </p>
            </div>
            <div className={styles.timelineControls}>
                <div className={styles.playbackButtons} role="group" aria-label="Timeline playback controls">
                    <button
                        type="button"
                        disabled={!canPlay || timeline.playing}
                        onClick={() => dispatch({ type: 'SET_TIMELINE_PLAYING', playing: true })}
                    >
                        Play
                    </button>
                    <button
                        type="button"
                        disabled={!timeline.playing}
                        onClick={() => dispatch({ type: 'SET_TIMELINE_PLAYING', playing: false })}
                    >
                        Pause
                    </button>
                    <button
                        type="button"
                        disabled={!hasTimeline}
                        onClick={() => dispatch({ type: 'REWIND_TIMELINE' })}
                    >
                        Rewind
                    </button>
                </div>
                <label className={styles.timelineSelect}>
                    <span>Speed</span>
                    <select
                        value={timeline.speed}
                        disabled={!canPlay}
                        onChange={event => dispatch({
                            type: 'SET_TIMELINE_SPEED',
                            speed: Number(event.target.value),
                        })}
                    >
                        {PLAYBACK_SPEEDS.map(speed => (
                            <option key={speed} value={speed}>{speed}×</option>
                        ))}
                    </select>
                </label>
                <div className={styles.timelineModes} role="group" aria-label="Timeline visibility mode">
                    <span>View</span>
                    <button
                        type="button"
                        aria-pressed={timeline.mode === 'cumulative'}
                        onClick={() => dispatch({ type: 'SET_TIMELINE_MODE', mode: 'cumulative' })}
                    >
                        Cumulative
                    </button>
                    <button
                        type="button"
                        aria-pressed={timeline.mode === 'window'}
                        onClick={() => dispatch({ type: 'SET_TIMELINE_MODE', mode: 'window' })}
                    >
                        Window
                    </button>
                </div>
                <label className={styles.timelineWindow} data-enabled={timeline.mode === 'window'}>
                    <span>Window <output>{formatDuration(timeline.windowMs)}</output></span>
                    <input
                        type="range"
                        min="1"
                        max={windowMaximum}
                        step={windowStep}
                        value={Math.min(windowMaximum, Math.max(1, timeline.windowMs))}
                        disabled={!canPlay || timeline.mode !== 'window'}
                        onChange={event => dispatch({
                            type: 'SET_TIMELINE_WINDOW_MS',
                            windowMs: Number(event.target.value),
                        })}
                    />
                </label>
            </div>
            <div className={styles.timelineScrubber} data-disabled={!hasTimeline}>
                <div
                    className={styles.timelineHistogram}
                    style={{ '--timeline-cursor': `${cursorProgress * 100}%` }}
                    aria-hidden="true"
                >
                    {histogram.map((intensity, index) => (
                        <i key={index} style={{ '--timeline-activity': intensity }} />
                    ))}
                    {hasTimeline ? <b /> : null}
                </div>
                <input
                    aria-label="Evidence timeline position"
                    aria-valuetext={formatInstant(timeline.cursorMs)}
                    type="range"
                    min={timeline.startMs ?? 0}
                    max={timeline.endMs ?? 1}
                    step={Math.max(1, Math.round(durationMs / 1000))}
                    value={timeline.cursorMs ?? 0}
                    disabled={!hasTimeline || durationMs === 0}
                    onChange={event => dispatch({
                        type: 'SET_TIMELINE_CURSOR',
                        cursorMs: Number(event.target.value),
                    })}
                />
                <div className={styles.timelineLabels}>
                    <time dateTime={hasTimeline ? new Date(timeline.startMs).toISOString() : undefined}>
                        {formatInstant(timeline.startMs)}
                    </time>
                    <strong>{formatInstant(timeline.cursorMs)}</strong>
                    <time dateTime={hasTimeline ? new Date(timeline.endMs).toISOString() : undefined}>
                        {formatInstant(timeline.endMs)}
                    </time>
                </div>
            </div>
            <div className={styles.timelineDomains}>
                <span>Telemetry domains</span>
                <div role="group" aria-label="Timeline telemetry domain filters">
                    {availableDomains.map(domain => {
                        const enabled = timeline.domains === null || timeline.domains.includes(domain);
                        return (
                            <button
                                key={domain}
                                type="button"
                                aria-pressed={enabled}
                                onClick={() => dispatch({
                                    type: 'TOGGLE_TIMELINE_DOMAIN',
                                    domain,
                                    availableDomains,
                                })}
                            >
                                {formatDomain(domain)}
                            </button>
                        );
                    })}
                    <button
                        type="button"
                        disabled={timeline.domains === null}
                        onClick={() => dispatch({ type: 'RESET_TIMELINE_DOMAINS' })}
                    >
                        Show all
                    </button>
                </div>
            </div>
            <p className={styles.timelineHint}>
                {timeline.mode === 'cumulative'
                    ? 'Cumulative mode includes activity from the start of the capture through the cursor.'
                    : `Window mode includes activity overlapping the ${formatDuration(timeline.windowMs)} before the cursor.`}
                {' '}Capture shape: {projection.stats.point} point items, {projection.stats.interval} intervals ({projection.stats.aggregated} aggregated), and {projection.stats.untimed} untimed context records.
                {' '}Timeline position and filters are a local review view and are never included in exported policy decisions.
            </p>
        </section>
    );
}
