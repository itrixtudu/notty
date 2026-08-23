'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const appRoot = path.resolve(__dirname, '..');
const dockerfile = fs.readFileSync(
  path.join(appRoot, 'Dockerfile.nosh'),
  'utf8',
);

test('the common Nosh image avoids recursive ownership rewrites', () => {
  const [baseStage] = dockerfile.split(/^FROM base AS local$/m);
  const stateSetupStart = baseStage.indexOf(
    '# Preserve the small runtime state roots',
  );
  const stateSetupEnd = baseStage.indexOf(
    '\n\n# Keep the password helper',
    stateSetupStart,
  );
  const stateSetup = baseStage.slice(stateSetupStart, stateSetupEnd);

  assert.doesNotMatch(
    baseStage,
    /\bchown\s+-R\b/,
    'the base stage must not walk dependency and build-output trees to change ownership',
  );
  assert.match(
    baseStage,
    /^COPY --chown=\$\{USERNAME\}:\$\{USERNAME\} tmux\.conf \/home\/\$\{USERNAME\}\/\.tmux\.conf$/m,
    'the one user-owned home file should receive ownership when copied',
  );
  assert.match(
    baseStage,
    /^RUN npx next build$/m,
    'the Next.js build should remain an independently timed BuildKit vertex',
  );
  assert.ok(stateSetupStart >= 0 && stateSetupEnd > stateSetupStart);
  for (const directory of [
    '/app/agents/runs',
    '/app/collab/intragent/channels',
    '/app/.notty-art-runs',
  ]) {
    assert.ok(
      stateSetup.includes(directory),
      `the runtime state root should be created directly: ${directory}`,
    );
  }
});
