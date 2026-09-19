#!/usr/bin/env node
import { prepareReviewSession, snapshotReviewSelection } from '../lib/guard/review/session.js';

const [command, ...argv] = process.argv.slice(2);
const options = {};
for (let index = 0; index < argv.length; index += 2) {
  const key = argv[index];
  if (!/^--[a-z-]+$/.test(key) || argv[index + 1] == null || Object.hasOwn(options, key.slice(2))) {
    throw new Error('Expected unique --name value arguments');
  }
  options[key.slice(2)] = argv[index + 1];
}
try {
  const result = command === 'prepare' ? await prepareReviewSession({
    ...options, configAvailable: options['config-available'], applyConfig: options['apply-config'],
    sbomSource: options['sbom-source'], sbomImage: options['sbom-image'],
  }) : command === 'snapshot' ? await snapshotReviewSelection(options.session, options.digest, options.output)
    : (() => { throw new Error('Use prepare or snapshot'); })();
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) { process.stderr.write(`nosh-policy-session: ${error.message}\n`); process.exitCode = 1; }
