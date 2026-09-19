#!/usr/bin/env node

import { AuthStateDatabase, closeAuthState } from '../lib/authState.js';
import { createSpawnOtp } from '../lib/mcpSpawnOtp.js';

function usage() {
  process.stderr.write('Usage: node /app/scripts/auth-state-cli.mjs reset|otp\n');
}

const [command, ...extraArguments] = process.argv.slice(2);

if (!['reset', 'otp'].includes(command) || extraArguments.length > 0) {
  usage();
  process.exitCode = 2;
} else if (command === 'otp') {
  try {
    const otp = createSpawnOtp({ source: 'operator-cli' });
    process.stdout.write(`Spawn OTP (shown once): ${otp.value}\n`);
    process.stdout.write(`OTP record: ${otp.uuid}\n`);
  } catch (error) {
    process.stderr.write(`Unable to create Notty spawn OTP: ${error.message}\n`);
    process.exitCode = 1;
  } finally {
    closeAuthState();
  }
} else {
  let state;
  try {
    state = new AuthStateDatabase();
    const result = state.reset();
    process.stdout.write(
      `Reset Notty auth state for workspace ${result.workspaceId} at ${new Date(result.resetAt).toISOString()}\n`
    );
  } catch (error) {
    process.stderr.write(`Unable to reset Notty auth state: ${error.message}\n`);
    process.exitCode = 1;
  } finally {
    state?.close();
  }
}
