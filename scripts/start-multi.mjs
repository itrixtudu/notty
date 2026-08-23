#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import process from 'node:process';

const DEFAULT_INSTANCE_COUNT = 3;
const DEFAULT_BASE_PORT = Number.parseInt(process.env.PORT ?? '3000', 10) || 3000;
const DEFAULT_OTP_BYTES = 12;

function toPositiveInt(value) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return null;
    }
    return parsed;
}

function parseArgs(argv) {
    let instances = null;
    let basePort = null;
    let otpBytes = null;
    let help = false;

    for (let index = 0; index < argv.length; index += 1) {
        const arg = argv[index];

        if (arg === '--help' || arg === '-h') {
            help = true;
            continue;
        }

        if (arg === '--instances' || arg === '-n') {
            instances = argv[index + 1];
            index += 1;
            continue;
        }

        if (arg.startsWith('--instances=')) {
            instances = arg.slice('--instances='.length);
            continue;
        }

        if (arg === '--base-port' || arg === '-p') {
            basePort = argv[index + 1];
            index += 1;
            continue;
        }

        if (arg.startsWith('--base-port=')) {
            basePort = arg.slice('--base-port='.length);
            continue;
        }

        if (arg === '--otp-bytes') {
            otpBytes = argv[index + 1];
            index += 1;
            continue;
        }

        if (arg.startsWith('--otp-bytes=')) {
            otpBytes = arg.slice('--otp-bytes='.length);
            continue;
        }
    }

    const normalizedInstances = toPositiveInt(instances) ?? DEFAULT_INSTANCE_COUNT;
    const normalizedBasePort = toPositiveInt(basePort) ?? DEFAULT_BASE_PORT;
    const normalizedOtpBytes = toPositiveInt(otpBytes) ?? DEFAULT_OTP_BYTES;

    return {
        instances: normalizedInstances,
        basePort: normalizedBasePort,
        otpBytes: normalizedOtpBytes,
        help,
    };
}

function printHelp() {
    console.error('Usage: node scripts/start-multi.mjs [--instances N] [--base-port P] [--otp-bytes B]');
    console.error(`Defaults: --instances ${DEFAULT_INSTANCE_COUNT}, --base-port ${DEFAULT_BASE_PORT}, --otp-bytes ${DEFAULT_OTP_BYTES}`);
}

function makeOtp(byteLength) {
    return randomBytes(byteLength).toString('hex');
}

const { instances, basePort, otpBytes, help } = parseArgs(process.argv.slice(2));

if (help) {
    printHelp();
    process.exit(0);
}

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(scriptDir, '..');
const serverPath = path.join(rootDir, 'server.js');

const children = [];
let shuttingDown = false;
let expectedExits = instances;

function requestShutdown(reason) {
    if (shuttingDown) {
        return;
    }

    shuttingDown = true;
    console.error(`[start] shutdown requested (${reason})`);

    for (const child of children) {
        if (!child.killed) {
            child.kill('SIGTERM');
        }
    }

    setTimeout(() => {
        for (const child of children) {
            if (!child.killed) {
                child.kill('SIGKILL');
            }
        }
    }, 5000).unref();
}

process.on('SIGINT', () => requestShutdown('SIGINT'));
process.on('SIGTERM', () => requestShutdown('SIGTERM'));

console.error(`[start] launching ${instances} instances`);

for (let index = 0; index < instances; index += 1) {
    const instance = index + 1;
    const port = basePort + index;
    const otp = makeOtp(otpBytes);
    const env = {
        ...process.env,
        PORT: String(port),
        NOTTY_MCP_SPAWN_OTP: otp,
        NOTTY_INSTANCE_INDEX: String(instance),
    };

    const child = spawn(process.execPath, [serverPath], {
        cwd: rootDir,
        env,
        stdio: 'inherit',
    });

    children.push(child);

    console.error(`[start] instance=${instance} port=${port} otp=${otp} pid=${child.pid}`);

    child.once('error', (err) => {
        console.error(`[start] instance=${instance} failed to start: ${err.message}`);
        process.exitCode = 1;
        requestShutdown(`spawn-error-instance-${instance}`);
    });

    child.once('exit', (code, signal) => {
        expectedExits -= 1;
        const status = signal ? `signal=${signal}` : `code=${code ?? 0}`;
        console.error(`[start] instance=${instance} exited (${status})`);

        if (!shuttingDown) {
            process.exitCode = code === 0 ? 0 : 1;
            requestShutdown(`unexpected-exit-instance-${instance}`);
        }

        if (expectedExits <= 0) {
            process.exit(process.exitCode ?? 0);
        }
    });
}
