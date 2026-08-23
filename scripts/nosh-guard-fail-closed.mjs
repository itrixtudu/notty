#!/usr/bin/env node

import { DockerClient } from '../lib/guardd/docker-client.js';

async function main() {
  const docker = new DockerClient();
  const containers = await docker.listContainers({
    all: false,
    filters: {
      label: [
        'io.notty.guard.managed=true',
        'io.notty.guard.component=runner',
      ],
    },
  });
  const results = [];
  for (const container of containers || []) {
    try {
      await docker.pauseContainer(container.Id);
      results.push({ containerId: container.Id, action: 'pause', ok: true });
    } catch (pauseError) {
      try {
        await docker.stopContainer(container.Id, 2);
        results.push({ containerId: container.Id, action: 'stop', ok: true });
      } catch (stopError) {
        results.push({
          containerId: container.Id,
          action: 'stop',
          ok: false,
          error: stopError.message,
          pauseError: pauseError.message,
        });
      }
    }
  }
  process.stdout.write(`${JSON.stringify({ failClosed: results }, null, 2)}\n`);
  if (results.some((result) => !result.ok)) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  process.stderr.write(`nosh-guard-fail-closed: ${error.message}\n`);
  process.exitCode = 1;
});
