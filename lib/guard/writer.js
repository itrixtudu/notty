import fs from 'node:fs';
import path from 'node:path';
import {
  ARTIFACT_KEYS,
  MANIFEST_FILE,
  PROFILE_FILE,
  REPORT_HTML_FILE,
  REPORT_JSON_FILE,
} from './constants.js';
import { serializeArtifact } from './compiler.js';
import { generateHtmlReport, generateJsonReport } from './report.js';
import { serializeJson, sha256 } from './stable.js';

function assertCompiledResult(result) {
  if (
    !result
    || result.profile?.kind !== 'NoshSecurityProfile'
    || !result.artifacts
  ) {
    throw new TypeError('writeCompiledProfile requires the result of compileGuardProfile');
  }
  for (const name of ARTIFACT_KEYS) {
    if (!result.artifacts[name]) {
      throw new TypeError(`compiled profile is missing ${name} artifact`);
    }
  }
}

function preflightTarget(filePath, overwrite) {
  try {
    const stat = fs.lstatSync(filePath);
    if (stat.isSymbolicLink()) {
      throw new Error(`refusing to write through symbolic link: ${filePath}`);
    }
    if (!overwrite) {
      throw new Error(`refusing to overwrite existing guard output: ${filePath}`);
    }
    if (!stat.isFile()) {
      throw new Error(`guard output target is not a regular file: ${filePath}`);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
}

export function writeCompiledProfile(outputDir, result, options = {}) {
  assertCompiledResult(result);
  if (typeof outputDir !== 'string' || !outputDir.trim()) {
    throw new TypeError('guard output directory must be a non-empty path');
  }
  const overwrite = options.overwrite === true;
  const directory = path.resolve(outputDir);
  try {
    if (fs.lstatSync(directory).isSymbolicLink()) {
      throw new Error(`refusing to use a symbolic-link guard output directory: ${directory}`);
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw error;
    }
  }
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (!fs.statSync(directory).isDirectory()) {
    throw new Error(`guard output path is not a directory: ${directory}`);
  }

  const payloads = {
    [PROFILE_FILE]: serializeJson(result.profile),
    [REPORT_JSON_FILE]: generateJsonReport(result),
    [REPORT_HTML_FILE]: generateHtmlReport(result),
  };
  for (const name of ARTIFACT_KEYS) {
    const artifact = result.artifacts[name];
    payloads[artifact.fileName] = serializeArtifact(name, artifact.content);
  }

  const targetNames = [...Object.keys(payloads), MANIFEST_FILE].sort();
  for (const fileName of targetNames) {
    preflightTarget(path.join(directory, fileName), overwrite);
  }

  const manifest = {
    apiVersion: 'notty.dev/v1alpha1',
    kind: 'NoshSecurityProfileBundle',
    metadata: {
      name: result.profile.metadata.name,
    },
    lifecycle: {
      phase: 'candidate',
      reviewRequired: true,
      automaticApply: false,
    },
    files: Object.fromEntries(
      Object.keys(payloads)
        .sort()
        .map((fileName) => [
          fileName,
          {
            hash: sha256(payloads[fileName]),
            bytes: Buffer.byteLength(payloads[fileName], 'utf8'),
          },
        ]),
    ),
  };
  payloads[MANIFEST_FILE] = serializeJson(manifest);

  for (const fileName of Object.keys(payloads).sort()) {
    fs.writeFileSync(path.join(directory, fileName), payloads[fileName], {
      encoding: 'utf8',
      flag: overwrite ? 'w' : 'wx',
      mode: 0o600,
    });
  }
  return {
    directory,
    files: Object.keys(payloads)
      .sort()
      .map((fileName) => path.join(directory, fileName)),
    manifest,
  };
}
