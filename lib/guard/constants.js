export const API_VERSION = 'notty.dev/v1alpha1';
export const EVIDENCE_KIND = 'NoshSecurityEvidence';
export const PROFILE_KIND = 'NoshSecurityProfile';
export const REPORT_KIND = 'NoshSecurityProfileReport';
export const SCHEMA_VERSION = 1;

export const ARTIFACT_KEYS = Object.freeze([
  'tetragon',
  'seccomp',
  'apparmor',
  'docker',
  'network',
]);

export const ARTIFACT_FILES = Object.freeze({
  tetragon: 'tetragon.yaml',
  seccomp: 'seccomp.json',
  apparmor: 'apparmor.profile',
  docker: 'docker.json',
  network: 'network-policy.yaml',
});

export const PROFILE_FILE = 'profile.yaml';
export const REPORT_JSON_FILE = 'report.json';
export const REPORT_HTML_FILE = 'report.html';
export const MANIFEST_FILE = 'manifest.json';
