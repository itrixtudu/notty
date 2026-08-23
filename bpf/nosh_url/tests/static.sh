#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_file="$root/nosh_url.bpf.c"
header_file="$root/include/nosh_url.h"
loader_file="$root/loader/nosh_url_loader.c"
sanitizer_file="$root/loader/url_sanitizer.c"
readme_file="$root/README.md"

require() {
  local pattern=$1
  local file=$2
  local message=$3
  if ! grep -Eq -- "$pattern" "$file"; then
    echo "nosh-url static test failed: $message" >&2
    exit 1
  fi
}

reject() {
  local pattern=$1
  local file=$2
  local message=$3
  if grep -Eq -- "$pattern" "$file"; then
    echo "nosh-url static test failed: $message" >&2
    exit 1
  fi
}

require 'NOSH_URL_RAW_MAX 2048' "$header_file" \
  'raw userspace reads are not bounded'
require 'NOSH_URL_PATH_MAX 512' "$header_file" \
  'sanitized evidence path contract is not bounded'
require 'SEC\("uprobe"\)' "$source_file" \
  'libcurl uprobe program is missing'
require 'NOSH_URL_CURLOPT_URL' "$source_file" \
  'CURLOPT_URL filtering is missing'
require 'bpf_current_task_under_cgroup' "$source_file" \
  'kernel descendant-cgroup filter is missing'
require 'bpf_probe_read_user_str' "$source_file" \
  'bounded userspace URL read is missing'
require 'bpf_ringbuf_discard' "$source_file" \
  'failed or truncated raw reads are not discarded'
require 'static __always_inline void clear_url_event' "$source_file" \
  'large URL events do not use the clang-14-safe clear helper'
require 'volatile __u64 \*words' "$source_file" \
  'URL event clearing can be folded back into an unsupported memset'
require 'URL event must be word aligned' "$source_file" \
  'URL event clear helper does not guard its word-store layout'
require '#pragma clang loop unroll\(disable\)' "$source_file" \
  'URL event clearing is not kept as a bounded loop'
require 'words\[index\] = 0' "$source_file" \
  'URL event clear helper does not initialize the full record'
require 'clear_url_event\(event\)' "$source_file" \
  'URL event is submitted without explicit full initialization'
reject '__builtin_memset\(event, 0, sizeof\(\*event\)\)' "$source_file" \
  'full URL event memset is unsupported by clang 14 BPF'
reject 'bpf_override_return|BPF_MAP_TYPE_CGROUP_SOCK_ADDR|verdict|deny|allow' \
  "$source_file" 'observational collector contains enforcement semantics'

require 'func_name = "curl_easy_setopt"' "$loader_file" \
  'loader does not resolve the exported libcurl function'
require 'bpf_program__attach_uprobe_opts.*-1' "$loader_file" \
  'uprobe is not attached by exact object for cgroup-filtered observation'
require '/proc/self/fd/%d' "$loader_file" \
  'attachment is not bound to an already-verified object descriptor'
require 'metadata->st_ino != expected_inode' "$loader_file" \
  'mapped object inode is not revalidated'
require 'context->initial_scan_complete' "$loader_file" \
  'late dynamic discovery is not distinguished from pre-ready discovery'
require 'context->discovery_misses \+= 1' "$loader_file" \
  'discovery gaps are not explicit'
require 'openat\(directory_fd, "\."' "$loader_file" \
  'repeat discovery does not use an independent directory description'
reject 'dup\(directory_fd\)' "$loader_file" \
  'repeat discovery shares and advances the persistent cgroup directory offset'
require 'coverageComplete\\\":false' "$loader_file" \
  'collector falsely claims complete URL coverage'
require 'readErrors' "$loader_file" \
  'userspace read failures are not emitted in statistics'
require 'return emit_stats\(context, true\)' "$loader_file" \
  'clean shutdown does not emit final statistics'
require 'consume_result = ring_buffer__consume\(ring\)' "$loader_file" \
  'shutdown drain does not inspect ring-buffer consume results'
require 'if \(consume_result < 0\)' "$loader_file" \
  'negative ring-buffer consume is not a shutdown error'
reject '\\"rawUrl\\"|\\"url\\"' "$loader_file" \
  'raw URL has an output field'

require "\*cursor == '\?' \|\| \*cursor == '#'" "$sanitizer_file" \
  'query and fragment stripping is missing'
require "\*cursor == '@'" "$sanitizer_file" \
  'userinfo stripping is missing'
require 'ascii_lower' "$sanitizer_file" \
  'scheme and host are not normalized to lowercase'
require 'NOSH_URL_SANITIZED_PATH_MAX' "$sanitizer_file" \
  'sanitizer does not enforce the 512-byte path limit'
require 'NOSH_URL_HOST_MAX 253' "$root/loader/url_sanitizer.h" \
  'sanitized host bound does not match the ingestion contract'

for schema in "$root"/schema/*.schema.json; do
  reject 'rawUrl|raw_url|userinfo|query|fragment|headers|payload' "$schema" \
    "schema exposes forbidden raw request material: $schema"
done
require 'observation-only' "$readme_file" \
  'documentation does not state the authority boundary'
require 'discoveryMisses' "$readme_file" \
  'documentation omits dynamic discovery gaps'

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
${CC:-cc} -std=c17 -Wall -Wextra -Werror \
  -I"$root/loader" -I"$root/include" \
  "$root/loader/url_sanitizer.c" "$root/tests/url_sanitizer_test.c" \
  -o "$scratch/url-sanitizer-test"
"$scratch/url-sanitizer-test"
${CC:-cc} -std=c17 -Wall -Wextra -Werror \
  -DNOSH_URL_TESTING \
  -I"$root/tests/include" -I"$root/include" -I"$root/loader" \
  "$root/loader/nosh_url_loader.c" "$root/loader/url_sanitizer.c" \
  "$root/tests/loader_stubs.c" -o "$scratch/nosh-url-loader-test"
test "$("$scratch/nosh-url-loader-test" --version)" = 1
"$scratch/nosh-url-loader-test" --help | grep -q 'nosh-url-loader run'
"$scratch/nosh-url-loader-test" --test-directory-rescan | \
  grep -q 'directory rescan test: ok'
"$scratch/nosh-url-loader-test" --test-shutdown-drain | \
  grep -q 'shutdown drain test: ok'
if "$scratch/nosh-url-loader-test" run >/dev/null 2>&1; then
  echo 'nosh-url static test failed: run accepted a missing cgroup' >&2
  exit 1
fi

echo 'nosh-url static tests: ok'
