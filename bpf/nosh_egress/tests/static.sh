#!/usr/bin/env bash
set -euo pipefail

component_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_file="$component_dir/nosh_egress.bpf.c"
header_file="$component_dir/include/nosh_egress.h"
loader_file="$component_dir/loader/nosh_egress_loader.c"
make_file="$component_dir/Makefile"
test_skeleton="$component_dir/tests/include/nosh_egress.skel.h"

require() {
  local pattern="$1"
  local file="$2"
  local message="$3"
  rg --quiet --multiline "$pattern" "$file" || {
    printf 'nosh-egress static test: %s\n' "$message" >&2
    exit 1
  }
}

reject() {
  local pattern="$1"
  local file="$2"
  local message="$3"
  if rg --quiet --multiline "$pattern" "$file"; then
    printf 'nosh-egress static test: %s\n' "$message" >&2
    exit 1
  fi
}

for section in \
  'cgroup/connect4' 'cgroup/connect6' \
  'cgroup/sendmsg4' 'cgroup/sendmsg6' \
  'cgroup_skb/ingress' 'cgroup_skb/egress'
do
  require "SEC\\(\"$section\"\\)" "$source_file" "missing hook $section"
done

require 'NOSH_EGRESS_MAP_ABI 2' "$header_file" 'map ABI is not pinned'
require 'NOSH_EGRESS_PROGRAM_ABI 2' "$header_file" 'program ABI is not pinned'
require 'NOSH_EGRESS_SCHEMA_VERSION 2' "$header_file" \
  'evidence schema ABI is not pinned'
require 'task_config_is_valid' "$source_file" 'sock-address identity check missing'
require 'config_is_valid\(config\)' "$source_file" \
  'packet hook base validation missing'
require 'lookup_containment\(config->policy_generation' "$source_file" \
  'exact platform containment lookup is missing'
require 'containment_deny' "$source_file" \
  'mode-independent platform containment denial is missing'
require 'config->containment_loaded' "$source_file" \
  'containment map readiness gate is missing'
reject 'invariant_denied' "$source_file" \
  'hardcoded special-use address denial remains'
reject 'remote_port == 853|port == 853' "$source_file" \
  'hardcoded DoT denial remains'
require 'coverage_decision' "$source_file" \
  'mode-aware known-destination coverage handling is missing'
require 'NOSH_EGRESS_PACKET_HIDDEN_DESTINATION' "$source_file" \
  'hidden-destination fail-closed classification is missing'
require 'NOSH_EGRESS_REASON_UNKNOWN_DESTINATION' "$source_file" \
  'unknown-destination fail-closed classification is missing'
require 'observe_response = matched \|\| config->mode == NOSH_EGRESS_MODE_LEARN \|\|' \
  "$source_file" 'unmatched learn and audit DNS response tracking is missing'
require 'matched = config->mode != NOSH_EGRESS_MODE_LEARN' "$source_file" \
  'learn mode still classifies DNS through candidate domain rules'
require 'if \(config->mode == NOSH_EGRESS_MODE_LEARN\)\n    return finish_decision' \
  "$source_file" 'learn mode does not bypass ordinary candidate policy'
reject 'value->rule_count = 1' "$source_file" \
  'learn still synthesizes DNS authority'
require 'NOSH_EGRESS_EVENT_DNS_ANSWER' "$source_file" \
  'explicit DNS answer evidence is missing'
require 'reason == NOSH_EGRESS_REASON_DNS_ANSWER \|\|\n      reason == NOSH_EGRESS_REASON_DNS_QUERY_OBSERVED' \
  "$source_file" 'DNS query observations are not classified separately'
require 'emit_dns_answer_record' "$source_file" \
  'DNS answer name/address correlation is missing'
require 'Authenticated NXDOMAIN, NODATA, and CNAME-only replies' \
  "$source_file" 'negative DNS response delivery contract missing'
require 'NOSH_EGRESS_DOMAIN_RULE_SLOTS 8' "$header_file" \
  'bounded domain rule slots missing'
require 'wildcard_one_label_suffix_length' "$source_file" \
  'single-label wildcard matching contract missing'
require '__sync_val_compare_and_swap\(&existing->expires_ns' "$source_file" \
  'maximum unexpired DNS grant merge missing'
require 'NOSH_EGRESS_DNS_TCP_MAX_MESSAGE' "$source_file" \
  'bounded TCP DNS framing missing'
require 'packet->l4_offset \+ udp_length != network_length' "$source_file" \
  'UDP length framing validation missing'
require 'packet->payload_length != \(__u32\)message_length \+ 2' "$source_file" \
  'TCP DNS single-frame validation missing'
require 'parse_compressed_dns_name' "$source_file" \
  'bounded DNS CNAME parsing missing'
require 'dns_response_scratch' "$source_file" \
  'validate-before-commit DNS response staging missing'
require 'static __noinline int handle_dns_query' "$source_file" \
  'query parser must retain a separate bounded BPF stack frame'
require 'static __noinline int handle_dns_response' "$source_file" \
  'response parser must retain a separate bounded BPF stack frame'
require 'name = \(struct nosh_dns_name \*\)name_storage' "$source_file" \
  'query name must use per-CPU scratch instead of the BPF stack'
require 'question = \(struct nosh_dns_name \*\)name_storage' "$source_file" \
  'response name must use per-CPU scratch instead of the BPF stack'
require 'static __always_inline void clear_dns_name' "$source_file" \
  'DNS names do not use the clang-14-safe clear helper'
require 'volatile __u8 \*bytes = \(volatile __u8 \*\)name' "$source_file" \
  'DNS name clearing can be folded back into an unsupported memset'
require 'for \(index = 0; index < sizeof\(\*name\); index\+\+\)' \
  "$source_file" 'DNS name clear helper does not initialize the full object'
reject '__builtin_memset\(name, 0, sizeof\(\*name\)\)' "$source_file" \
  '129-byte DNS name memset is unsupported by clang 14 BPF'
if [[ $(grep -Ec 'clear_dns_name\(name\)' "$source_file") -ne 2 ]]; then
  printf '%s\n' \
    'nosh-egress static test: both DNS name parsers must use the safe clear helper' \
    >&2
  exit 1
fi
require '_Static_assert\(sizeof\(struct nosh_egress_dns_response_scratch\)' \
  "$source_file" 'query scratch size guard missing'
require 'struct nosh_egress_domain_key \*\)name_storage' "$source_file" \
  'domain lookup key must use per-CPU scratch instead of the BPF stack'
require '_Static_assert\(sizeof\(struct nosh_egress_dns_tx_value\)' \
  "$source_file" 'response scratch size guard missing'
require 'cname_offset != data_offset \+ data_length' "$source_file" \
  'exact CNAME RDATA consumption missing'
require 'type != transaction->question_type' "$source_file" \
  'DNS answer family binding missing'
require 'scratch->cname_ttl < ttl' "$source_file" \
  'CNAME TTL cap missing'
require 'required_ipv6_ndp' "$source_file" \
  'narrow IPv6 Neighbor Discovery exception missing'
require 'required_ipv6_error' "$source_file" \
  'IPv6 control-error delivery exception missing'
require 'containment_value && required_control' "$source_file" \
  'exact gateway containment blocks required IPv6 control plumbing'
require 'NOSH_EGRESS_IPV6_MAX_EXTENSION_HEADERS' "$source_file" \
  'bounded IPv6 extension parsing missing'
require 'NOSH_EGRESS_STAT_UNSUPPORTED_PROTOCOL' "$source_file" \
  'unsupported IP protocol coverage accounting missing'
require 'output_slot = transaction->rule_count' "$source_file" \
  'exact and wildcard domain rule union missing'
require 'NOSH_EGRESS_SELECTOR_ICMP_TYPE' "$source_file" \
  'ICMP type selector enforcement missing'
require 'parse_icmp_selector' "$loader_file" \
  'ICMP selector manifest validation missing'
require 'O_RDONLY \| O_CLOEXEC \| O_NOFOLLOW' "$loader_file" \
  'no-follow manifest open missing'
require 'metadata.st_uid != 0' \
  "$loader_file" 'trusted manifest metadata validation missing'
require 'sha256_update\(&hash, line, \(size_t\)length\)' "$loader_file" \
  'exact manifest byte hashing missing'
require 'strcmp\(digest_text, expected_digest\)' "$loader_file" \
  'manifest digest comparison missing'
require 'NOSH_EGRESS_OBJECT_DIGEST' "$loader_file" \
  'embedded object digest missing'
require 'sha256sum \$\(BPF_OBJECT\)' "$make_file" \
  'object digest build step missing'
require 'collector stopped; pinned enforcement remains active' "$loader_file" \
  'persistent pin lifecycle missing'
require 'status\|snapshot\|detach --pin-root ABS' "$loader_file" \
  'pinned lifecycle CLI missing'
require 'BPF_FS_MAGIC' "$loader_file" 'bpffs filesystem attestation missing'
require '#define MAP_COUNT 12' "$loader_file" \
  'pinned containment and response-staging map contract missing'
require 'struct bpf_map \*containment' "$test_skeleton" \
  'loader syntax skeleton is missing the containment map'
require 'struct bpf_map \*dns_response_scratch' "$test_skeleton" \
  'loader syntax skeleton is missing DNS response scratch'
require 'NOSH_EGRESS_POLICY_V2' "$loader_file" \
  'v2 policy manifest parser missing'
require 'prefix != 32' "$loader_file" \
  'IPv4 containment is not exact-only'
require 'prefix != 128' "$loader_file" \
  'IPv6 containment is not exact-only'
require 'containment_digest' "$loader_file" \
  'containment identity digest is missing'
require 'decisionClass' "$loader_file" \
  'stable decision class evidence is missing'
require 'enforcementApplied' "$loader_file" \
  'enforcement-applied evidence is missing'
require 'containmentId' "$loader_file" \
  'containment identity evidence is missing'
require 'recordKind.*dns-answer' "$loader_file" \
  'DNS answer JSON record is missing'
require 'NOSH_EGRESS_DNS_MAX_LABELS - 1' "$loader_file" \
  'loader wildcard label-depth validation missing'

printf 'nosh-egress static tests: ok\n'
