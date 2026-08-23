// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#ifndef NOSH_EGRESS_H
#define NOSH_EGRESS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define NOSH_EGRESS_SCHEMA_VERSION 2
#define NOSH_EGRESS_MAP_ABI 2
#define NOSH_EGRESS_PROGRAM_ABI 2
#define NOSH_EGRESS_CONFIG_MAGIC 0x4e534547U
#define NOSH_EGRESS_ADDRESS_LEN 16
#define NOSH_EGRESS_DOMAIN_LEN 128
#define NOSH_EGRESS_RINGBUF_BYTES (8 * 1024 * 1024)
#define NOSH_EGRESS_STATIC_V4_MAX 16384
#define NOSH_EGRESS_STATIC_V6_MAX 16384
#define NOSH_EGRESS_DOMAIN_MAX 8192
#define NOSH_EGRESS_RESOLVER_MAX 32
#define NOSH_EGRESS_GRANT_MAX 65536
#define NOSH_EGRESS_DNS_TX_MAX 32768
#define NOSH_EGRESS_DOMAIN_RULE_SLOTS 8
#define NOSH_EGRESS_DNS_ANSWER_SLOTS 8
#define NOSH_EGRESS_DNS_MAX_LABELS 16
#define NOSH_EGRESS_DIGEST_LEN 72
#define NOSH_EGRESS_IDENTITY_LEN 128
#define NOSH_EGRESS_CONTAINMENT_MAX 64
#define NOSH_EGRESS_CONTAINMENT_ID_LEN 64

enum nosh_egress_mode {
  NOSH_EGRESS_MODE_UNSPECIFIED = 0,
  NOSH_EGRESS_MODE_LEARN = 1,
  NOSH_EGRESS_MODE_AUDIT = 2,
  NOSH_EGRESS_MODE_ENFORCE = 3,
};

enum nosh_egress_family {
  NOSH_EGRESS_FAMILY_UNSPECIFIED = 0,
  NOSH_EGRESS_FAMILY_IPV4 = 4,
  NOSH_EGRESS_FAMILY_IPV6 = 6,
};

enum nosh_egress_protocol {
  NOSH_EGRESS_PROTOCOL_ANY = 0,
  NOSH_EGRESS_PROTOCOL_ICMP = 1,
  NOSH_EGRESS_PROTOCOL_TCP = 6,
  NOSH_EGRESS_PROTOCOL_UDP = 17,
  NOSH_EGRESS_PROTOCOL_ICMPV6 = 58,
};

enum nosh_egress_hook {
  NOSH_EGRESS_HOOK_CONNECT4 = 1,
  NOSH_EGRESS_HOOK_CONNECT6 = 2,
  NOSH_EGRESS_HOOK_SENDMSG4 = 3,
  NOSH_EGRESS_HOOK_SENDMSG6 = 4,
  NOSH_EGRESS_HOOK_INGRESS = 5,
  NOSH_EGRESS_HOOK_EGRESS = 6,
};

enum nosh_egress_verdict {
  NOSH_EGRESS_VERDICT_ALLOW = 1,
  NOSH_EGRESS_VERDICT_WOULD_DENY = 2,
  NOSH_EGRESS_VERDICT_DENY = 3,
};

enum nosh_egress_event_kind {
  NOSH_EGRESS_EVENT_DECISION = 1,
  NOSH_EGRESS_EVENT_DNS_ANSWER = 2,
};

enum nosh_egress_decision_class {
  NOSH_EGRESS_DECISION_POLICY_ALLOW = 1,
  NOSH_EGRESS_DECISION_OBSERVED = 2,
  NOSH_EGRESS_DECISION_WOULD_DENY = 3,
  NOSH_EGRESS_DECISION_POLICY_DENY = 4,
  NOSH_EGRESS_DECISION_CONTAINMENT_DENY = 5,
  NOSH_EGRESS_DECISION_COVERAGE_GAP = 6,
  NOSH_EGRESS_DECISION_BACKEND_DENY = 7,
  NOSH_EGRESS_DECISION_INFRASTRUCTURE_ALLOW = 8,
  NOSH_EGRESS_DECISION_DNS_OBSERVATION = 9,
};

enum nosh_egress_reason {
  NOSH_EGRESS_REASON_STATIC = 1,
  NOSH_EGRESS_REASON_DNS_RESOLVER = 2,
  NOSH_EGRESS_REASON_DNS_GRANT = 3,
  NOSH_EGRESS_REASON_LEARN = 4,
  NOSH_EGRESS_REASON_DEFAULT_DENY = 5,
  NOSH_EGRESS_REASON_CONFIG_INVALID = 6,
  NOSH_EGRESS_REASON_PARSE_ERROR = 7,
  NOSH_EGRESS_REASON_FRAGMENT = 8,
  NOSH_EGRESS_REASON_DNS_DOMAIN_DENY = 9,
  NOSH_EGRESS_REASON_DNS_RESPONSE_DENY = 10,
  NOSH_EGRESS_REASON_UNSUPPORTED = 11,
  NOSH_EGRESS_REASON_IPV6_CONTROL = 12,
  NOSH_EGRESS_REASON_CONTAINMENT = 13,
  NOSH_EGRESS_REASON_HIDDEN_DESTINATION = 14,
  NOSH_EGRESS_REASON_UNKNOWN_DESTINATION = 15,
  NOSH_EGRESS_REASON_DNS_ANSWER = 16,
  NOSH_EGRESS_REASON_DNS_QUERY_OBSERVED = 17,
  NOSH_EGRESS_REASON_DNS_RESPONSE = 18,
};

enum nosh_egress_stat {
  NOSH_EGRESS_STAT_ALLOWED = 0,
  NOSH_EGRESS_STAT_WOULD_DENY = 1,
  NOSH_EGRESS_STAT_DENIED = 2,
  NOSH_EGRESS_STAT_RINGBUF_DROPS = 3,
  NOSH_EGRESS_STAT_PARSE_ERRORS = 4,
  NOSH_EGRESS_STAT_FRAGMENTS = 5,
  NOSH_EGRESS_STAT_CONFIG_INVALID = 6,
  NOSH_EGRESS_STAT_POLICY_MISS = 7,
  NOSH_EGRESS_STAT_DNS_QUERIES = 8,
  NOSH_EGRESS_STAT_DNS_RESPONSES = 9,
  NOSH_EGRESS_STAT_DNS_TX_MISS = 10,
  NOSH_EGRESS_STAT_DNS_GRANT_UPDATES = 11,
  NOSH_EGRESS_STAT_DNS_GRANT_FAILURES = 12,
  NOSH_EGRESS_STAT_DNS_UNSUPPORTED = 13,
  NOSH_EGRESS_STAT_UNSUPPORTED_PROTOCOL = 14,
  NOSH_EGRESS_STAT_COVERAGE_ALLOWED = 15,
  NOSH_EGRESS_STAT_COVERAGE_WOULD_DENY = 16,
  NOSH_EGRESS_STAT_COVERAGE_DENIED = 17,
  NOSH_EGRESS_STAT_CONTAINMENT_DENIED = 18,
  NOSH_EGRESS_STAT_BACKEND_DENIED = 19,
  NOSH_EGRESS_STAT_DNS_ANSWERS = 20,
  NOSH_EGRESS_STAT_MAX = 21,
};

enum nosh_egress_domain_flags {
  NOSH_EGRESS_DOMAIN_WILDCARD = 1U << 0,
};

enum nosh_egress_selector_flags {
  NOSH_EGRESS_SELECTOR_ICMP_TYPE = 1U << 0,
  NOSH_EGRESS_SELECTOR_ICMP_CODE = 1U << 1,
};

struct nosh_egress_config {
  __u64 target_cgroup_id;
  __u64 policy_generation;
  __u32 magic;
  __u16 map_abi;
  __u16 program_abi;
  __u8 mode;
  __u8 policy_loaded;
  __u8 containment_loaded;
  __u8 reserved[5];
};

struct nosh_egress_identity {
  char policy_digest[NOSH_EGRESS_DIGEST_LEN];
  char object_digest[NOSH_EGRESS_DIGEST_LEN];
  char run_id[NOSH_EGRESS_IDENTITY_LEN];
  char image_digest[NOSH_EGRESS_IDENTITY_LEN];
  char workspace_key[NOSH_EGRESS_IDENTITY_LEN];
  char containment_digest[NOSH_EGRESS_DIGEST_LEN];
  __u32 containment_count;
  __u8 reserved[4];
};

struct nosh_egress_containment_key {
  __u32 generation;
  __u8 family;
  __u8 reserved[3];
  __u8 address[NOSH_EGRESS_ADDRESS_LEN];
};

struct nosh_egress_containment_value {
  __u32 generation;
  __u8 id_length;
  __u8 reserved[3];
  char id[NOSH_EGRESS_CONTAINMENT_ID_LEN];
};

/* generation+protocol+port are an exact 64-bit LPM prefix. */
struct nosh_egress_v4_lpm_key {
  __u32 prefixlen;
  __u32 generation;
  __u8 protocol;
  __u8 selector_flags;
  __u16 selector;
  __u32 address;
};

struct nosh_egress_v6_lpm_key {
  __u32 prefixlen;
  __u32 generation;
  __u8 protocol;
  __u8 selector_flags;
  __u16 selector;
  __u8 address[NOSH_EGRESS_ADDRESS_LEN];
};

struct nosh_egress_rule_value {
  __u32 generation;
  __u32 rule_id;
};

struct nosh_egress_resolver_key {
  __u32 generation;
  __u8 family;
  __u8 reserved[3];
  __u8 address[NOSH_EGRESS_ADDRESS_LEN];
};

/* Domain bytes are reversed so wildcard suffixes become LPM prefixes. */
struct nosh_egress_domain_key {
  __u32 prefixlen;
  __u32 generation;
  __u8 wildcard;
  __u8 slot;
  __u8 reserved[2];
  __u8 reversed_name[NOSH_EGRESS_DOMAIN_LEN];
};

struct nosh_egress_domain_value {
  __u32 generation;
  __u32 rule_id;
  __u16 port;
  __u8 protocol;
  __u8 flags;
  __u8 name_length;
  __u8 reserved[3];
};

struct nosh_egress_grant_key {
  __u32 generation;
  __u16 port;
  __u8 family;
  __u8 protocol;
  __u8 address[NOSH_EGRESS_ADDRESS_LEN];
};

struct nosh_egress_grant_value {
  __u64 expires_ns;
  __u32 rule_id;
  __u32 attribution;
};

struct nosh_egress_dns_tx_key {
  __u32 generation;
  __u16 client_port;
  __u16 transaction_id;
  __u8 family;
  __u8 transport;
  __u8 reserved[2];
  __u8 resolver[NOSH_EGRESS_ADDRESS_LEN];
};

struct nosh_egress_dns_tx_value {
  __u64 expires_ns;
  __u16 question_type;
  __u8 question_length;
  __u8 rule_count;
  __u8 reserved[4];
  __u32 rule_ids[NOSH_EGRESS_DOMAIN_RULE_SLOTS];
  __u16 ports[NOSH_EGRESS_DOMAIN_RULE_SLOTS];
  __u8 protocols[NOSH_EGRESS_DOMAIN_RULE_SLOTS];
  char question[NOSH_EGRESS_DOMAIN_LEN];
  __u8 alias_length;
  __u8 reserved_alias[7];
  char alias[NOSH_EGRESS_DOMAIN_LEN];
};

struct nosh_egress_dns_answer {
  __u32 ttl;
  __u8 family;
  __u8 reserved[3];
  __u8 address[NOSH_EGRESS_ADDRESS_LEN];
};

/*
 * A response is parsed completely into this per-CPU staging area before any
 * dynamic authorization map is changed.  This prevents an early valid RR in
 * a later-malformed response from leaving a usable grant behind.
 */
struct nosh_egress_dns_response_scratch {
  __u32 cname_ttl;
  __u8 answer_count;
  __u8 cname_seen;
  __u8 reserved[2];
  struct nosh_egress_dns_answer answers[NOSH_EGRESS_DNS_ANSWER_SLOTS];
};

struct nosh_egress_event {
  __u64 timestamp_ns;
  __u64 cgroup_id;
  __u64 policy_generation;
  __u64 expires_ns;
  __u32 pid;
  __u32 rule_id;
  __u32 packet_len;
  __u16 schema_version;
  __u16 event_size;
  __u16 source_port;
  __u16 destination_port;
  __u16 transaction_id;
  __u16 dns_record_type;
  __u8 event_kind;
  __u8 hook;
  __u8 family;
  __u8 protocol;
  __u8 verdict;
  __u8 reason;
  __u8 decision_class;
  __u8 enforcement_applied;
  __u8 domain_length;
  __u8 containment_id_length;
  __u8 reserved[2];
  __u8 source_address[NOSH_EGRESS_ADDRESS_LEN];
  __u8 destination_address[NOSH_EGRESS_ADDRESS_LEN];
  char domain[NOSH_EGRESS_DOMAIN_LEN];
  char containment_id[NOSH_EGRESS_CONTAINMENT_ID_LEN];
};

#endif
