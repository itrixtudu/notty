// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "include/nosh_egress.h"

#define NOSH_EGRESS_HDR_START_NET 1
#define NOSH_EGRESS_DNS_HEADER_LEN 12
#define NOSH_EGRESS_DNS_MAX_ANSWERS NOSH_EGRESS_DNS_ANSWER_SLOTS
#define NOSH_EGRESS_DNS_TCP_MAX_MESSAGE 4096
#define NOSH_EGRESS_DNS_TX_TTL_NS (30ULL * 1000000000ULL)
#define NOSH_EGRESS_DNS_GRANT_MAX_TTL 300U
#define NOSH_EGRESS_IPV4_FRAGMENT_MASK 0x3fff
#define NOSH_EGRESS_IPV6_HOP_BY_HOP 0
#define NOSH_EGRESS_IPV6_ROUTING 43
#define NOSH_EGRESS_IPV6_FRAGMENT 44
#define NOSH_EGRESS_IPV6_AH 51
#define NOSH_EGRESS_IPV6_DESTINATION_OPTIONS 60
#define NOSH_EGRESS_IPV6_MAX_EXTENSION_HEADERS 4
#define NOSH_EGRESS_PACKET_PARSE_ERROR -1
#define NOSH_EGRESS_PACKET_UNSUPPORTED -2
#define NOSH_EGRESS_PACKET_HIDDEN_DESTINATION -3

struct nosh_ipv4_header {
  __u8 version_ihl;
  __u8 tos;
  __be16 total_length;
  __be16 identification;
  __be16 fragment_offset;
  __u8 ttl;
  __u8 protocol;
  __be16 checksum;
  __be32 source;
  __be32 destination;
};

struct nosh_ipv6_header {
  __be32 version_flow;
  __be16 payload_length;
  __u8 next_header;
  __u8 hop_limit;
  __u8 source[16];
  __u8 destination[16];
};

struct nosh_ipv6_extension_header {
  __u8 next_header;
  __u8 length;
};

struct nosh_ports {
  __be16 source;
  __be16 destination;
};

struct nosh_udp_header {
  __be16 source;
  __be16 destination;
  __be16 length;
  __be16 checksum;
};

struct nosh_tcp_header {
  __be16 source;
  __be16 destination;
  __be32 sequence;
  __be32 acknowledgement;
  __u8 data_offset;
  __u8 flags;
  __be16 window;
  __be16 checksum;
  __be16 urgent;
};

struct nosh_dns_header {
  __be16 transaction_id;
  __be16 flags;
  __be16 questions;
  __be16 answers;
  __be16 authorities;
  __be16 additionals;
};

struct nosh_dns_rr_fixed {
  __be16 type;
  __be16 class;
  __be32 ttl;
  __be16 data_length;
};

struct nosh_packet {
  __u32 network_length;
  __u32 l4_offset;
  __u32 payload_offset;
  __u32 payload_length;
  __u16 source_port;
  __u16 destination_port;
  __u8 family;
  __u8 protocol;
  __u8 fragmented;
  __u8 icmp_type;
  __u8 icmp_code;
  __u8 hop_limit;
  __u8 address_known;
  __u8 source[16];
  __u8 destination[16];
};

struct nosh_dns_name {
  __u8 length;
  char bytes[NOSH_EGRESS_DOMAIN_LEN];
};

_Static_assert(sizeof(struct nosh_egress_dns_response_scratch) >=
               sizeof(struct nosh_dns_name),
               "DNS response scratch must hold one parsed name");
_Static_assert(sizeof(struct nosh_egress_dns_response_scratch) >=
               sizeof(struct nosh_egress_domain_key),
               "DNS response scratch must hold one domain lookup key");
_Static_assert(sizeof(struct nosh_egress_dns_tx_value) >=
               sizeof(struct nosh_dns_name),
               "DNS transaction scratch must hold one parsed name");

/*
 * This 129-byte object exceeds Clang 14 BPF's 128-store memset expansion
 * limit when addressed at its natural byte alignment.  Keep the bounded
 * volatile loop intact so LLVM cannot fold it back into an unsupported
 * memset call.
 */
static __always_inline void clear_dns_name(struct nosh_dns_name *name)
{
  volatile __u8 *bytes = (volatile __u8 *)name;
  __u32 index;

#pragma clang loop unroll(disable)
  for (index = 0; index < sizeof(*name); index++)
    bytes[index] = 0;
}

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct nosh_egress_config);
} session_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct nosh_egress_identity);
} policy_identity SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NOSH_EGRESS_CONTAINMENT_MAX);
  __type(key, struct nosh_egress_containment_key);
  __type(value, struct nosh_egress_containment_value);
} containment SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, NOSH_EGRESS_STATIC_V4_MAX);
  __type(key, struct nosh_egress_v4_lpm_key);
  __type(value, struct nosh_egress_rule_value);
} static_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, NOSH_EGRESS_STATIC_V6_MAX);
  __type(key, struct nosh_egress_v6_lpm_key);
  __type(value, struct nosh_egress_rule_value);
} static_v6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, NOSH_EGRESS_DOMAIN_MAX);
  __type(key, struct nosh_egress_domain_key);
  __type(value, struct nosh_egress_domain_value);
} domain_rules SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NOSH_EGRESS_RESOLVER_MAX);
  __type(key, struct nosh_egress_resolver_key);
  __type(value, __u8);
} resolvers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, NOSH_EGRESS_GRANT_MAX);
  __type(key, struct nosh_egress_grant_key);
  __type(value, struct nosh_egress_grant_value);
} dynamic_grants SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, NOSH_EGRESS_DNS_TX_MAX);
  __type(key, struct nosh_egress_dns_tx_key);
  __type(value, struct nosh_egress_dns_tx_value);
} dns_transactions SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct nosh_egress_dns_tx_value);
} dns_transaction_scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct nosh_egress_dns_response_scratch);
} dns_response_scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, NOSH_EGRESS_STAT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NOSH_EGRESS_RINGBUF_BYTES);
} events SEC(".maps");

static __always_inline void increment_stat(enum nosh_egress_stat stat)
{
  __u32 key = stat;
  __u64 *value = bpf_map_lookup_elem(&stats, &key);

  if (value)
    *value += 1;
}

static __always_inline struct nosh_egress_config *configuration(void)
{
  __u32 key = 0;

  return bpf_map_lookup_elem(&session_config, &key);
}

static __always_inline int config_is_valid(
    const struct nosh_egress_config *config)
{
  return config && config->magic == NOSH_EGRESS_CONFIG_MAGIC &&
    config->map_abi == NOSH_EGRESS_MAP_ABI &&
    config->program_abi == NOSH_EGRESS_PROGRAM_ABI &&
    config->policy_generation && config->policy_loaded &&
    config->containment_loaded &&
    config->mode >= NOSH_EGRESS_MODE_LEARN &&
    config->mode <= NOSH_EGRESS_MODE_ENFORCE;
}

static __always_inline int task_config_is_valid(
    const struct nosh_egress_config *config)
{
  return config_is_valid(config) &&
    config->target_cgroup_id == bpf_get_current_cgroup_id();
}

static __always_inline struct nosh_egress_containment_value *
lookup_containment(__u32 generation, __u8 family,
                   const __u8 address[16])
{
  struct nosh_egress_containment_key key = {
    .generation = generation,
    .family = family,
  };

  if (family != NOSH_EGRESS_FAMILY_IPV4 &&
      family != NOSH_EGRESS_FAMILY_IPV6)
    return NULL;
  __builtin_memcpy(key.address, address, sizeof(key.address));
  return bpf_map_lookup_elem(&containment, &key);
}

static __always_inline int containment_value_is_valid(
    const struct nosh_egress_containment_value *value, __u32 generation)
{
  return value && value->generation == generation && value->id_length &&
    value->id_length < NOSH_EGRESS_CONTAINMENT_ID_LEN;
}

static __always_inline __u8 decision_class(__u8 verdict, __u8 reason)
{
  if (reason == NOSH_EGRESS_REASON_CONTAINMENT)
    return NOSH_EGRESS_DECISION_CONTAINMENT_DENY;
  if (reason == NOSH_EGRESS_REASON_CONFIG_INVALID ||
      reason == NOSH_EGRESS_REASON_HIDDEN_DESTINATION ||
      reason == NOSH_EGRESS_REASON_UNKNOWN_DESTINATION)
    return NOSH_EGRESS_DECISION_BACKEND_DENY;
  if (reason == NOSH_EGRESS_REASON_PARSE_ERROR ||
      reason == NOSH_EGRESS_REASON_FRAGMENT ||
      reason == NOSH_EGRESS_REASON_UNSUPPORTED ||
      reason == NOSH_EGRESS_REASON_DNS_RESPONSE_DENY)
    return NOSH_EGRESS_DECISION_COVERAGE_GAP;
  if (reason == NOSH_EGRESS_REASON_DNS_ANSWER ||
      reason == NOSH_EGRESS_REASON_DNS_QUERY_OBSERVED)
    return NOSH_EGRESS_DECISION_DNS_OBSERVATION;
  if (reason == NOSH_EGRESS_REASON_IPV6_CONTROL ||
      reason == NOSH_EGRESS_REASON_DNS_RESOLVER ||
      reason == NOSH_EGRESS_REASON_DNS_RESPONSE)
    return NOSH_EGRESS_DECISION_INFRASTRUCTURE_ALLOW;
  if (verdict == NOSH_EGRESS_VERDICT_WOULD_DENY)
    return NOSH_EGRESS_DECISION_WOULD_DENY;
  if (verdict == NOSH_EGRESS_VERDICT_DENY)
    return NOSH_EGRESS_DECISION_POLICY_DENY;
  if (reason == NOSH_EGRESS_REASON_STATIC ||
      reason == NOSH_EGRESS_REASON_DNS_GRANT)
    return NOSH_EGRESS_DECISION_POLICY_ALLOW;
  return NOSH_EGRESS_DECISION_OBSERVED;
}

static __always_inline void emit_record(
    const struct nosh_egress_config *config,
    __u8 hook, __u8 family, __u8 protocol,
    __u16 source_port, __u16 destination_port,
    const __u8 source[16], const __u8 destination[16],
    __u8 verdict, __u8 reason, __u32 rule_id,
    __u32 packet_len, __u16 transaction_id,
    const struct nosh_dns_name *name, __u64 expires_ns,
    __u8 event_kind, __u16 dns_record_type,
    const struct nosh_egress_containment_value *containment_value)
{
  struct nosh_egress_event *event;
  __u8 class_value = decision_class(verdict, reason);

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    increment_stat(NOSH_EGRESS_STAT_RINGBUF_DROPS);
    return;
  }
  __builtin_memset(event, 0, sizeof(*event));
  event->timestamp_ns = bpf_ktime_get_ns();
  event->cgroup_id = config ? config->target_cgroup_id :
    bpf_get_current_cgroup_id();
  event->policy_generation = config ? config->policy_generation : 0;
  event->expires_ns = expires_ns;
  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->rule_id = rule_id;
  event->packet_len = packet_len;
  event->schema_version = NOSH_EGRESS_SCHEMA_VERSION;
  event->event_size = sizeof(*event);
  event->source_port = source_port;
  event->destination_port = destination_port;
  event->transaction_id = transaction_id;
  event->dns_record_type = dns_record_type;
  event->event_kind = event_kind;
  event->hook = hook;
  event->family = family;
  event->protocol = protocol;
  event->verdict = verdict;
  event->reason = reason;
  event->decision_class = class_value;
  event->enforcement_applied = verdict == NOSH_EGRESS_VERDICT_DENY ||
    (config && config->mode == NOSH_EGRESS_MODE_ENFORCE &&
     class_value == NOSH_EGRESS_DECISION_POLICY_ALLOW);
  if (source)
    __builtin_memcpy(event->source_address, source, 16);
  if (destination)
    __builtin_memcpy(event->destination_address, destination, 16);
  if (name) {
    event->domain_length = name->length;
    __builtin_memcpy(event->domain, name->bytes, sizeof(event->domain));
  }
  if (containment_value &&
      containment_value->id_length < NOSH_EGRESS_CONTAINMENT_ID_LEN) {
    event->containment_id_length = containment_value->id_length;
    __builtin_memcpy(event->containment_id, containment_value->id,
                     sizeof(event->containment_id));
  }
  bpf_ringbuf_submit(event, 0);
}

static __always_inline void emit_event(
    const struct nosh_egress_config *config,
    __u8 hook, __u8 family, __u8 protocol,
    __u16 source_port, __u16 destination_port,
    const __u8 source[16], const __u8 destination[16],
    __u8 verdict, __u8 reason, __u32 rule_id,
    __u32 packet_len, __u16 transaction_id,
    const struct nosh_dns_name *name, __u64 expires_ns)
{
  emit_record(config, hook, family, protocol, source_port, destination_port,
              source, destination, verdict, reason, rule_id, packet_len,
              transaction_id, name, expires_ns, NOSH_EGRESS_EVENT_DECISION,
              0, NULL);
}

static __always_inline int finish_decision(
    const struct nosh_egress_config *config, int authorized,
    __u8 hook, __u8 family, __u8 protocol,
    __u16 source_port, __u16 destination_port,
    const __u8 source[16], const __u8 destination[16],
    __u8 reason, __u32 rule_id, __u32 packet_len)
{
  __u8 verdict;
  int result;

  if (!config_is_valid(config)) {
    increment_stat(NOSH_EGRESS_STAT_CONFIG_INVALID);
    increment_stat(NOSH_EGRESS_STAT_BACKEND_DENIED);
    emit_event(config, hook, family, protocol, source_port,
               destination_port, source, destination,
               NOSH_EGRESS_VERDICT_DENY,
               NOSH_EGRESS_REASON_CONFIG_INVALID, 0, packet_len, 0,
               NULL, 0);
    return 0;
  }

  if (authorized || config->mode == NOSH_EGRESS_MODE_LEARN) {
    verdict = NOSH_EGRESS_VERDICT_ALLOW;
    result = 1;
    increment_stat(NOSH_EGRESS_STAT_ALLOWED);
    if (!authorized)
      reason = NOSH_EGRESS_REASON_LEARN;
  } else if (config->mode == NOSH_EGRESS_MODE_AUDIT) {
    verdict = NOSH_EGRESS_VERDICT_WOULD_DENY;
    result = 1;
    increment_stat(NOSH_EGRESS_STAT_WOULD_DENY);
  } else {
    verdict = NOSH_EGRESS_VERDICT_DENY;
    result = 0;
    increment_stat(NOSH_EGRESS_STAT_DENIED);
  }
  if (!authorized)
    increment_stat(NOSH_EGRESS_STAT_POLICY_MISS);
  emit_event(config, hook, family, protocol, source_port,
             destination_port, source, destination, verdict, reason,
             rule_id, packet_len, 0, NULL, 0);
  return result;
}

/* Backend identity and hidden/unknown destinations stay fail closed. */
static __always_inline int force_deny(
    const struct nosh_egress_config *config,
    __u8 hook, __u8 family, __u8 protocol,
    __u16 source_port, __u16 destination_port,
    const __u8 source[16], const __u8 destination[16],
    __u8 reason, __u32 rule_id, __u32 packet_len)
{
  increment_stat(NOSH_EGRESS_STAT_DENIED);
  increment_stat(NOSH_EGRESS_STAT_BACKEND_DENIED);
  emit_event(config, hook, family, protocol, source_port,
             destination_port, source, destination,
             NOSH_EGRESS_VERDICT_DENY, reason, rule_id,
             packet_len, 0, NULL, 0);
  return 0;
}

static __always_inline int containment_deny(
    const struct nosh_egress_config *config,
    __u8 hook, __u8 family, __u8 protocol,
    __u16 source_port, __u16 destination_port,
    const __u8 source[16], const __u8 destination[16],
    const struct nosh_egress_containment_value *containment_value,
    __u32 packet_len)
{
  increment_stat(NOSH_EGRESS_STAT_DENIED);
  increment_stat(NOSH_EGRESS_STAT_CONTAINMENT_DENIED);
  emit_record(config, hook, family, protocol, source_port, destination_port,
              source, destination, NOSH_EGRESS_VERDICT_DENY,
              NOSH_EGRESS_REASON_CONTAINMENT, 0, packet_len, 0, NULL, 0,
              NOSH_EGRESS_EVENT_DECISION, 0, containment_value);
  return 0;
}

static __always_inline int coverage_decision(
    const struct nosh_egress_config *config,
    __u8 hook, __u8 family, __u8 protocol,
    __u16 source_port, __u16 destination_port,
    const __u8 source[16], const __u8 destination[16],
    __u8 reason, __u32 packet_len)
{
  __u8 verdict;
  int result;

  if (!config_is_valid(config))
    return force_deny(config, hook, family, protocol, source_port,
                      destination_port, source, destination,
                      NOSH_EGRESS_REASON_CONFIG_INVALID, 0, packet_len);
  if (config->mode == NOSH_EGRESS_MODE_LEARN) {
    verdict = NOSH_EGRESS_VERDICT_ALLOW;
    result = 1;
    increment_stat(NOSH_EGRESS_STAT_ALLOWED);
    increment_stat(NOSH_EGRESS_STAT_COVERAGE_ALLOWED);
  } else if (config->mode == NOSH_EGRESS_MODE_AUDIT) {
    verdict = NOSH_EGRESS_VERDICT_WOULD_DENY;
    result = 1;
    increment_stat(NOSH_EGRESS_STAT_WOULD_DENY);
    increment_stat(NOSH_EGRESS_STAT_COVERAGE_WOULD_DENY);
  } else {
    verdict = NOSH_EGRESS_VERDICT_DENY;
    result = 0;
    increment_stat(NOSH_EGRESS_STAT_DENIED);
    increment_stat(NOSH_EGRESS_STAT_COVERAGE_DENIED);
  }
  emit_event(config, hook, family, protocol, source_port, destination_port,
             source, destination, verdict, reason, 0, packet_len, 0,
             NULL, 0);
  return result;
}

static __always_inline struct nosh_egress_rule_value *lookup_static4_one(
    __u32 generation, __u8 protocol, __u8 selector_flags,
    __u16 selector, __u32 address)
{
  struct nosh_egress_v4_lpm_key key = {
    .prefixlen = 96,
    .generation = generation,
    .protocol = protocol,
    .selector_flags = selector_flags,
    .selector = selector,
    .address = address,
  };

  return bpf_map_lookup_elem(&static_v4, &key);
}

static __always_inline struct nosh_egress_rule_value *lookup_static4(
    __u32 generation, __u8 protocol, __u16 port,
    __u8 icmp_type, __u8 icmp_code, __u32 address)
{
  struct nosh_egress_rule_value *rule;

  if (protocol == NOSH_EGRESS_PROTOCOL_ICMP ||
      protocol == NOSH_EGRESS_PROTOCOL_ICMPV6) {
    __u16 selector = ((__u16)icmp_type << 8) | icmp_code;

    rule = lookup_static4_one(generation, protocol,
                              NOSH_EGRESS_SELECTOR_ICMP_TYPE |
                                NOSH_EGRESS_SELECTOR_ICMP_CODE,
                              selector, address);
    if (!rule)
      rule = lookup_static4_one(generation, protocol,
                                NOSH_EGRESS_SELECTOR_ICMP_TYPE,
                                (__u16)icmp_type << 8, address);
    if (!rule)
      rule = lookup_static4_one(generation, protocol,
                                NOSH_EGRESS_SELECTOR_ICMP_CODE,
                                icmp_code, address);
    if (!rule)
      rule = lookup_static4_one(generation, protocol, 0, 0, address);
    if (!rule)
      rule = lookup_static4_one(generation, NOSH_EGRESS_PROTOCOL_ANY,
                                0, 0, address);
  } else {
    rule = lookup_static4_one(generation, protocol, 0, port, address);
    if (!rule && port)
      rule = lookup_static4_one(generation, protocol, 0, 0, address);
    if (!rule)
      rule = lookup_static4_one(generation, NOSH_EGRESS_PROTOCOL_ANY,
                                0, port, address);
    if (!rule && port)
      rule = lookup_static4_one(generation, NOSH_EGRESS_PROTOCOL_ANY,
                                0, 0, address);
  }
  return rule;
}

static __always_inline struct nosh_egress_rule_value *lookup_static6_one(
    __u32 generation, __u8 protocol, __u8 selector_flags,
    __u16 selector, const __u8 address[16])
{
  struct nosh_egress_v6_lpm_key key = {
    .prefixlen = 192,
    .generation = generation,
    .protocol = protocol,
    .selector_flags = selector_flags,
    .selector = selector,
  };

  __builtin_memcpy(key.address, address, 16);
  return bpf_map_lookup_elem(&static_v6, &key);
}

static __always_inline struct nosh_egress_rule_value *lookup_static6(
    __u32 generation, __u8 protocol, __u16 port,
    __u8 icmp_type, __u8 icmp_code, const __u8 address[16])
{
  struct nosh_egress_rule_value *rule;

  if (protocol == NOSH_EGRESS_PROTOCOL_ICMP ||
      protocol == NOSH_EGRESS_PROTOCOL_ICMPV6) {
    __u16 selector = ((__u16)icmp_type << 8) | icmp_code;

    rule = lookup_static6_one(generation, protocol,
                              NOSH_EGRESS_SELECTOR_ICMP_TYPE |
                                NOSH_EGRESS_SELECTOR_ICMP_CODE,
                              selector, address);
    if (!rule)
      rule = lookup_static6_one(generation, protocol,
                                NOSH_EGRESS_SELECTOR_ICMP_TYPE,
                                (__u16)icmp_type << 8, address);
    if (!rule)
      rule = lookup_static6_one(generation, protocol,
                                NOSH_EGRESS_SELECTOR_ICMP_CODE,
                                icmp_code, address);
    if (!rule)
      rule = lookup_static6_one(generation, protocol, 0, 0, address);
    if (!rule)
      rule = lookup_static6_one(generation, NOSH_EGRESS_PROTOCOL_ANY,
                                0, 0, address);
  } else {
    rule = lookup_static6_one(generation, protocol, 0, port, address);
    if (!rule && port)
      rule = lookup_static6_one(generation, protocol, 0, 0, address);
    if (!rule)
      rule = lookup_static6_one(generation, NOSH_EGRESS_PROTOCOL_ANY,
                                0, port, address);
    if (!rule && port)
      rule = lookup_static6_one(generation, NOSH_EGRESS_PROTOCOL_ANY,
                                0, 0, address);
  }
  return rule;
}

static __always_inline int resolver_allowed(__u32 generation, __u8 family,
                                             const __u8 address[16])
{
  struct nosh_egress_resolver_key key = {
    .generation = generation,
    .family = family,
  };

  __builtin_memcpy(key.address, address, 16);
  return bpf_map_lookup_elem(&resolvers, &key) != NULL;
}

static __always_inline struct nosh_egress_grant_value *lookup_grant_one(
    __u32 generation, __u8 family, __u8 protocol, __u16 port,
    const __u8 address[16])
{
  struct nosh_egress_grant_key key = {
    .generation = generation,
    .port = port,
    .family = family,
    .protocol = protocol,
  };
  struct nosh_egress_grant_value *grant;

  __builtin_memcpy(key.address, address, 16);
  grant = bpf_map_lookup_elem(&dynamic_grants, &key);
  if (grant && grant->expires_ns <= bpf_ktime_get_ns()) {
    bpf_map_delete_elem(&dynamic_grants, &key);
    return NULL;
  }
  return grant;
}

static __always_inline struct nosh_egress_grant_value *lookup_grant(
    __u32 generation, __u8 family, __u8 protocol, __u16 port,
    const __u8 address[16])
{
  struct nosh_egress_grant_value *grant;

  grant = lookup_grant_one(generation, family, protocol, port, address);
  if (!grant && port)
    grant = lookup_grant_one(generation, family, protocol, 0, address);
  if (!grant)
    grant = lookup_grant_one(generation, family,
                             NOSH_EGRESS_PROTOCOL_ANY, port, address);
  if (!grant && port)
    grant = lookup_grant_one(generation, family,
                             NOSH_EGRESS_PROTOCOL_ANY, 0, address);
  return grant;
}

static __always_inline int load_bytes(struct __sk_buff *skb, __u32 offset,
                                      void *destination, __u32 length)
{
  return bpf_skb_load_bytes_relative(skb, offset, destination, length,
                                     NOSH_EGRESS_HDR_START_NET);
}

static __always_inline int parse_packet(struct __sk_buff *skb,
                                        struct nosh_packet *packet)
{
  __u8 first = 0;
  struct nosh_ports ports = {};
  __u32 network_length = 0;

  __builtin_memset(packet, 0, sizeof(*packet));
  if (load_bytes(skb, 0, &first, 1) < 0)
    return -1;
  if ((first >> 4) == 4) {
    struct nosh_ipv4_header header = {};
    __u16 fragment;

    if (load_bytes(skb, 0, &header, sizeof(header)) < 0 ||
        (header.version_ihl & 0x0f) < 5)
      return -1;
    packet->family = NOSH_EGRESS_FAMILY_IPV4;
    packet->protocol = header.protocol;
    packet->l4_offset = (header.version_ihl & 0x0f) * 4;
    __builtin_memcpy(packet->source, &header.source, 4);
    __builtin_memcpy(packet->destination, &header.destination, 4);
    packet->address_known = 1;
    /* Source-routing options can hide the ultimate policy destination. */
    if ((header.version_ihl & 0x0f) != 5)
      return NOSH_EGRESS_PACKET_HIDDEN_DESTINATION;
    network_length = bpf_ntohs(header.total_length);
    if (network_length < packet->l4_offset)
      return NOSH_EGRESS_PACKET_PARSE_ERROR;
    fragment = bpf_ntohs(header.fragment_offset);
    packet->fragmented = !!(fragment & NOSH_EGRESS_IPV4_FRAGMENT_MASK);
  } else if ((first >> 4) == 6) {
    struct nosh_ipv6_header header = {};
    __u8 next_header;
    __u32 offset;
    int extension_index;

    if (load_bytes(skb, 0, &header, sizeof(header)) < 0)
      return NOSH_EGRESS_PACKET_PARSE_ERROR;
    packet->family = NOSH_EGRESS_FAMILY_IPV6;
    packet->hop_limit = header.hop_limit;
    next_header = header.next_header;
    offset = sizeof(header);
    network_length = sizeof(header) + bpf_ntohs(header.payload_length);
    __builtin_memcpy(packet->source, header.source, 16);
    __builtin_memcpy(packet->destination, header.destination, 16);
    packet->address_known = 1;
    /* IPv6 jumbograms require Hop-by-Hop state v2 does not implement. */
    if (!header.payload_length)
      return NOSH_EGRESS_PACKET_UNSUPPORTED;
#pragma unroll
    for (extension_index = 0;
         extension_index < NOSH_EGRESS_IPV6_MAX_EXTENSION_HEADERS;
         extension_index++) {
      struct nosh_ipv6_extension_header extension = {};
      __u32 extension_length;

      if (next_header == NOSH_EGRESS_IPV6_FRAGMENT) {
        packet->protocol = next_header;
        packet->l4_offset = offset;
        packet->fragmented = 1;
        break;
      }
      /* Routing headers can hide the ultimate destination from policy. */
      if (next_header == NOSH_EGRESS_IPV6_ROUTING)
        return NOSH_EGRESS_PACKET_HIDDEN_DESTINATION;
      if (next_header != NOSH_EGRESS_IPV6_HOP_BY_HOP &&
          next_header != NOSH_EGRESS_IPV6_DESTINATION_OPTIONS &&
          next_header != NOSH_EGRESS_IPV6_AH) {
        packet->protocol = next_header;
        packet->l4_offset = offset;
        break;
      }
      if (network_length < offset + sizeof(extension) ||
          load_bytes(skb, offset, &extension, sizeof(extension)) < 0)
        return NOSH_EGRESS_PACKET_PARSE_ERROR;
      extension_length = next_header == NOSH_EGRESS_IPV6_AH
        ? ((__u32)extension.length + 2) * 4
        : ((__u32)extension.length + 1) * 8;
      if ((next_header == NOSH_EGRESS_IPV6_AH && extension.length < 1) ||
          extension_length < 8 ||
          network_length < offset + extension_length)
        return NOSH_EGRESS_PACKET_PARSE_ERROR;
      next_header = extension.next_header;
      offset += extension_length;
      packet->protocol = next_header;
      packet->l4_offset = offset;
    }
    if (next_header == NOSH_EGRESS_IPV6_ROUTING)
      return NOSH_EGRESS_PACKET_HIDDEN_DESTINATION;
    if (next_header == NOSH_EGRESS_IPV6_HOP_BY_HOP ||
        next_header == NOSH_EGRESS_IPV6_DESTINATION_OPTIONS ||
        next_header == NOSH_EGRESS_IPV6_AH)
      return NOSH_EGRESS_PACKET_UNSUPPORTED;
    if (next_header == NOSH_EGRESS_IPV6_FRAGMENT) {
      packet->protocol = next_header;
      packet->l4_offset = offset;
      packet->fragmented = 1;
    }
  } else {
    return NOSH_EGRESS_PACKET_PARSE_ERROR;
  }
  if (!network_length || network_length > skb->len)
    return NOSH_EGRESS_PACKET_PARSE_ERROR;
  packet->network_length = network_length;
  if (packet->fragmented)
    return 0;
  if ((packet->family == NOSH_EGRESS_FAMILY_IPV4 &&
       packet->protocol != NOSH_EGRESS_PROTOCOL_TCP &&
       packet->protocol != NOSH_EGRESS_PROTOCOL_UDP &&
       packet->protocol != NOSH_EGRESS_PROTOCOL_ICMP) ||
      (packet->family == NOSH_EGRESS_FAMILY_IPV6 &&
       packet->protocol != NOSH_EGRESS_PROTOCOL_TCP &&
       packet->protocol != NOSH_EGRESS_PROTOCOL_UDP &&
       packet->protocol != NOSH_EGRESS_PROTOCOL_ICMPV6))
    return NOSH_EGRESS_PACKET_UNSUPPORTED;
  if (packet->protocol == NOSH_EGRESS_PROTOCOL_TCP) {
    if (network_length < packet->l4_offset + sizeof(ports))
      return NOSH_EGRESS_PACKET_PARSE_ERROR;
    if (load_bytes(skb, packet->l4_offset, &ports, sizeof(ports)) < 0)
      return NOSH_EGRESS_PACKET_PARSE_ERROR;
    packet->source_port = bpf_ntohs(ports.source);
    packet->destination_port = bpf_ntohs(ports.destination);
    {
      struct nosh_tcp_header tcp = {};
      __u32 tcp_length;

      if (network_length < packet->l4_offset + sizeof(tcp) ||
          load_bytes(skb, packet->l4_offset, &tcp, sizeof(tcp)) < 0)
        return NOSH_EGRESS_PACKET_PARSE_ERROR;
      tcp_length = (__u32)(tcp.data_offset >> 4) * 4;
      if (tcp_length < sizeof(tcp))
        return NOSH_EGRESS_PACKET_PARSE_ERROR;
      packet->payload_offset = packet->l4_offset + tcp_length;
    }
    if (network_length < packet->payload_offset)
      return NOSH_EGRESS_PACKET_PARSE_ERROR;
    packet->payload_length = network_length - packet->payload_offset;
  } else if (packet->protocol == NOSH_EGRESS_PROTOCOL_UDP) {
    struct nosh_udp_header udp = {};
    __u32 udp_length;

    if (network_length < packet->l4_offset + sizeof(udp) ||
        load_bytes(skb, packet->l4_offset, &udp, sizeof(udp)) < 0)
      return NOSH_EGRESS_PACKET_PARSE_ERROR;
    udp_length = bpf_ntohs(udp.length);
    if (udp_length < sizeof(udp) ||
        packet->l4_offset + udp_length != network_length)
      return NOSH_EGRESS_PACKET_PARSE_ERROR;
    packet->source_port = bpf_ntohs(udp.source);
    packet->destination_port = bpf_ntohs(udp.destination);
    packet->payload_offset = packet->l4_offset + sizeof(udp);
    packet->payload_length = udp_length - sizeof(udp);
  } else if (packet->protocol == NOSH_EGRESS_PROTOCOL_ICMP ||
             packet->protocol == NOSH_EGRESS_PROTOCOL_ICMPV6) {
    __u8 selector[2] = {};

    if (network_length < packet->l4_offset + sizeof(selector) ||
        load_bytes(skb, packet->l4_offset, selector, sizeof(selector)) < 0)
      return NOSH_EGRESS_PACKET_PARSE_ERROR;
    packet->icmp_type = selector[0];
    packet->icmp_code = selector[1];
  }
  return 0;
}

static __always_inline int ipv6_address_equal(const __u8 left[16],
                                               const __u8 right[16])
{
  int index;

#pragma unroll
  for (index = 0; index < 16; index++) {
    if (left[index] != right[index])
      return 0;
  }
  return 1;
}

static __always_inline int ipv6_unspecified(const __u8 address[16])
{
  int index;

#pragma unroll
  for (index = 0; index < 16; index++) {
    if (address[index])
      return 0;
  }
  return 1;
}

static __always_inline int ipv6_multicast(const __u8 address[16])
{
  return address[0] == 0xff;
}

static __always_inline int ipv6_all_nodes(const __u8 address[16])
{
  int index;

  if (address[0] != 0xff || address[1] != 0x02 || address[15] != 1)
    return 0;
#pragma unroll
  for (index = 2; index < 15; index++) {
    if (address[index])
      return 0;
  }
  return 1;
}

static __always_inline int ipv6_solicited_node(
    const __u8 address[16], const __u8 target[16])
{
  int index;

  if (address[0] != 0xff || address[1] != 0x02 ||
      address[11] != 1 || address[12] != 0xff ||
      address[13] != target[13] || address[14] != target[14] ||
      address[15] != target[15])
    return 0;
#pragma unroll
  for (index = 2; index < 11; index++) {
    if (address[index])
      return 0;
  }
  return 1;
}

/*
 * Neighbor Discovery is link-local kernel plumbing required before any IPv6
 * application flow can be evaluated.  It is not a reviewer-overridable
 * application allow rule: only RFC-mandated NS/NA shapes with hop-limit 255
 * and a non-multicast target are admitted.
 */
static __always_inline int required_ipv6_ndp(
    struct __sk_buff *skb, const struct nosh_packet *packet)
{
  __u8 target[16] = {};

  if (packet->family != NOSH_EGRESS_FAMILY_IPV6 ||
      packet->protocol != NOSH_EGRESS_PROTOCOL_ICMPV6 ||
      (packet->icmp_type != 135 && packet->icmp_type != 136) ||
      packet->icmp_code || packet->hop_limit != 255 ||
      packet->network_length < packet->l4_offset + 24 ||
      load_bytes(skb, packet->l4_offset + 8, target, sizeof(target)) < 0 ||
      ipv6_unspecified(target) || ipv6_multicast(target))
    return 0;
  if (packet->icmp_type == 135) {
    if (ipv6_multicast(packet->source))
      return 0;
    return ipv6_address_equal(packet->destination, target) ||
      ipv6_solicited_node(packet->destination, target);
  }
  if (ipv6_unspecified(packet->source) || ipv6_multicast(packet->source) ||
      ipv6_unspecified(packet->destination))
    return 0;
  return !ipv6_multicast(packet->destination) ||
    ipv6_all_nodes(packet->destination);
}

/*
 * Preserve IPv6 error delivery (including Packet Too Big) without opening a
 * general link-local ingress exception.  The quoted packet must be IPv6 and
 * must name this outer destination as its original source.
 */
static __always_inline int required_ipv6_error(
    struct __sk_buff *skb, const struct nosh_packet *packet, int ingress)
{
  struct nosh_ipv6_header quoted = {};
  int code_valid = 0;

  if (!ingress || packet->family != NOSH_EGRESS_FAMILY_IPV6 ||
      packet->protocol != NOSH_EGRESS_PROTOCOL_ICMPV6 ||
      packet->icmp_type < 1 || packet->icmp_type > 4 ||
      packet->network_length < packet->l4_offset + 8 + sizeof(quoted) ||
      ipv6_unspecified(packet->source) || ipv6_multicast(packet->source) ||
      ipv6_unspecified(packet->destination) ||
      ipv6_multicast(packet->destination))
    return 0;
  if (packet->icmp_type == 1)
    code_valid = packet->icmp_code <= 7;
  else if (packet->icmp_type == 2)
    code_valid = packet->icmp_code == 0;
  else if (packet->icmp_type == 3)
    code_valid = packet->icmp_code <= 1;
  else if (packet->icmp_type == 4)
    code_valid = packet->icmp_code <= 2;
  if (!code_valid ||
      load_bytes(skb, packet->l4_offset + 8,
                 &quoted, sizeof(quoted)) < 0 ||
      (bpf_ntohl(quoted.version_flow) >> 28) != 6)
    return 0;
  return ipv6_address_equal(quoted.source, packet->destination);
}

static __always_inline int parse_dns_name(struct __sk_buff *skb,
                                          __u32 *offset,
                                          struct nosh_dns_name *name)
{
  int label_index;

  clear_dns_name(name);
#pragma clang loop unroll(disable)
  for (label_index = 0; label_index < NOSH_EGRESS_DNS_MAX_LABELS;
       label_index++) {
    __u8 label_length = 0;
    int byte_index;

    if (load_bytes(skb, *offset, &label_length, 1) < 0)
      return -1;
    *offset += 1;
    if (!label_length)
      return name->length ? 0 : -1;
    if (label_length & 0xc0 || label_length > 63)
      return -1;
    if (name->length) {
      if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1)
        return -1;
      name->bytes[name->length++] = '.';
    }
#pragma clang loop unroll(disable)
    for (byte_index = 0; byte_index < 63; byte_index++) {
      __u8 byte;

      if (byte_index >= label_length)
        break;
      if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1 ||
          load_bytes(skb, *offset, &byte, 1) < 0)
        return -1;
      *offset += 1;
      if (byte >= 'A' && byte <= 'Z')
        byte += 'a' - 'A';
      if ((byte < 'a' || byte > 'z') &&
          (byte < '0' || byte > '9') && byte != '-' && byte != '_')
        return -1;
      name->bytes[name->length++] = byte;
    }
  }
  return -1;
}

static __always_inline int dns_name_matches(
    const struct nosh_dns_name *name,
    const struct nosh_egress_dns_tx_value *transaction)
{
  int index;

  if (name->length != transaction->question_length)
    return 0;
#pragma clang loop unroll(disable)
  for (index = 0; index < NOSH_EGRESS_DOMAIN_LEN; index++) {
    if (index >= name->length)
      break;
    if (name->bytes[index] != transaction->question[index])
      return 0;
  }
  return 1;
}

static __always_inline int dns_message_offset(
    struct __sk_buff *skb, const struct nosh_packet *packet, __u32 *offset)
{
  __be16 framed_length = 0;
  __u16 message_length;

  if (packet->protocol == NOSH_EGRESS_PROTOCOL_UDP) {
    if (packet->payload_length < NOSH_EGRESS_DNS_HEADER_LEN)
      return -1;
    *offset = packet->payload_offset;
    return 0;
  }
  if (packet->protocol != NOSH_EGRESS_PROTOCOL_TCP ||
      packet->payload_length < 2 ||
      load_bytes(skb, packet->payload_offset, &framed_length,
                 sizeof(framed_length)) < 0)
    return -1;
  message_length = bpf_ntohs(framed_length);
  if (message_length < NOSH_EGRESS_DNS_HEADER_LEN ||
      message_length > NOSH_EGRESS_DNS_TCP_MAX_MESSAGE ||
      packet->payload_length != (__u32)message_length + 2)
    return -1;
  *offset = packet->payload_offset + 2;
  return 0;
}

static __always_inline int parse_compressed_dns_name(
    struct __sk_buff *skb, __u32 message_offset, __u32 message_end,
    __u32 *offset, struct nosh_dns_name *name)
{
  __u32 cursor = *offset;
  __u32 next = cursor;
  int jumped = 0;
  int pointers = 0;
  int label_index;

  clear_dns_name(name);
#pragma clang loop unroll(disable)
  for (label_index = 0; label_index < NOSH_EGRESS_DNS_MAX_LABELS;
       label_index++) {
    __u8 length = 0;
    int byte_index;

    if (cursor >= message_end ||
        load_bytes(skb, cursor, &length, 1) < 0)
      return -1;
    if (!length) {
      if (!jumped)
        next = cursor + 1;
      *offset = next;
      return name->length ? 0 : -1;
    }
    if ((length & 0xc0) == 0xc0) {
      __u8 second = 0;
      __u16 pointer;

      if (cursor + 1 >= message_end ||
          load_bytes(skb, cursor + 1, &second, 1) < 0 || pointers >= 2)
        return -1;
      pointer = ((__u16)(length & 0x3f) << 8) | second;
      if (pointer < NOSH_EGRESS_DNS_HEADER_LEN ||
          message_offset + pointer >= message_end)
        return -1;
      if (!jumped)
        next = cursor + 2;
      cursor = message_offset + pointer;
      jumped = 1;
      pointers++;
      continue;
    }
    if (length & 0xc0 || length > 63)
      return -1;
    cursor++;
    if ((__u32)length > message_end - cursor)
      return -1;
    if (name->length) {
      if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1)
        return -1;
      name->bytes[name->length++] = '.';
    }
#pragma clang loop unroll(disable)
    for (byte_index = 0; byte_index < 63; byte_index++) {
      __u8 byte;

      if (byte_index >= length)
        break;
      if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1 ||
          load_bytes(skb, cursor, &byte, 1) < 0)
        return -1;
      cursor++;
      if (byte >= 'A' && byte <= 'Z')
        byte += 'a' - 'A';
      if ((byte < 'a' || byte > 'z') &&
          (byte < '0' || byte > '9') && byte != '-' && byte != '_')
        return -1;
      name->bytes[name->length++] = byte;
    }
    if (!jumped)
      next = cursor;
  }
  return -1;
}

static __always_inline int dns_name_matches_alias(
    const struct nosh_dns_name *name,
    const struct nosh_egress_dns_tx_value *transaction)
{
  int index;

  if (!transaction->alias_length ||
      name->length != transaction->alias_length)
    return 0;
#pragma clang loop unroll(disable)
  for (index = 0; index < NOSH_EGRESS_DOMAIN_LEN; index++) {
    if (index >= name->length)
      break;
    if (name->bytes[index] != transaction->alias[index])
      return 0;
  }
  return 1;
}

/* Return the suffix length only when the query has one non-empty first label. */
static __always_inline int wildcard_one_label_suffix_length(
    __u8 name_length, const char name[NOSH_EGRESS_DOMAIN_LEN])
{
  int index;

  if (!name_length || name_length >= NOSH_EGRESS_DOMAIN_LEN)
    return 0;
#pragma clang loop unroll(disable)
  for (index = 0; index < NOSH_EGRESS_DOMAIN_LEN; index++) {
    if (index >= name_length)
      break;
    if (name[index] == '.') {
      if (!index || index >= name_length - 1)
        return 0;
      return (int)name_length - index - 1;
    }
  }
  return 0;
}

static __always_inline int collect_domain_rules(
    __u32 generation, __u8 name_length,
    const char name[NOSH_EGRESS_DOMAIN_LEN],
    struct nosh_egress_dns_tx_value *transaction,
    struct nosh_egress_domain_key *key)
{
  struct nosh_egress_domain_value *rule;
  int wildcard_suffix_length;
  int slot;
  int index;

  if (!name_length)
    return 0;
  __builtin_memset(key, 0, sizeof(*key));
  key->generation = generation;
#pragma clang loop unroll(disable)
  for (index = 0; index < NOSH_EGRESS_DOMAIN_LEN; index++) {
    if (index >= name_length)
      break;
    key->reversed_name[index] = name[name_length - index - 1];
  }
  key->prefixlen = 64 + (__u32)name_length * 8;
  key->wildcard = 0;
#pragma unroll
  for (slot = 0; slot < NOSH_EGRESS_DOMAIN_RULE_SLOTS; slot++) {
    int output_slot;

    key->slot = slot;
    rule = bpf_map_lookup_elem(&domain_rules, key);
    if (!rule || (rule->flags & NOSH_EGRESS_DOMAIN_WILDCARD) ||
        rule->name_length != name_length)
      break;
    output_slot = transaction->rule_count;
    if (output_slot >= NOSH_EGRESS_DOMAIN_RULE_SLOTS)
      break;
    transaction->rule_ids[output_slot] = rule->rule_id;
    transaction->ports[output_slot] = rule->port;
    transaction->protocols[output_slot] = rule->protocol;
    transaction->rule_count++;
  }

  wildcard_suffix_length = wildcard_one_label_suffix_length(name_length,
                                                             name);
  if (!wildcard_suffix_length)
    return transaction->rule_count;
  key->prefixlen = 64 + (__u32)wildcard_suffix_length * 8;
  key->wildcard = 1;
#pragma unroll
  for (slot = 0; slot < NOSH_EGRESS_DOMAIN_RULE_SLOTS; slot++) {
    int output_slot;

    key->slot = slot;
    rule = bpf_map_lookup_elem(&domain_rules, key);
    if (!rule || !(rule->flags & NOSH_EGRESS_DOMAIN_WILDCARD) ||
        rule->name_length != wildcard_suffix_length)
      break;
    output_slot = transaction->rule_count;
    if (output_slot >= NOSH_EGRESS_DOMAIN_RULE_SLOTS)
      break;
    transaction->rule_ids[output_slot] = rule->rule_id;
    transaction->ports[output_slot] = rule->port;
    transaction->protocols[output_slot] = rule->protocol;
    transaction->rule_count++;
  }
  return transaction->rule_count;
}

/*
 * Keep DNS parsing in a separate BPF stack frame.  Historically, inlining
 * both parser paths into each cgroup_skb entrypoint combined their state with
 * packet parsing and exceeded MAX_BPF_STACK.  Parsed names now live in the
 * existing per-CPU scratch maps as a second bound on stack use.  This
 * subprogram has exactly five arguments, as required by the BPF calling
 * convention, and does not change the map ABI or staged commit boundary.
 */
static __noinline int handle_dns_query(
    struct __sk_buff *skb, const struct nosh_egress_config *config,
    const struct nosh_packet *packet, __u8 hook, __u32 dns_offset)
{
  struct nosh_dns_header header = {};
  struct nosh_dns_name *name;
  struct nosh_egress_dns_tx_key key = {};
  struct nosh_egress_dns_tx_value *value;
  struct nosh_egress_dns_response_scratch *name_storage;
  __u32 scratch_key = 0;
  __u32 offset = dns_offset + NOSH_EGRESS_DNS_HEADER_LEN;
  __u16 qtype = 0;
  __u16 qclass = 0;
  __u16 txid;
  int matched;
  int observe_response;
  __u8 verdict;
  int result;

  value = bpf_map_lookup_elem(&dns_transaction_scratch, &scratch_key);
  name_storage = bpf_map_lookup_elem(&dns_response_scratch, &scratch_key);
  if (!value || !name_storage) {
    increment_stat(NOSH_EGRESS_STAT_CONFIG_INVALID);
    return force_deny(config, hook, packet->family, packet->protocol,
                      packet->source_port, packet->destination_port,
                      packet->source, packet->destination,
                      NOSH_EGRESS_REASON_CONFIG_INVALID, 0, skb->len);
  }
  __builtin_memset(value, 0, sizeof(*value));
  /*
   * This per-CPU response area is idle while parsing a query and is larger
   * than one bounded DNS name.  Reusing it avoids a 129-byte kernel-stack
   * object without adding or resizing any ABI-visible map.
   */
  name = (struct nosh_dns_name *)name_storage;

  if (load_bytes(skb, dns_offset,
                 &header, sizeof(header)) < 0 ||
      (bpf_ntohs(header.flags) & 0x8000) ||
      bpf_ntohs(header.questions) != 1 ||
      parse_dns_name(skb, &offset, name) < 0 ||
      offset > packet->payload_offset + packet->payload_length ||
      4 > packet->payload_offset + packet->payload_length - offset ||
      load_bytes(skb, offset, &qtype, 2) < 0 ||
      load_bytes(skb, offset + 2, &qclass, 2) < 0 ||
      bpf_ntohs(qclass) != 1) {
    increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
    return coverage_decision(config, hook, packet->family, packet->protocol,
                             packet->source_port, packet->destination_port,
                             packet->source, packet->destination,
                             NOSH_EGRESS_REASON_PARSE_ERROR, skb->len);
  }
  if (bpf_ntohs(qtype) != 1 && bpf_ntohs(qtype) != 28) {
    increment_stat(NOSH_EGRESS_STAT_DNS_UNSUPPORTED);
    return coverage_decision(config, hook, packet->family, packet->protocol,
                             packet->source_port, packet->destination_port,
                             packet->source, packet->destination,
                             NOSH_EGRESS_REASON_UNSUPPORTED, skb->len);
  }

  increment_stat(NOSH_EGRESS_STAT_DNS_QUERIES);
  value->question_length = name->length;
  __builtin_memcpy(value->question, name->bytes, sizeof(value->question));
  matched = config->mode != NOSH_EGRESS_MODE_LEARN &&
    collect_domain_rules(
      config->policy_generation, value->question_length, value->question,
      value, (struct nosh_egress_domain_key *)name_storage) > 0;
  observe_response = matched || config->mode == NOSH_EGRESS_MODE_LEARN ||
    config->mode == NOSH_EGRESS_MODE_AUDIT;
  txid = bpf_ntohs(header.transaction_id);
  if (observe_response) {
    key.generation = config->policy_generation;
    key.client_port = packet->source_port;
    key.transaction_id = txid;
    key.family = packet->family;
    key.transport = packet->protocol;
    __builtin_memcpy(key.resolver, packet->destination, 16);
    value->expires_ns = bpf_ktime_get_ns() + NOSH_EGRESS_DNS_TX_TTL_NS;
    value->question_type = bpf_ntohs(qtype);
    if (bpf_map_update_elem(&dns_transactions, &key, value, BPF_ANY) < 0) {
      increment_stat(NOSH_EGRESS_STAT_DNS_GRANT_FAILURES);
      bpf_map_delete_elem(&dns_transactions, &key);
      return force_deny(config, hook, packet->family, packet->protocol,
                        packet->source_port, packet->destination_port,
                        packet->source, packet->destination,
                        NOSH_EGRESS_REASON_CONFIG_INVALID, 0, skb->len);
    }
  }

  if (matched || config->mode == NOSH_EGRESS_MODE_LEARN) {
    verdict = NOSH_EGRESS_VERDICT_ALLOW;
    result = 1;
    increment_stat(NOSH_EGRESS_STAT_ALLOWED);
  } else if (config->mode == NOSH_EGRESS_MODE_AUDIT) {
    verdict = NOSH_EGRESS_VERDICT_WOULD_DENY;
    result = 1;
    increment_stat(NOSH_EGRESS_STAT_WOULD_DENY);
  } else {
    verdict = NOSH_EGRESS_VERDICT_DENY;
    result = 0;
    increment_stat(NOSH_EGRESS_STAT_DENIED);
  }
  if (!matched)
    increment_stat(NOSH_EGRESS_STAT_POLICY_MISS);
  /* collect_domain_rules reused name_storage for its LPM key. */
  name->length = value->question_length;
  __builtin_memcpy(name->bytes, value->question, sizeof(name->bytes));
  emit_event(config, hook, packet->family, packet->protocol,
             packet->source_port, packet->destination_port,
             packet->source, packet->destination, verdict,
             matched ? NOSH_EGRESS_REASON_DNS_RESOLVER :
               config->mode == NOSH_EGRESS_MODE_LEARN ?
                 NOSH_EGRESS_REASON_DNS_QUERY_OBSERVED :
                 NOSH_EGRESS_REASON_DNS_DOMAIN_DENY,
             value->rule_count ? value->rule_ids[0] : 0,
             skb->len, txid, name, 0);
  return result;
}

static __always_inline int insert_dns_grant(
    const struct nosh_egress_config *config,
    __u32 rule_id, __u8 protocol, __u16 port,
    __u8 family, const __u8 address[16], __u32 ttl, __u64 *expires_ns)
{
  struct nosh_egress_grant_key key = {
    .generation = config->policy_generation,
    .port = port,
    .family = family,
    .protocol = protocol,
  };
  struct nosh_egress_grant_value value = {
    .rule_id = rule_id,
    .attribution = rule_id,
  };
  struct nosh_egress_grant_value *existing;
  __u64 now;
  int updated = 0;
  int attempt;

  if (!ttl)
    return 1;
  if (ttl > NOSH_EGRESS_DNS_GRANT_MAX_TTL)
    ttl = NOSH_EGRESS_DNS_GRANT_MAX_TTL;
  now = bpf_ktime_get_ns();
  value.expires_ns = now + (__u64)ttl * 1000000000ULL;
  __builtin_memcpy(key.address, address, 16);
  existing = bpf_map_lookup_elem(&dynamic_grants, &key);
  if (!existing) {
    if (bpf_map_update_elem(&dynamic_grants, &key, &value, BPF_NOEXIST) == 0) {
      *expires_ns = value.expires_ns;
      increment_stat(NOSH_EGRESS_STAT_DNS_GRANT_UPDATES);
      return 0;
    }
    existing = bpf_map_lookup_elem(&dynamic_grants, &key);
    if (!existing) {
      increment_stat(NOSH_EGRESS_STAT_DNS_GRANT_FAILURES);
      return -1;
    }
  }
  /* Keep the union of concurrent grants: expiry can only move forward. */
#pragma unroll
  for (attempt = 0; attempt < 4; attempt++) {
    __u64 observed = existing->expires_ns;
    __u64 replaced;

    if (observed > now && observed >= value.expires_ns) {
      *expires_ns = observed;
      break;
    }
    replaced = __sync_val_compare_and_swap(&existing->expires_ns,
                                           observed, value.expires_ns);
    if (replaced == observed) {
      *expires_ns = value.expires_ns;
      updated = 1;
      break;
    }
  }
  if (!*expires_ns) {
    *expires_ns = existing->expires_ns;
    if (*expires_ns < value.expires_ns) {
      increment_stat(NOSH_EGRESS_STAT_DNS_GRANT_FAILURES);
      return -1;
    }
  }
  /* Stable attribution is the lowest contributing reviewed rule ID. */
#pragma unroll
  for (attempt = 0; attempt < 4; attempt++) {
    __u32 observed = existing->attribution;

    if (observed <= value.attribution)
      break;
    if (__sync_val_compare_and_swap(&existing->attribution, observed,
                                    value.attribution) == observed)
      break;
  }
  existing->rule_id = existing->attribution;
  if (updated)
    increment_stat(NOSH_EGRESS_STAT_DNS_GRANT_UPDATES);
  return 0;
}

static __always_inline void emit_dns_answer_record(
    const struct nosh_egress_config *config, __u8 hook,
    const struct nosh_packet *packet, __u16 transaction_id,
    const struct nosh_dns_name *question,
    const struct nosh_egress_dns_answer *answer)
{
  __u64 expires_ns = bpf_ktime_get_ns() +
    (__u64)answer->ttl * 1000000000ULL;
  __u16 record_type = answer->family == NOSH_EGRESS_FAMILY_IPV4 ? 1 : 28;

  increment_stat(NOSH_EGRESS_STAT_DNS_ANSWERS);
  emit_record(config, hook, packet->family, packet->protocol,
              packet->source_port, packet->destination_port,
              packet->source, answer->address, NOSH_EGRESS_VERDICT_ALLOW,
              NOSH_EGRESS_REASON_DNS_ANSWER, 0, 0, transaction_id,
              question, expires_ns, NOSH_EGRESS_EVENT_DNS_ANSWER,
              record_type, NULL);
}

static __noinline int handle_dns_response(
    struct __sk_buff *skb, const struct nosh_egress_config *config,
    const struct nosh_packet *packet, __u8 hook, __u32 dns_offset)
{
  struct nosh_dns_header header = {};
  struct nosh_dns_name *question;
  struct nosh_egress_dns_tx_key key = {};
  struct nosh_egress_dns_tx_value *transaction;
  struct nosh_egress_dns_tx_value *name_storage;
  struct nosh_egress_dns_response_scratch *scratch;
  __u32 scratch_key = 0;
  __u32 offset = dns_offset + NOSH_EGRESS_DNS_HEADER_LEN;
  __u16 qtype = 0;
  __u16 qclass = 0;
  __u16 answers;
  __u16 flags;
  __u16 txid;
  int answer_index;
  int rule_slot;
  int grants = 0;
  int response_valid = 1;
  __u8 response_gap_reason = NOSH_EGRESS_REASON_PARSE_ERROR;
  __u32 message_end = packet->payload_offset + packet->payload_length;

  name_storage = bpf_map_lookup_elem(&dns_transaction_scratch, &scratch_key);
  if (!name_storage) {
    increment_stat(NOSH_EGRESS_STAT_CONFIG_INVALID);
    return force_deny(config, hook, packet->family, packet->protocol,
                      packet->source_port, packet->destination_port,
                      packet->source, packet->destination,
                      NOSH_EGRESS_REASON_CONFIG_INVALID, 0, skb->len);
  }
  /* The per-CPU transaction scratch is not the live transaction map value. */
  question = (struct nosh_dns_name *)name_storage;

  if (load_bytes(skb, dns_offset, &header, sizeof(header)) < 0)
    goto response_parse_error;
  flags = bpf_ntohs(header.flags);
  if (!(flags & 0x8000) || (flags & 0x7800) ||
      bpf_ntohs(header.questions) != 1 ||
      parse_dns_name(skb, &offset, question) < 0 ||
      offset > packet->payload_offset + packet->payload_length ||
      4 > packet->payload_offset + packet->payload_length - offset ||
      load_bytes(skb, offset, &qtype, sizeof(qtype)) < 0 ||
      load_bytes(skb, offset + 2, &qclass, sizeof(qclass)) < 0 ||
      bpf_ntohs(qclass) != 1)
    goto response_parse_error;
  offset += 4;
  txid = bpf_ntohs(header.transaction_id);
  key.generation = config->policy_generation;
  key.client_port = packet->destination_port;
  key.transaction_id = txid;
  key.family = packet->family;
  key.transport = packet->protocol;
  __builtin_memcpy(key.resolver, packet->source, 16);
  transaction = bpf_map_lookup_elem(&dns_transactions, &key);
  if (!transaction || transaction->expires_ns <= bpf_ktime_get_ns() ||
      transaction->question_type != bpf_ntohs(qtype) ||
      !dns_name_matches(question, transaction)) {
    increment_stat(NOSH_EGRESS_STAT_DNS_TX_MISS);
    return coverage_decision(config, hook, packet->family, packet->protocol,
                             packet->source_port, packet->destination_port,
                             packet->source, packet->destination,
                             NOSH_EGRESS_REASON_DNS_RESPONSE_DENY,
                             skb->len);
  }
  if (flags & 0x0200) {
    increment_stat(NOSH_EGRESS_STAT_DNS_UNSUPPORTED);
    bpf_map_delete_elem(&dns_transactions, &key);
    return coverage_decision(config, hook, packet->family, packet->protocol,
                             packet->source_port, packet->destination_port,
                             packet->source, packet->destination,
                             NOSH_EGRESS_REASON_UNSUPPORTED, skb->len);
  }
  answers = bpf_ntohs(header.answers);
  if (answers > NOSH_EGRESS_DNS_MAX_ANSWERS) {
    increment_stat(NOSH_EGRESS_STAT_DNS_UNSUPPORTED);
    bpf_map_delete_elem(&dns_transactions, &key);
    return coverage_decision(config, hook, packet->family, packet->protocol,
                             packet->source_port, packet->destination_port,
                             packet->source, packet->destination,
                             NOSH_EGRESS_REASON_UNSUPPORTED, skb->len);
  }
  scratch = bpf_map_lookup_elem(&dns_response_scratch, &scratch_key);
  if (!scratch) {
    increment_stat(NOSH_EGRESS_STAT_CONFIG_INVALID);
    bpf_map_delete_elem(&dns_transactions, &key);
    return force_deny(config, hook, packet->family, packet->protocol,
                      packet->source_port, packet->destination_port,
                      packet->source, packet->destination,
                      NOSH_EGRESS_REASON_CONFIG_INVALID, 0, skb->len);
  }
  __builtin_memset(scratch, 0, sizeof(*scratch));

  /* First pass: validate and stage.  No dynamic grant is mutated here. */
#pragma clang loop unroll(disable)
  for (answer_index = 0; answer_index < NOSH_EGRESS_DNS_MAX_ANSWERS;
       answer_index++) {
    struct nosh_dns_rr_fixed fixed = {};
    __u16 type;
    __u16 data_length;
    __u32 ttl;
    __u8 address[16] = {};
    __u32 data_offset;
    int owner_authorized;
    int owner_is_question;
    int owner_is_alias;

    if (answer_index >= answers)
      break;
    if (parse_compressed_dns_name(skb, dns_offset, message_end,
                                  &offset, question) < 0 ||
        load_bytes(skb, offset, &fixed, sizeof(fixed)) < 0) {
      increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
      response_valid = 0;
      break;
    }
    owner_is_question = dns_name_matches(question, transaction);
    owner_is_alias = dns_name_matches_alias(question, transaction);
    owner_authorized = owner_is_question || owner_is_alias;
    offset += sizeof(fixed);
    data_offset = offset;
    type = bpf_ntohs(fixed.type);
    data_length = bpf_ntohs(fixed.data_length);
    ttl = bpf_ntohl(fixed.ttl);
    if (data_offset > message_end || data_length > message_end - data_offset) {
      increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
      response_valid = 0;
      break;
    }
    if (bpf_ntohs(fixed.class) == 1 && type == 5) {
      __u32 cname_offset = data_offset;

      if (parse_compressed_dns_name(skb, dns_offset, message_end,
                                    &cname_offset, question) < 0 ||
          cname_offset != data_offset + data_length) {
        increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
        response_valid = 0;
        break;
      }
      if (owner_authorized) {
        /* v2 supports one CNAME hop rooted at the observed question. */
        if (!owner_is_question || scratch->cname_seen ||
            scratch->answer_count) {
          increment_stat(NOSH_EGRESS_STAT_DNS_UNSUPPORTED);
          response_gap_reason = NOSH_EGRESS_REASON_UNSUPPORTED;
          response_valid = 0;
          break;
        }
        scratch->cname_seen = 1;
        scratch->cname_ttl = ttl;
        transaction->alias_length = question->length;
        __builtin_memcpy(transaction->alias, question->bytes,
                         sizeof(transaction->alias));
      }
    } else if (bpf_ntohs(fixed.class) == 1 && (type == 1 || type == 28)) {
      __u8 family = type == 1 ? NOSH_EGRESS_FAMILY_IPV4 :
        NOSH_EGRESS_FAMILY_IPV6;
      __u16 expected_length = type == 1 ? 4 : 16;

      if (data_length != expected_length ||
          load_bytes(skb, offset, address, expected_length) < 0) {
        increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
        response_valid = 0;
        break;
      }
      if (owner_authorized) {
        struct nosh_egress_dns_answer *candidate;

        if ((scratch->cname_seen && owner_is_question) ||
            type != transaction->question_type ||
            scratch->answer_count >= NOSH_EGRESS_DNS_ANSWER_SLOTS) {
          increment_stat(NOSH_EGRESS_STAT_DNS_UNSUPPORTED);
          response_gap_reason = NOSH_EGRESS_REASON_UNSUPPORTED;
          response_valid = 0;
          break;
        }
        if (!(flags & 0x000f) && ttl &&
            (!owner_is_alias || (scratch->cname_seen && scratch->cname_ttl))) {
          candidate = &scratch->answers[scratch->answer_count++];
          candidate->family = family;
          candidate->ttl = owner_is_alias && scratch->cname_ttl < ttl
            ? scratch->cname_ttl : ttl;
          __builtin_memcpy(candidate->address, address,
                           sizeof(candidate->address));
        }
      }
    }
    offset += data_length;
  }
  if (!response_valid) {
    bpf_map_delete_elem(&dns_transactions, &key);
    return coverage_decision(config, hook, packet->family, packet->protocol,
                             packet->source_port, packet->destination_port,
                             packet->source, packet->destination,
                             response_gap_reason, skb->len);
  }

  /* Second pass: the complete answer section is known-good; commit grants. */
  question->length = transaction->question_length;
  __builtin_memcpy(question->bytes, transaction->question,
                   sizeof(question->bytes));
#pragma unroll
  for (answer_index = 0; answer_index < NOSH_EGRESS_DNS_ANSWER_SLOTS;
       answer_index++) {
    struct nosh_egress_dns_answer *candidate;

    if (answer_index >= scratch->answer_count)
      break;
    candidate = &scratch->answers[answer_index];
    emit_dns_answer_record(config, hook, packet, txid, question, candidate);
    /* Defense in depth: only successful positive-TTL answers can grant. */
    if ((flags & 0x000f) || !candidate->ttl)
      continue;
#pragma unroll
    for (rule_slot = 0; rule_slot < NOSH_EGRESS_DOMAIN_RULE_SLOTS;
         rule_slot++) {
      __u64 grant_expires_ns = 0;

      if (rule_slot >= transaction->rule_count)
        break;
      if (insert_dns_grant(config, transaction->rule_ids[rule_slot],
                           transaction->protocols[rule_slot],
                           transaction->ports[rule_slot], candidate->family,
                           candidate->address, candidate->ttl,
                           &grant_expires_ns) == 0) {
        grants++;
        emit_event(config, hook, candidate->family,
                   transaction->protocols[rule_slot], 53,
                   transaction->ports[rule_slot], packet->source,
                   candidate->address, NOSH_EGRESS_VERDICT_ALLOW,
                   NOSH_EGRESS_REASON_DNS_GRANT,
                   transaction->rule_ids[rule_slot], 0, txid, question,
                   grant_expires_ns);
      }
    }
  }
  increment_stat(NOSH_EGRESS_STAT_DNS_RESPONSES);
  emit_event(config, hook, packet->family, packet->protocol,
             packet->source_port, packet->destination_port,
             packet->source, packet->destination,
             NOSH_EGRESS_VERDICT_ALLOW,
             grants ? NOSH_EGRESS_REASON_DNS_GRANT :
               NOSH_EGRESS_REASON_DNS_RESPONSE,
             transaction->rule_count ? transaction->rule_ids[0] : 0,
             skb->len, txid, question, transaction->expires_ns);
  bpf_map_delete_elem(&dns_transactions, &key);
  /* Authenticated NXDOMAIN, NODATA, and CNAME-only replies are valid DNS. */
  increment_stat(NOSH_EGRESS_STAT_ALLOWED);
  return 1;

response_parse_error:
  increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
  return coverage_decision(config, hook, packet->family, packet->protocol,
                           packet->source_port, packet->destination_port,
                           packet->source, packet->destination,
                           NOSH_EGRESS_REASON_PARSE_ERROR, skb->len);
}

static __always_inline int decide_sock_addr(struct bpf_sock_addr *ctx,
                                            __u8 family, __u8 hook)
{
  struct nosh_egress_config *config = configuration();
  struct nosh_egress_rule_value *static_rule = NULL;
  struct nosh_egress_grant_value *grant = NULL;
  struct nosh_egress_containment_value *containment_value;
  __u8 address[16] = {};
  __u8 protocol = ctx->protocol;
  __u16 port = bpf_ntohs((__u16)ctx->user_port);
  int authorized = 0;
  __u8 reason = NOSH_EGRESS_REASON_DEFAULT_DENY;
  __u32 rule_id = 0;

  if (protocol != NOSH_EGRESS_PROTOCOL_TCP &&
      protocol != NOSH_EGRESS_PROTOCOL_UDP)
    protocol = ctx->type == 1 ? NOSH_EGRESS_PROTOCOL_TCP :
      ctx->type == 2 ? NOSH_EGRESS_PROTOCOL_UDP : 0;
  if (family == NOSH_EGRESS_FAMILY_IPV4)
    __builtin_memcpy(address, &ctx->user_ip4, 4);
  else {
    __u32 word;
    volatile struct bpf_sock_addr *volatile_ctx = ctx;

    word = volatile_ctx->user_ip6[0];
    __builtin_memcpy(address, &word, 4);
    word = volatile_ctx->user_ip6[1];
    __builtin_memcpy(address + 4, &word, 4);
    word = volatile_ctx->user_ip6[2];
    __builtin_memcpy(address + 8, &word, 4);
    word = volatile_ctx->user_ip6[3];
    __builtin_memcpy(address + 12, &word, 4);
  }
  if (!task_config_is_valid(config)) {
    increment_stat(NOSH_EGRESS_STAT_CONFIG_INVALID);
    return force_deny(config, hook, family, protocol, 0, port,
                      NULL, address, NOSH_EGRESS_REASON_CONFIG_INVALID,
                      0, 0);
  }
  containment_value = lookup_containment(config->policy_generation,
                                         family, address);
  if (containment_value && !containment_value_is_valid(
      containment_value, config->policy_generation)) {
    increment_stat(NOSH_EGRESS_STAT_CONFIG_INVALID);
    return force_deny(config, hook, family, protocol, 0, port,
                      NULL, address, NOSH_EGRESS_REASON_CONFIG_INVALID,
                      0, 0);
  }
  if (containment_value)
    return containment_deny(config, hook, family, protocol, 0, port,
                            NULL, address, containment_value, 0);
  if (protocol != NOSH_EGRESS_PROTOCOL_TCP &&
      protocol != NOSH_EGRESS_PROTOCOL_UDP) {
    increment_stat(NOSH_EGRESS_STAT_UNSUPPORTED_PROTOCOL);
    return coverage_decision(config, hook, family, protocol, 0, port,
                             NULL, address, NOSH_EGRESS_REASON_UNSUPPORTED,
                             0);
  }

  if ((protocol == NOSH_EGRESS_PROTOCOL_UDP ||
       protocol == NOSH_EGRESS_PROTOCOL_TCP) && port == 53 &&
      resolver_allowed(config->policy_generation, family, address)) {
    authorized = 1;
    reason = NOSH_EGRESS_REASON_DNS_RESOLVER;
  } else if (config->mode == NOSH_EGRESS_MODE_LEARN) {
    return finish_decision(config, 0, hook, family, protocol,
                           0, port, NULL, address,
                           NOSH_EGRESS_REASON_DEFAULT_DENY, 0, 0);
  } else if (family == NOSH_EGRESS_FAMILY_IPV4) {
    __u32 ipv4;
    __builtin_memcpy(&ipv4, address, 4);
    static_rule = lookup_static4(config->policy_generation, protocol,
                                 port, 0, 0, ipv4);
  } else {
    static_rule = lookup_static6(config->policy_generation, protocol,
                                 port, 0, 0, address);
  }
  if (static_rule) {
    authorized = 1;
    reason = NOSH_EGRESS_REASON_STATIC;
    rule_id = static_rule->rule_id;
  }
  if (!authorized) {
    grant = lookup_grant(config->policy_generation, family, protocol,
                         port, address);
    if (grant) {
      authorized = 1;
      reason = NOSH_EGRESS_REASON_DNS_GRANT;
      rule_id = grant->rule_id;
    }
  }
  return finish_decision(config, authorized, hook, family, protocol,
                         0, port, NULL, address, reason, rule_id, 0);
}

static __always_inline int decide_packet(struct __sk_buff *skb,
                                         __u8 hook, int ingress)
{
  struct nosh_egress_config *config = configuration();
  struct nosh_packet packet = {};
  struct nosh_egress_rule_value *static_rule = NULL;
  struct nosh_egress_grant_value *grant = NULL;
  struct nosh_egress_containment_value *containment_value = NULL;
  const __u8 *remote;
  __u16 remote_port;
  __u32 dns_offset = 0;
  int authorized = 0;
  __u8 reason = NOSH_EGRESS_REASON_DEFAULT_DENY;
  __u32 rule_id = 0;
  int parse_result;
  int required_control = 0;

  if (!config_is_valid(config)) {
    increment_stat(NOSH_EGRESS_STAT_CONFIG_INVALID);
    return force_deny(config, hook, 0, 0, 0, 0, NULL, NULL,
                      NOSH_EGRESS_REASON_CONFIG_INVALID, 0, skb->len);
  }
  parse_result = parse_packet(skb, &packet);
  if (parse_result == 0 && !packet.fragmented) {
    required_control = required_ipv6_ndp(skb, &packet) ||
      required_ipv6_error(skb, &packet, ingress);
  }
  if (packet.address_known) {
    remote = ingress ? packet.source : packet.destination;
    containment_value = lookup_containment(config->policy_generation,
                                           packet.family, remote);
    if (containment_value && !containment_value_is_valid(
        containment_value, config->policy_generation)) {
      increment_stat(NOSH_EGRESS_STAT_CONFIG_INVALID);
      return force_deny(config, hook, packet.family, packet.protocol,
                        packet.source_port, packet.destination_port,
                        packet.source, packet.destination,
                        NOSH_EGRESS_REASON_CONFIG_INVALID, 0, skb->len);
    }
    if (containment_value && required_control)
      return finish_decision(config, 1, hook, packet.family,
                             packet.protocol, packet.source_port,
                             packet.destination_port, packet.source,
                             packet.destination,
                             NOSH_EGRESS_REASON_IPV6_CONTROL, 0, skb->len);
    if (containment_value)
      return containment_deny(config, hook, packet.family, packet.protocol,
                              packet.source_port, packet.destination_port,
                              packet.source, packet.destination,
                              containment_value, skb->len);
  }
  if (parse_result == NOSH_EGRESS_PACKET_HIDDEN_DESTINATION) {
    increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
    return force_deny(config, hook, packet.family, packet.protocol,
                      packet.source_port, packet.destination_port,
                      packet.source, packet.destination,
                      NOSH_EGRESS_REASON_HIDDEN_DESTINATION, 0, skb->len);
  }
  if (parse_result == NOSH_EGRESS_PACKET_UNSUPPORTED) {
    increment_stat(NOSH_EGRESS_STAT_UNSUPPORTED_PROTOCOL);
    if (!packet.address_known)
      return force_deny(config, hook, packet.family, packet.protocol,
                        packet.source_port, packet.destination_port,
                        packet.source, packet.destination,
                        NOSH_EGRESS_REASON_UNKNOWN_DESTINATION, 0, skb->len);
    return coverage_decision(config, hook, packet.family, packet.protocol,
                             packet.source_port, packet.destination_port,
                             packet.source, packet.destination,
                             NOSH_EGRESS_REASON_UNSUPPORTED, skb->len);
  }
  if (parse_result < 0) {
    increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
    if (!packet.address_known)
      return force_deny(config, hook, 0, 0, 0, 0, NULL, NULL,
                        NOSH_EGRESS_REASON_UNKNOWN_DESTINATION, 0, skb->len);
    return coverage_decision(config, hook, packet.family, packet.protocol,
                             packet.source_port, packet.destination_port,
                             packet.source, packet.destination,
                             NOSH_EGRESS_REASON_PARSE_ERROR, skb->len);
  }
  if (packet.fragmented) {
    increment_stat(NOSH_EGRESS_STAT_FRAGMENTS);
    return coverage_decision(config, hook, packet.family, packet.protocol,
                             packet.source_port, packet.destination_port,
                             packet.source, packet.destination,
                             NOSH_EGRESS_REASON_FRAGMENT, skb->len);
  }

  if (required_control)
    return finish_decision(config, 1, hook, packet.family, packet.protocol,
                           packet.source_port, packet.destination_port,
                           packet.source, packet.destination,
                           NOSH_EGRESS_REASON_IPV6_CONTROL, 0, skb->len);

  if (!ingress &&
      (packet.protocol == NOSH_EGRESS_PROTOCOL_UDP ||
       packet.protocol == NOSH_EGRESS_PROTOCOL_TCP) &&
      packet.destination_port == 53 &&
      resolver_allowed(config->policy_generation, packet.family,
                       packet.destination)) {
    if (packet.protocol == NOSH_EGRESS_PROTOCOL_TCP &&
        !packet.payload_length)
      return finish_decision(config, 1, hook, packet.family,
                             packet.protocol, packet.source_port,
                             packet.destination_port, packet.source,
                             packet.destination,
                             NOSH_EGRESS_REASON_DNS_RESOLVER, 0, skb->len);
    if (dns_message_offset(skb, &packet, &dns_offset) < 0) {
      increment_stat(packet.protocol == NOSH_EGRESS_PROTOCOL_TCP ?
                     NOSH_EGRESS_STAT_DNS_UNSUPPORTED :
                     NOSH_EGRESS_STAT_PARSE_ERRORS);
      return coverage_decision(
        config, hook, packet.family, packet.protocol,
        packet.source_port, packet.destination_port,
        packet.source, packet.destination,
        packet.protocol == NOSH_EGRESS_PROTOCOL_TCP ?
          NOSH_EGRESS_REASON_UNSUPPORTED : NOSH_EGRESS_REASON_PARSE_ERROR,
        skb->len);
    }
    return handle_dns_query(skb, config, &packet, hook, dns_offset);
  }
  if (ingress &&
      (packet.protocol == NOSH_EGRESS_PROTOCOL_UDP ||
       packet.protocol == NOSH_EGRESS_PROTOCOL_TCP) &&
      packet.source_port == 53 &&
      resolver_allowed(config->policy_generation, packet.family,
                       packet.source)) {
    if (packet.protocol == NOSH_EGRESS_PROTOCOL_TCP &&
        !packet.payload_length)
      return finish_decision(config, 1, hook, packet.family,
                             packet.protocol, packet.source_port,
                             packet.destination_port, packet.source,
                             packet.destination,
                             NOSH_EGRESS_REASON_DNS_RESOLVER, 0, skb->len);
    if (dns_message_offset(skb, &packet, &dns_offset) < 0) {
      increment_stat(packet.protocol == NOSH_EGRESS_PROTOCOL_TCP ?
                     NOSH_EGRESS_STAT_DNS_UNSUPPORTED :
                     NOSH_EGRESS_STAT_PARSE_ERRORS);
      return coverage_decision(
        config, hook, packet.family, packet.protocol,
        packet.source_port, packet.destination_port,
        packet.source, packet.destination,
        packet.protocol == NOSH_EGRESS_PROTOCOL_TCP ?
          NOSH_EGRESS_REASON_UNSUPPORTED : NOSH_EGRESS_REASON_PARSE_ERROR,
        skb->len);
    }
    return handle_dns_response(skb, config, &packet, hook, dns_offset);
  }

  remote = ingress ? packet.source : packet.destination;
  remote_port = ingress ? packet.source_port : packet.destination_port;
  if (config->mode == NOSH_EGRESS_MODE_LEARN)
    return finish_decision(config, 0, hook, packet.family, packet.protocol,
                           packet.source_port, packet.destination_port,
                           packet.source, packet.destination,
                           NOSH_EGRESS_REASON_DEFAULT_DENY, 0, skb->len);
  if (packet.family == NOSH_EGRESS_FAMILY_IPV4) {
    __u32 ipv4;
    __builtin_memcpy(&ipv4, remote, 4);
    static_rule = lookup_static4(config->policy_generation, packet.protocol,
                                 remote_port, packet.icmp_type,
                                 packet.icmp_code, ipv4);
  } else if (packet.family == NOSH_EGRESS_FAMILY_IPV6) {
    static_rule = lookup_static6(config->policy_generation, packet.protocol,
                                 remote_port, packet.icmp_type,
                                 packet.icmp_code, remote);
  }
  if (static_rule) {
    authorized = 1;
    reason = NOSH_EGRESS_REASON_STATIC;
    rule_id = static_rule->rule_id;
  }
  if (!authorized) {
    grant = lookup_grant(config->policy_generation, packet.family,
                         packet.protocol, remote_port, remote);
    if (grant) {
      authorized = 1;
      reason = NOSH_EGRESS_REASON_DNS_GRANT;
      rule_id = grant->rule_id;
    }
  }
  return finish_decision(config, authorized, hook, packet.family,
                         packet.protocol, packet.source_port,
                         packet.destination_port, packet.source,
                         packet.destination, reason, rule_id, skb->len);
}

SEC("cgroup/connect4")
int nosh_egress_connect4(struct bpf_sock_addr *ctx)
{
  return decide_sock_addr(ctx, NOSH_EGRESS_FAMILY_IPV4,
                          NOSH_EGRESS_HOOK_CONNECT4);
}

SEC("cgroup/connect6")
int nosh_egress_connect6(struct bpf_sock_addr *ctx)
{
  return decide_sock_addr(ctx, NOSH_EGRESS_FAMILY_IPV6,
                          NOSH_EGRESS_HOOK_CONNECT6);
}

SEC("cgroup/sendmsg4")
int nosh_egress_sendmsg4(struct bpf_sock_addr *ctx)
{
  return decide_sock_addr(ctx, NOSH_EGRESS_FAMILY_IPV4,
                          NOSH_EGRESS_HOOK_SENDMSG4);
}

SEC("cgroup/sendmsg6")
int nosh_egress_sendmsg6(struct bpf_sock_addr *ctx)
{
  return decide_sock_addr(ctx, NOSH_EGRESS_FAMILY_IPV6,
                          NOSH_EGRESS_HOOK_SENDMSG6);
}

SEC("cgroup_skb/ingress")
int nosh_egress_ingress(struct __sk_buff *skb)
{
  return decide_packet(skb, NOSH_EGRESS_HOOK_INGRESS, 1);
}

SEC("cgroup_skb/egress")
int nosh_egress_egress(struct __sk_buff *skb)
{
  return decide_packet(skb, NOSH_EGRESS_HOOK_EGRESS, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
