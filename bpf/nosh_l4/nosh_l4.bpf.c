// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "include/nosh_l4.h"

#ifdef NOSH_L4_INSPEKTOR_GADGET
#include <gadget/macros.h>
#endif

#define NOSH_L4_OWNER_MAX_ENTRIES 32768
#define NOSH_L4_RINGBUF_BYTES (16 * 1024 * 1024)

#define NOSH_L4_SOCK_STREAM 1
#define NOSH_L4_SOCK_DGRAM 2

#define NOSH_L4_IPV4_FRAGMENT_OFFSET_MASK 0x1fff
#define NOSH_L4_IPV4_MORE_FRAGMENTS 0x2000
#define NOSH_L4_IPV6_FRAGMENT_OFFSET_MASK 0xfff8

#define NOSH_L4_IPV6_HOPOPTS 0
#define NOSH_L4_IPV6_ROUTING 43
#define NOSH_L4_IPV6_FRAGMENT 44
#define NOSH_L4_IPV6_ESP 50
#define NOSH_L4_IPV6_AH 51
#define NOSH_L4_IPV6_NONE 59
#define NOSH_L4_IPV6_DSTOPTS 60

/* enum bpf_hdr_start_off: MAC is 0 and the network header is 1. */
#define NOSH_L4_HDR_START_NET 1

struct nosh_l4_ipv4_header {
  __u8 version_ihl;
  __u8 tos;
  __be16 total_length;
  __be16 identification;
  __be16 fragment_offset;
  __u8 ttl;
  __u8 protocol;
  __be16 checksum;
  __be32 source_address;
  __be32 destination_address;
};

struct nosh_l4_ipv6_header {
  __be32 version_traffic_flow;
  __be16 payload_length;
  __u8 next_header;
  __u8 hop_limit;
  __u8 source_address[NOSH_L4_ADDRESS_LEN];
  __u8 destination_address[NOSH_L4_ADDRESS_LEN];
};

struct nosh_l4_ipv6_extension {
  __u8 next_header;
  __u8 length;
};

struct nosh_l4_ipv6_fragment {
  __u8 next_header;
  __u8 reserved;
  __be16 fragment_offset;
  __be32 identification;
};

struct nosh_l4_ports {
  __be16 source_port;
  __be16 destination_port;
};

struct nosh_l4_icmp_header {
  __u8 type;
  __u8 code;
};

struct nosh_l4_packet {
  __u32 l4_offset;
  __u16 source_port;
  __u16 destination_port;
  __u8 direction;
  __u8 family;
  __u8 protocol;
  __u8 icmp_type;
  __u8 icmp_code;
  __u8 flags;
  __u8 source_address[NOSH_L4_ADDRESS_LEN];
  __u8 destination_address[NOSH_L4_ADDRESS_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NOSH_L4_RINGBUF_BYTES);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, NOSH_L4_OWNER_MAX_ENTRIES);
  __type(key, __u64);
  __type(value, struct nosh_l4_process);
} socket_owners SEC(".maps");

/*
 * A plain HASH is intentional: Inspektor Gadget map iterators can export it,
 * and a libbpf collector can batch-read and delete completed observations.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NOSH_L4_FLOW_MAX_ENTRIES);
  __type(key, struct nosh_l4_flow_key);
  __type(value, struct nosh_l4_flow_totals);
} flow_totals SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, NOSH_L4_STAT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct nosh_l4_config);
} session_config SEC(".maps");

#ifdef NOSH_L4_INSPEKTOR_GADGET
GADGET_TRACER(nosh_l4_events, events, nosh_l4_event);
GADGET_MAPITER(nosh_l4_totals, flow_totals);
#endif

static __always_inline void increment_stat(enum nosh_l4_stat stat)
{
  __u32 key = stat;
  __u64 *value = bpf_map_lookup_elem(&stats, &key);

  if (value)
    *value += 1;
}

static __always_inline int protocol_is_profiled(__u8 protocol)
{
  return protocol == NOSH_L4_PROTOCOL_TCP ||
         protocol == NOSH_L4_PROTOCOL_UDP ||
         protocol == NOSH_L4_PROTOCOL_ICMP ||
         protocol == NOSH_L4_PROTOCOL_ICMPV6;
}

static __always_inline __u64 configured_cgroup_id(void)
{
  __u32 key = 0;
  struct nosh_l4_config *config =
    bpf_map_lookup_elem(&session_config, &key);

  return config ? config->target_cgroup_id : 0;
}

static __always_inline __u32 configured_output_mode(void)
{
  __u32 key = 0;
  struct nosh_l4_config *config =
    bpf_map_lookup_elem(&session_config, &key);

  return config ? config->output_mode : NOSH_L4_OUTPUT_EVENTS;
}

static __always_inline int load_network_bytes(struct __sk_buff *skb,
                                               __u32 offset,
                                               void *destination,
                                               __u32 length)
{
  return bpf_skb_load_bytes_relative(skb, offset, destination, length,
                                     NOSH_L4_HDR_START_NET);
}

static __always_inline int parse_ports_or_icmp(struct __sk_buff *skb,
                                               struct nosh_l4_packet *packet)
{
  if (packet->protocol == NOSH_L4_PROTOCOL_TCP ||
      packet->protocol == NOSH_L4_PROTOCOL_UDP) {
    struct nosh_l4_ports ports = {};

    if (load_network_bytes(skb, packet->l4_offset, &ports, sizeof(ports)) < 0)
      return -1;

    packet->source_port = bpf_ntohs(ports.source_port);
    packet->destination_port = bpf_ntohs(ports.destination_port);
    return 0;
  }

  if (packet->protocol == NOSH_L4_PROTOCOL_ICMP ||
      packet->protocol == NOSH_L4_PROTOCOL_ICMPV6) {
    struct nosh_l4_icmp_header icmp = {};

    if (load_network_bytes(skb, packet->l4_offset, &icmp, sizeof(icmp)) < 0)
      return -1;

    packet->icmp_type = icmp.type;
    packet->icmp_code = icmp.code;
    return 0;
  }

  return -2;
}

static __always_inline int parse_ipv4(struct __sk_buff *skb,
                                      struct nosh_l4_packet *packet)
{
  struct nosh_l4_ipv4_header ipv4 = {};
  __u16 fragment_offset;
  __u32 header_length;

  if (load_network_bytes(skb, 0, &ipv4, sizeof(ipv4)) < 0)
    return -1;

  if ((ipv4.version_ihl >> 4) != NOSH_L4_FAMILY_IPV4)
    return -1;

  header_length = (ipv4.version_ihl & 0x0f) * 4;
  if (header_length < sizeof(ipv4))
    return -1;

  packet->family = NOSH_L4_FAMILY_IPV4;
  packet->protocol = ipv4.protocol;
  packet->l4_offset = header_length;
  __builtin_memcpy(packet->source_address, &ipv4.source_address,
                   sizeof(ipv4.source_address));
  __builtin_memcpy(packet->destination_address, &ipv4.destination_address,
                   sizeof(ipv4.destination_address));

  if (!protocol_is_profiled(packet->protocol))
    return -2;

  fragment_offset = bpf_ntohs(ipv4.fragment_offset);
  if (fragment_offset &
      (NOSH_L4_IPV4_FRAGMENT_OFFSET_MASK | NOSH_L4_IPV4_MORE_FRAGMENTS))
    packet->flags |= NOSH_L4_F_FRAGMENT;

  if (fragment_offset & NOSH_L4_IPV4_FRAGMENT_OFFSET_MASK) {
    packet->flags |= NOSH_L4_F_L4_UNAVAILABLE;
    return 0;
  }

  return parse_ports_or_icmp(skb, packet);
}

static __always_inline int ipv6_extension_header(__u8 next_header)
{
  return next_header == NOSH_L4_IPV6_HOPOPTS ||
         next_header == NOSH_L4_IPV6_ROUTING ||
         next_header == NOSH_L4_IPV6_DSTOPTS;
}

static __always_inline int parse_ipv6(struct __sk_buff *skb,
                                      struct nosh_l4_packet *packet)
{
  struct nosh_l4_ipv6_header ipv6 = {};
  __u8 next_header;
  __u32 offset = sizeof(ipv6);
  int iteration;

  if (load_network_bytes(skb, 0, &ipv6, sizeof(ipv6)) < 0)
    return -1;

  if ((bpf_ntohl(ipv6.version_traffic_flow) >> 28) != NOSH_L4_FAMILY_IPV6)
    return -1;

  packet->family = NOSH_L4_FAMILY_IPV6;
  __builtin_memcpy(packet->source_address, ipv6.source_address,
                   sizeof(packet->source_address));
  __builtin_memcpy(packet->destination_address, ipv6.destination_address,
                   sizeof(packet->destination_address));
  next_header = ipv6.next_header;

#pragma unroll
  for (iteration = 0; iteration < 6; iteration++) {
    if (protocol_is_profiled(next_header))
      break;

    if (ipv6_extension_header(next_header)) {
      struct nosh_l4_ipv6_extension extension = {};

      if (load_network_bytes(skb, offset, &extension, sizeof(extension)) < 0)
        return -1;
      next_header = extension.next_header;
      offset += ((__u32)extension.length + 1) * 8;
      continue;
    }

    if (next_header == NOSH_L4_IPV6_FRAGMENT) {
      struct nosh_l4_ipv6_fragment fragment = {};
      __u16 fragment_offset;

      if (load_network_bytes(skb, offset, &fragment, sizeof(fragment)) < 0)
        return -1;
      next_header = fragment.next_header;
      fragment_offset = bpf_ntohs(fragment.fragment_offset);
      packet->flags |= NOSH_L4_F_FRAGMENT;
      offset += sizeof(fragment);
      if (fragment_offset & NOSH_L4_IPV6_FRAGMENT_OFFSET_MASK) {
        packet->flags |= NOSH_L4_F_L4_UNAVAILABLE;
        packet->protocol = next_header;
        packet->l4_offset = offset;
        return protocol_is_profiled(next_header) ? 0 : -2;
      }
      continue;
    }

    if (next_header == NOSH_L4_IPV6_AH) {
      struct nosh_l4_ipv6_extension authentication = {};

      if (load_network_bytes(skb, offset, &authentication,
                             sizeof(authentication)) < 0)
        return -1;
      next_header = authentication.next_header;
      offset += ((__u32)authentication.length + 2) * 4;
      continue;
    }

    if (next_header == NOSH_L4_IPV6_ESP ||
        next_header == NOSH_L4_IPV6_NONE)
      return -2;

    return -2;
  }

  if (!protocol_is_profiled(next_header))
    return -2;

  packet->protocol = next_header;
  packet->l4_offset = offset;
  return parse_ports_or_icmp(skb, packet);
}

static __always_inline int parse_packet(struct __sk_buff *skb,
                                        struct nosh_l4_packet *packet)
{
  __u8 first_byte = 0;
  __u8 version;

  __builtin_memset(packet, 0, sizeof(*packet));

  if (load_network_bytes(skb, 0, &first_byte, sizeof(first_byte)) < 0)
    return -1;

  version = first_byte >> 4;
  if (version == NOSH_L4_FAMILY_IPV4)
    return parse_ipv4(skb, packet);
  if (version == NOSH_L4_FAMILY_IPV6)
    return parse_ipv6(skb, packet);
  return -2;
}

static __always_inline void read_current_process(struct nosh_l4_process *owner,
                                                 __u64 timestamp_ns)
{
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 uid_gid = bpf_get_current_uid_gid();

  __builtin_memset(owner, 0, sizeof(*owner));
  owner->pid = pid_tgid >> 32;
  owner->tid = (__u32)pid_tgid;
  owner->uid = (__u32)uid_gid;
  owner->gid = uid_gid >> 32;
  owner->last_seen_ns = timestamp_ns;
  bpf_get_current_comm(owner->comm, sizeof(owner->comm));
}

static __always_inline __u8 sock_addr_protocol(struct bpf_sock_addr *ctx)
{
  __u8 protocol = ctx->protocol;

  if (protocol == NOSH_L4_PROTOCOL_TCP ||
      protocol == NOSH_L4_PROTOCOL_UDP)
    return protocol;
  if (ctx->type == NOSH_L4_SOCK_STREAM)
    return NOSH_L4_PROTOCOL_TCP;
  if (ctx->type == NOSH_L4_SOCK_DGRAM)
    return NOSH_L4_PROTOCOL_UDP;
  return NOSH_L4_PROTOCOL_UNSPECIFIED;
}

static __always_inline void fill_event_process(struct nosh_l4_event *event,
                                               const struct nosh_l4_process *owner,
                                               __u8 source)
{
  event->pid = owner->pid;
  event->tid = owner->tid;
  event->uid = owner->uid;
  event->gid = owner->gid;
  event->owner_source = source;
  __builtin_memcpy(event->comm, owner->comm, sizeof(event->comm));
}

/*
 * Keep every bpf_sock_addr IPv6 read at a fixed 32-bit context offset.
 * A bulk memcpy lets clang form a temporary ctx + 8 pointer, which the BPF
 * verifier refuses to dereference even though the same fixed fields are valid.
 * Volatile field reads also prevent adjacent words from being coalesced into
 * an unaligned 64-bit access to msg_src_ip6.
 */
static __always_inline void copy_user_ip6(
    struct nosh_l4_event *event,
    volatile struct bpf_sock_addr *ctx)
{
  __u32 word;

  word = ctx->user_ip6[0];
  __builtin_memcpy(&event->destination_address[0], &word, sizeof(word));
  word = ctx->user_ip6[1];
  __builtin_memcpy(&event->destination_address[4], &word, sizeof(word));
  word = ctx->user_ip6[2];
  __builtin_memcpy(&event->destination_address[8], &word, sizeof(word));
  word = ctx->user_ip6[3];
  __builtin_memcpy(&event->destination_address[12], &word, sizeof(word));
}

static __always_inline void copy_msg_src_ip6(
    struct nosh_l4_event *event,
    volatile struct bpf_sock_addr *ctx)
{
  __u32 word;

  word = ctx->msg_src_ip6[0];
  __builtin_memcpy(&event->source_address[0], &word, sizeof(word));
  word = ctx->msg_src_ip6[1];
  __builtin_memcpy(&event->source_address[4], &word, sizeof(word));
  word = ctx->msg_src_ip6[2];
  __builtin_memcpy(&event->source_address[8], &word, sizeof(word));
  word = ctx->msg_src_ip6[3];
  __builtin_memcpy(&event->source_address[12], &word, sizeof(word));
}

static __always_inline void observe_sock_addr(struct bpf_sock_addr *ctx,
                                              __u8 family,
                                              __u8 hook,
                                              __u8 operation)
{
  struct nosh_l4_process owner = {};
  struct nosh_l4_event *event;
  __u64 timestamp_ns = bpf_ktime_get_ns();
  __u64 socket_cookie = bpf_get_socket_cookie(ctx);
  __u8 protocol = sock_addr_protocol(ctx);

  if (protocol != NOSH_L4_PROTOCOL_TCP &&
      protocol != NOSH_L4_PROTOCOL_UDP) {
    increment_stat(NOSH_L4_STAT_UNSUPPORTED_PROTOCOL);
    return;
  }

  read_current_process(&owner, timestamp_ns);
  if (socket_cookie)
    bpf_map_update_elem(&socket_owners, &socket_cookie, &owner, BPF_ANY);

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    increment_stat(NOSH_L4_STAT_RINGBUF_DROPS);
    return;
  }

  __builtin_memset(event, 0, sizeof(*event));
  event->timestamp_ns = timestamp_ns;
  event->cgroup_id = configured_cgroup_id();
  if (!event->cgroup_id) {
    increment_stat(NOSH_L4_STAT_CONFIG_MISSING);
    event->cgroup_id = bpf_get_current_cgroup_id();
  }
  event->socket_cookie = socket_cookie;
  event->schema_version = NOSH_L4_SCHEMA_VERSION;
  event->event_size = sizeof(*event);
  event->flags = NOSH_L4_F_OBSERVED_ONLY |
                 NOSH_L4_F_COMPLETION_UNKNOWN;
  event->event_kind = NOSH_L4_EVENT_ATTEMPT;
  event->hook = hook;
  event->operation = operation;
  event->direction = NOSH_L4_DIRECTION_EGRESS;
  event->family = family;
  event->protocol = protocol;
  event->verdict = NOSH_L4_VERDICT_ALLOW;
  event->hook_return = NOSH_L4_ALLOW;
  event->destination_port = bpf_ntohs((__u16)ctx->user_port);
  fill_event_process(event, &owner, NOSH_L4_OWNER_CURRENT_TASK);

  if (family == NOSH_L4_FAMILY_IPV4) {
    __builtin_memcpy(event->destination_address, &ctx->user_ip4,
                     sizeof(ctx->user_ip4));
    if (operation == NOSH_L4_OPERATION_SENDMSG)
      __builtin_memcpy(event->source_address, &ctx->msg_src_ip4,
                       sizeof(ctx->msg_src_ip4));
  } else {
    copy_user_ip6(event, ctx);
    if (operation == NOSH_L4_OPERATION_SENDMSG)
      copy_msg_src_ip6(event, ctx);
  }

  bpf_ringbuf_submit(event, 0);
}

static __always_inline int update_flow_totals(
    const struct nosh_l4_flow_key *key,
    __u64 timestamp_ns,
    __u64 packet_bytes,
    __u64 *packets,
    __u64 *bytes)
{
  struct nosh_l4_flow_totals *totals;
  struct nosh_l4_flow_totals initial = {
    .first_seen_ns = timestamp_ns,
    .last_seen_ns = timestamp_ns,
    .packets = 1,
    .bytes = packet_bytes,
  };

  totals = bpf_map_lookup_elem(&flow_totals, key);
  if (!totals) {
    if (bpf_map_update_elem(&flow_totals, key, &initial, BPF_NOEXIST) == 0) {
      *packets = 1;
      *bytes = packet_bytes;
      return 0;
    }

    /* A concurrent CPU may have inserted this flow after our first lookup. */
    totals = bpf_map_lookup_elem(&flow_totals, key);
    if (!totals) {
      increment_stat(NOSH_L4_STAT_FLOW_MAP_FULL);
      return -1;
    }
  }

  /*
   * Discard the atomic operation's return value so older BPF targets can use
   * the original XADD instruction rather than fetch-and-add atomics.
   */
  __sync_fetch_and_add(&totals->packets, 1);
  __sync_fetch_and_add(&totals->bytes, packet_bytes);
  *packets = totals->packets;
  *bytes = totals->bytes;
  totals->last_seen_ns = timestamp_ns;
  return 0;
}

static __always_inline void observe_packet(struct __sk_buff *skb,
                                           __u8 direction,
                                           __u8 hook)
{
  struct nosh_l4_packet packet = {};
  struct nosh_l4_flow_key key = {};
  struct nosh_l4_process *owner;
  struct nosh_l4_event *event;
  __u64 timestamp_ns;
  __u64 socket_cookie;
  __u64 packets = 0;
  __u64 bytes = 0;
  int parse_result;

  parse_result = parse_packet(skb, &packet);
  if (parse_result < 0) {
    if (parse_result == -2)
      increment_stat(NOSH_L4_STAT_UNSUPPORTED_PROTOCOL);
    else
      increment_stat(NOSH_L4_STAT_PARSE_ERRORS);
    return;
  }

  timestamp_ns = bpf_ktime_get_ns();
  socket_cookie = bpf_get_socket_cookie(skb);
  packet.direction = direction;

  key.cgroup_id = configured_cgroup_id();
  if (!key.cgroup_id)
    increment_stat(NOSH_L4_STAT_CONFIG_MISSING);
  key.socket_cookie = socket_cookie;
  key.ifindex = skb->ifindex;
  key.source_port = packet.source_port;
  key.destination_port = packet.destination_port;
  key.direction = direction;
  key.family = packet.family;
  key.protocol = packet.protocol;
  key.icmp_type = packet.icmp_type;
  key.icmp_code = packet.icmp_code;
  key.flags = packet.flags;
  __builtin_memcpy(key.source_address, packet.source_address,
                   sizeof(key.source_address));
  __builtin_memcpy(key.destination_address, packet.destination_address,
                   sizeof(key.destination_address));

  if (update_flow_totals(&key, timestamp_ns, skb->len, &packets, &bytes) < 0)
    return;

  /* Build capture emits this bounded map once at shutdown, not every packet. */
  if (configured_output_mode() == NOSH_L4_OUTPUT_FLOW_SUMMARY)
    return;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    increment_stat(NOSH_L4_STAT_RINGBUF_DROPS);
    return;
  }

  __builtin_memset(event, 0, sizeof(*event));
  event->timestamp_ns = timestamp_ns;
  event->cgroup_id = key.cgroup_id;
  event->socket_cookie = socket_cookie;
  event->packets = packets;
  event->bytes = bytes;
  event->packet_len = skb->len;
  event->ifindex = skb->ifindex;
  event->schema_version = NOSH_L4_SCHEMA_VERSION;
  event->event_size = sizeof(*event);
  event->source_port = packet.source_port;
  event->destination_port = packet.destination_port;
  event->flags = NOSH_L4_F_OBSERVED_ONLY | packet.flags;
  event->event_kind = NOSH_L4_EVENT_PACKET;
  event->hook = hook;
  event->operation = NOSH_L4_OPERATION_PACKET;
  event->direction = direction;
  event->family = packet.family;
  event->protocol = packet.protocol;
  event->verdict = NOSH_L4_VERDICT_ALLOW;
  event->hook_return = NOSH_L4_ALLOW;
  event->icmp_type = packet.icmp_type;
  event->icmp_code = packet.icmp_code;
  __builtin_memcpy(event->source_address, packet.source_address,
                   sizeof(event->source_address));
  __builtin_memcpy(event->destination_address, packet.destination_address,
                   sizeof(event->destination_address));

  if (socket_cookie) {
    owner = bpf_map_lookup_elem(&socket_owners, &socket_cookie);
    if (owner)
      fill_event_process(event, owner,
                         NOSH_L4_OWNER_SOCKET_COOKIE_CACHE);
  }

  bpf_ringbuf_submit(event, 0);
}

SEC("cgroup/connect4")
int nosh_l4_connect4(struct bpf_sock_addr *ctx)
{
  observe_sock_addr(ctx, NOSH_L4_FAMILY_IPV4, NOSH_L4_HOOK_CONNECT4,
                    NOSH_L4_OPERATION_CONNECT);
  return NOSH_L4_ALLOW;
}

SEC("cgroup/connect6")
int nosh_l4_connect6(struct bpf_sock_addr *ctx)
{
  observe_sock_addr(ctx, NOSH_L4_FAMILY_IPV6, NOSH_L4_HOOK_CONNECT6,
                    NOSH_L4_OPERATION_CONNECT);
  return NOSH_L4_ALLOW;
}

SEC("cgroup/sendmsg4")
int nosh_l4_sendmsg4(struct bpf_sock_addr *ctx)
{
  observe_sock_addr(ctx, NOSH_L4_FAMILY_IPV4, NOSH_L4_HOOK_SENDMSG4,
                    NOSH_L4_OPERATION_SENDMSG);
  return NOSH_L4_ALLOW;
}

SEC("cgroup/sendmsg6")
int nosh_l4_sendmsg6(struct bpf_sock_addr *ctx)
{
  observe_sock_addr(ctx, NOSH_L4_FAMILY_IPV6, NOSH_L4_HOOK_SENDMSG6,
                    NOSH_L4_OPERATION_SENDMSG);
  return NOSH_L4_ALLOW;
}

SEC("cgroup_skb/ingress")
int nosh_l4_ingress(struct __sk_buff *skb)
{
  observe_packet(skb, NOSH_L4_DIRECTION_INGRESS, NOSH_L4_HOOK_INGRESS);
  return NOSH_L4_ALLOW;
}

SEC("cgroup_skb/egress")
int nosh_l4_egress(struct __sk_buff *skb)
{
  observe_packet(skb, NOSH_L4_DIRECTION_EGRESS, NOSH_L4_HOOK_EGRESS);
  return NOSH_L4_ALLOW;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
