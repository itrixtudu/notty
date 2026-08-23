// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#ifndef NOSH_L4_H
#define NOSH_L4_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define NOSH_L4_SCHEMA_VERSION 1
#define NOSH_L4_ADDRESS_LEN 16
#define NOSH_L4_COMM_LEN 16
#define NOSH_L4_ALLOW 1
#define NOSH_L4_FLOW_MAX_ENTRIES 65536

enum nosh_l4_output_mode {
  NOSH_L4_OUTPUT_EVENTS = 0,
  NOSH_L4_OUTPUT_FLOW_SUMMARY = 1,
};

enum nosh_l4_event_kind {
  NOSH_L4_EVENT_UNSPECIFIED = 0,
  NOSH_L4_EVENT_ATTEMPT = 1,
  NOSH_L4_EVENT_PACKET = 2,
};

enum nosh_l4_hook {
  NOSH_L4_HOOK_UNSPECIFIED = 0,
  NOSH_L4_HOOK_CONNECT4 = 1,
  NOSH_L4_HOOK_CONNECT6 = 2,
  NOSH_L4_HOOK_SENDMSG4 = 3,
  NOSH_L4_HOOK_SENDMSG6 = 4,
  NOSH_L4_HOOK_INGRESS = 5,
  NOSH_L4_HOOK_EGRESS = 6,
};

enum nosh_l4_operation {
  NOSH_L4_OPERATION_NONE = 0,
  NOSH_L4_OPERATION_CONNECT = 1,
  NOSH_L4_OPERATION_SENDMSG = 2,
  NOSH_L4_OPERATION_PACKET = 3,
};

enum nosh_l4_direction {
  NOSH_L4_DIRECTION_NONE = 0,
  NOSH_L4_DIRECTION_INGRESS = 1,
  NOSH_L4_DIRECTION_EGRESS = 2,
};

enum nosh_l4_family {
  NOSH_L4_FAMILY_UNSPECIFIED = 0,
  NOSH_L4_FAMILY_IPV4 = 4,
  NOSH_L4_FAMILY_IPV6 = 6,
};

enum nosh_l4_protocol {
  NOSH_L4_PROTOCOL_UNSPECIFIED = 0,
  NOSH_L4_PROTOCOL_ICMP = 1,
  NOSH_L4_PROTOCOL_TCP = 6,
  NOSH_L4_PROTOCOL_UDP = 17,
  NOSH_L4_PROTOCOL_ICMPV6 = 58,
};

enum nosh_l4_verdict {
  NOSH_L4_VERDICT_UNSPECIFIED = 0,
  NOSH_L4_VERDICT_ALLOW = 1,
};

enum nosh_l4_owner_source {
  NOSH_L4_OWNER_UNKNOWN = 0,
  NOSH_L4_OWNER_CURRENT_TASK = 1,
  NOSH_L4_OWNER_SOCKET_COOKIE_CACHE = 2,
};

enum nosh_l4_flags {
  NOSH_L4_F_OBSERVED_ONLY = 1U << 0,
  NOSH_L4_F_COMPLETION_UNKNOWN = 1U << 1,
  NOSH_L4_F_L4_UNAVAILABLE = 1U << 2,
  NOSH_L4_F_FRAGMENT = 1U << 3,
};

enum nosh_l4_stat {
  NOSH_L4_STAT_RINGBUF_DROPS = 0,
  NOSH_L4_STAT_PARSE_ERRORS = 1,
  NOSH_L4_STAT_UNSUPPORTED_PROTOCOL = 2,
  NOSH_L4_STAT_FLOW_MAP_FULL = 3,
  NOSH_L4_STAT_CONFIG_MISSING = 4,
  NOSH_L4_STAT_MAX = 5,
};

struct nosh_l4_config {
  __u64 target_cgroup_id;
  __u32 output_mode;
  __u32 reserved;
};

struct nosh_l4_process {
  __u32 pid;
  __u32 tid;
  __u32 uid;
  __u32 gid;
  __u64 last_seen_ns;
  char comm[NOSH_L4_COMM_LEN];
};

struct nosh_l4_flow_key {
  __u64 cgroup_id;
  __u64 socket_cookie;
  __u32 ifindex;
  __u16 source_port;
  __u16 destination_port;
  __u8 direction;
  __u8 family;
  __u8 protocol;
  __u8 icmp_type;
  __u8 icmp_code;
  __u8 flags;
  __u8 pad[2];
  __u8 source_address[NOSH_L4_ADDRESS_LEN];
  __u8 destination_address[NOSH_L4_ADDRESS_LEN];
};

struct nosh_l4_flow_totals {
  __u64 first_seen_ns;
  __u64 last_seen_ns;
  __u64 packets;
  __u64 bytes;
};

struct nosh_l4_event {
  __u64 timestamp_ns;
  __u64 cgroup_id;
  __u64 socket_cookie;
  __u64 packets;
  __u64 bytes;
  __u32 pid;
  __u32 tid;
  __u32 uid;
  __u32 gid;
  __u32 packet_len;
  __u32 ifindex;
  __s32 hook_return;
  __u16 schema_version;
  __u16 event_size;
  __u16 source_port;
  __u16 destination_port;
  __u16 flags;
  __u8 event_kind;
  __u8 hook;
  __u8 operation;
  __u8 direction;
  __u8 family;
  __u8 protocol;
  __u8 verdict;
  __u8 owner_source;
  __u8 icmp_type;
  __u8 icmp_code;
  __u8 reserved[2];
  __u8 source_address[NOSH_L4_ADDRESS_LEN];
  __u8 destination_address[NOSH_L4_ADDRESS_LEN];
  char comm[NOSH_L4_COMM_LEN];
};

#endif
