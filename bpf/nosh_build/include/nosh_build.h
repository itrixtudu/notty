// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#ifndef NOSH_BUILD_H
#define NOSH_BUILD_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define NOSH_BUILD_SCHEMA_VERSION 2
#define NOSH_BUILD_ALLOW 1
#define NOSH_BUILD_COMM_LEN 16
#define NOSH_BUILD_FILENAME_LEN 256
#define NOSH_BUILD_ADDRESS_LEN 16
#define NOSH_BUILD_DNS_QNAME_LEN 256
#define NOSH_BUILD_DNS_MAX_LABELS 32
#define NOSH_BUILD_DNS_MAX_ANSWERS 8
#define NOSH_BUILD_DNS_MAX_VISITED_ANSWERS 16
#define NOSH_BUILD_DNS_WIRE_LEN 1232
#define NOSH_BUILD_INFLIGHT_MAX_ENTRIES 65536
#define NOSH_BUILD_FILE_MAX_ENTRIES 32768

enum nosh_build_collection_depth {
  NOSH_BUILD_DEPTH_BALANCED = 0,
  NOSH_BUILD_DEPTH_POLICY = 1,
};

enum nosh_build_file_access {
  NOSH_BUILD_FILE_ACCESS_READ = 1U << 0,
  NOSH_BUILD_FILE_ACCESS_WRITE = 1U << 1,
  NOSH_BUILD_FILE_ACCESS_EXECUTE = 1U << 2,
  NOSH_BUILD_FILE_ACCESS_CREATE = 1U << 3,
};

enum nosh_build_event_kind {
  NOSH_BUILD_EVENT_UNSPECIFIED = 0,
  NOSH_BUILD_EVENT_PROCESS_EXEC = 1,
  NOSH_BUILD_EVENT_PROCESS_EXIT = 2,
  NOSH_BUILD_EVENT_DNS_QUERY = 3,
  NOSH_BUILD_EVENT_DNS_RESPONSE = 4,
};

enum nosh_build_family {
  NOSH_BUILD_FAMILY_UNSPECIFIED = 0,
  NOSH_BUILD_FAMILY_IPV4 = 4,
  NOSH_BUILD_FAMILY_IPV6 = 6,
};

enum nosh_build_dns_answer_kind {
  NOSH_BUILD_DNS_ANSWER_UNSPECIFIED = 0,
  NOSH_BUILD_DNS_ANSWER_IPV4 = 1,
  NOSH_BUILD_DNS_ANSWER_IPV6 = 2,
  NOSH_BUILD_DNS_ANSWER_CNAME = 3,
};

enum nosh_build_stat {
  NOSH_BUILD_STAT_RINGBUF_DROPS = 0,
  NOSH_BUILD_STAT_SYSCALL_MAP_FULL = 1,
  NOSH_BUILD_STAT_INFLIGHT_MAP_FULL = 2,
  NOSH_BUILD_STAT_CONFIG_MISSING = 3,
  NOSH_BUILD_STAT_CGROUP_FILTER_ERRORS = 4,
  NOSH_BUILD_STAT_DNS_PARSE_ERRORS = 5,
  NOSH_BUILD_STAT_DNS_COMPRESSED_NAMES = 6,
  NOSH_BUILD_STAT_DNS_TRUNCATED_NAMES = 7,
  NOSH_BUILD_STAT_FILE_MAP_FULL = 8,
  NOSH_BUILD_STAT_FILE_PATH_ERRORS = 9,
  NOSH_BUILD_STAT_FILE_OPEN_OBSERVATIONS = 10,
  NOSH_BUILD_STAT_DNS_TRUNCATED_RESPONSES = 11,
  NOSH_BUILD_STAT_DNS_ANSWER_LIMIT_REACHED = 12,
  NOSH_BUILD_STAT_DNS_UNSUPPORTED_ANSWERS = 13,
  NOSH_BUILD_STAT_DNS_CORRELATION_MISSING = 14,
  NOSH_BUILD_STAT_DNS_QUERY_OBSERVATIONS = 15,
  NOSH_BUILD_STAT_DNS_RESPONSE_OBSERVATIONS = 16,
  NOSH_BUILD_STAT_DNS_NAME_POINTERS = 17,
  NOSH_BUILD_STAT_MAX = 18,
};

struct nosh_build_config {
  __u64 target_cgroup_id;
  __u32 collection_depth;
  __u32 reserved;
};

struct nosh_build_event_header {
  __u64 timestamp_ns;
  __u64 cgroup_id;
  __u16 schema_version;
  __u16 event_size;
  __u8 event_kind;
  __u8 reserved[3];
};

struct nosh_build_process_event {
  struct nosh_build_event_header header;
  __u32 pid;
  __u32 tid;
  __u32 ppid;
  __u32 uid;
  __u32 gid;
  __s32 exit_code;
  char comm[NOSH_BUILD_COMM_LEN];
  char filename[NOSH_BUILD_FILENAME_LEN];
};

struct nosh_build_dns_correlation {
  __u64 socket_cookie;
  __u16 client_port;
  __u16 server_port;
  __u16 query_type;
  __u16 query_class;
  __u16 transaction_id;
  __u16 qname_length;
  __u8 family;
  __u8 complete;
  __u8 reserved[6];
  __u8 server_address[NOSH_BUILD_ADDRESS_LEN];
  char qname[NOSH_BUILD_DNS_QNAME_LEN];
};

struct nosh_build_dns_query_event {
  struct nosh_build_event_header header;
  struct nosh_build_dns_correlation correlation;
};

/*
 * Private kernel-to-loader ABI. Raw DNS bytes are decoded in trusted
 * userspace and must never be emitted or persisted as evidence.
 */
struct nosh_build_dns_wire_event {
  struct nosh_build_event_header header;
  __u64 socket_cookie;
  __u16 client_port;
  __u16 server_port;
  __u16 wire_length;
  __u16 original_length;
  __u8 family;
  __u8 reserved[7];
  __u8 server_address[NOSH_BUILD_ADDRESS_LEN];
  __u8 wire[NOSH_BUILD_DNS_WIRE_LEN];
};

struct nosh_build_dns_answer {
  __u32 ttl;
  __u16 type;
  __u16 class;
  __u16 owner_name_length;
  __u16 data_name_length;
  __u8 kind;
  __u8 family;
  __u8 reserved[2];
  __u8 address[NOSH_BUILD_ADDRESS_LEN];
  char owner_name[NOSH_BUILD_DNS_QNAME_LEN];
  char data_name[NOSH_BUILD_DNS_QNAME_LEN];
};

struct nosh_build_dns_response_event {
  struct nosh_build_event_header header;
  struct nosh_build_dns_correlation correlation;
  __u16 flags;
  __u16 response_code;
  __u16 question_count;
  __u16 answers_declared;
  __u16 answers_visited;
  __u16 answers_captured;
  __u8 parse_complete;
  __u8 answer_limit_reached;
  __u8 reserved[6];
  struct nosh_build_dns_answer answers[NOSH_BUILD_DNS_MAX_ANSWERS];
};

struct nosh_build_syscall_key {
  __s64 syscall_number;
};

struct nosh_build_syscall_totals {
  __u64 calls;
  __u64 completions;
  __u64 errors;
  __u64 total_duration_ns;
  __u64 max_duration_ns;
};

struct nosh_build_inflight_syscall {
  __u64 started_ns;
  __s64 syscall_number;
};

struct nosh_build_file_key {
  char path[NOSH_BUILD_FILENAME_LEN];
};

struct nosh_build_file_totals {
  __u64 first_seen_ns;
  __u64 last_seen_ns;
  __u64 opens;
  __u64 read_opens;
  __u64 write_opens;
  __u64 execute_opens;
  __u64 create_opens;
};

#endif
