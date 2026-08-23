// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "include/nosh_build.h"

#define NOSH_BUILD_RINGBUF_BYTES (16 * 1024 * 1024)
#define NOSH_BUILD_SYSCALL_MAX_ENTRIES 1024
#define NOSH_BUILD_DNS_PORT 53
#define NOSH_BUILD_DNS_COPY_CHUNK_LEN 32
#define NOSH_BUILD_IPPROTO_UDP 17
#define NOSH_BUILD_IPV4_FRAGMENT_OFFSET_MASK 0x1fff
#define NOSH_BUILD_IPV4_MORE_FRAGMENTS 0x2000
#define NOSH_BUILD_HDR_START_NET 1
#define NOSH_BUILD_DNS_RESPONSE 0x8000
#define NOSH_BUILD_FMODE_READ (1U << 0)
#define NOSH_BUILD_FMODE_WRITE (1U << 1)
#define NOSH_BUILD_FMODE_EXEC (1U << 5)
#define NOSH_BUILD_FMODE_CREATED (1U << 20)

struct nosh_build_ipv4_header {
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

struct nosh_build_ipv6_header {
  __be32 version_traffic_flow;
  __be16 payload_length;
  __u8 next_header;
  __u8 hop_limit;
  __u8 source_address[NOSH_BUILD_ADDRESS_LEN];
  __u8 destination_address[NOSH_BUILD_ADDRESS_LEN];
};

struct nosh_build_udp_header {
  __be16 source_port;
  __be16 destination_port;
  __be16 length;
  __be16 checksum;
};

struct nosh_build_dns_header {
  __be16 transaction_id;
  __be16 flags;
  __be16 question_count;
  __be16 answer_count;
  __be16 authority_count;
  __be16 additional_count;
};

struct nosh_build_dns_packet {
  __u32 udp_offset;
  __u32 dns_offset;
  __u32 dns_end;
  __u16 source_port;
  __u16 destination_port;
  __u8 family;
  __u8 reserved[3];
  __u8 source_address[NOSH_BUILD_ADDRESS_LEN];
  __u8 destination_address[NOSH_BUILD_ADDRESS_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NOSH_BUILD_RINGBUF_BYTES);
} events SEC(".maps");

/*
 * Per-CPU values make max_duration_ns a race-free local compare/store. The
 * loader folds every CPU slot after detaching the programs.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __uint(max_entries, NOSH_BUILD_SYSCALL_MAX_ENTRIES);
  __type(key, struct nosh_build_syscall_key);
  __type(value, struct nosh_build_syscall_totals);
} syscall_totals SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NOSH_BUILD_INFLIGHT_MAX_ENTRIES);
  __type(key, __u64);
  __type(value, struct nosh_build_inflight_syscall);
} inflight_syscalls SEC(".maps");

/*
 * Policy capture must never silently evict an older path. Exhaustion is
 * surfaced through NOSH_BUILD_STAT_FILE_MAP_FULL and fails completion.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, NOSH_BUILD_FILE_MAX_ENTRIES);
  __type(key, struct nosh_build_file_key);
  __type(value, struct nosh_build_file_totals);
} file_totals SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, NOSH_BUILD_STAT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct nosh_build_config);
} session_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} target_cgroup SEC(".maps");

static __always_inline void increment_stat(enum nosh_build_stat stat)
{
  __u32 key = stat;
  __u64 *value = bpf_map_lookup_elem(&stats, &key);

  if (value)
    *value += 1;
}

static __always_inline __u64 configured_cgroup_id(void)
{
  __u32 key = 0;
  struct nosh_build_config *config =
    bpf_map_lookup_elem(&session_config, &key);

  if (!config || !config->target_cgroup_id) {
    increment_stat(NOSH_BUILD_STAT_CONFIG_MISSING);
    return 0;
  }
  return config->target_cgroup_id;
}

/* Tracepoints are global; the kernel helper includes descendant cgroups. */
static __always_inline bool current_is_target_descendant(void)
{
  long result = bpf_current_task_under_cgroup(&target_cgroup, 0);

  if (result < 0) {
    increment_stat(NOSH_BUILD_STAT_CGROUP_FILTER_ERRORS);
    return false;
  }
  return result == 1;
}

static __always_inline void read_process_identity(__u32 *pid,
                                                   __u32 *tid,
                                                   __u32 *uid,
                                                   __u32 *gid)
{
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 uid_gid = bpf_get_current_uid_gid();

  *pid = pid_tgid >> 32;
  *tid = (__u32)pid_tgid;
  *uid = (__u32)uid_gid;
  *gid = uid_gid >> 32;
}

static __always_inline __u32 read_parent_pid(void)
{
  struct task_struct *task =
    (struct task_struct *)bpf_get_current_task();
  struct task_struct *parent = BPF_CORE_READ(task, real_parent);

  return parent ? BPF_CORE_READ(parent, tgid) : 0;
}

SEC("tracepoint/sched/sched_process_exec")
int nosh_build_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
  struct nosh_build_process_event *event;
  __u64 target_id = configured_cgroup_id();
  __u32 filename_offset;

  if (!target_id || !current_is_target_descendant())
    return 0;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    increment_stat(NOSH_BUILD_STAT_RINGBUF_DROPS);
    return 0;
  }

  __builtin_memset(event, 0, sizeof(*event));

  event->header.timestamp_ns = bpf_ktime_get_ns();
  event->header.cgroup_id = bpf_get_current_cgroup_id();
  read_process_identity(&event->pid, &event->tid,
                        &event->uid, &event->gid);
  event->ppid = read_parent_pid();
  event->exit_code = 0;
  event->header.schema_version = NOSH_BUILD_SCHEMA_VERSION;
  event->header.event_size = sizeof(*event);
  event->header.event_kind = NOSH_BUILD_EVENT_PROCESS_EXEC;
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  filename_offset = ctx->__data_loc_filename & 0xffff;
  if (filename_offset)
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              (const void *)ctx + filename_offset);
  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int nosh_build_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
  struct nosh_build_process_event *event;
  struct task_struct *task;
  __u64 pid_tgid;
  __u64 target_id = configured_cgroup_id();

  (void)ctx;
  /* Clear a tracked entry even if the task moved out before it exited. */
  pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&inflight_syscalls, &pid_tgid);
  if (!target_id || !current_is_target_descendant())
    return 0;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    increment_stat(NOSH_BUILD_STAT_RINGBUF_DROPS);
    return 0;
  }

  __builtin_memset(event, 0, sizeof(*event));
  task = (struct task_struct *)bpf_get_current_task();
  event->header.timestamp_ns = bpf_ktime_get_ns();
  event->header.cgroup_id = bpf_get_current_cgroup_id();
  read_process_identity(&event->pid, &event->tid,
                        &event->uid, &event->gid);
  event->ppid = read_parent_pid();
  event->exit_code = BPF_CORE_READ(task, exit_code);
  event->header.schema_version = NOSH_BUILD_SCHEMA_VERSION;
  event->header.event_size = sizeof(*event);
  event->header.event_kind = NOSH_BUILD_EVENT_PROCESS_EXIT;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

static __always_inline struct nosh_build_syscall_totals *
get_syscall_totals(__s64 syscall_number)
{
  struct nosh_build_syscall_key key = {
    .syscall_number = syscall_number,
  };
  struct nosh_build_syscall_totals initial = {};
  struct nosh_build_syscall_totals *totals;

  totals = bpf_map_lookup_elem(&syscall_totals, &key);
  if (totals)
    return totals;

  bpf_map_update_elem(&syscall_totals, &key, &initial, BPF_NOEXIST);
  totals = bpf_map_lookup_elem(&syscall_totals, &key);
  if (!totals)
    increment_stat(NOSH_BUILD_STAT_SYSCALL_MAP_FULL);
  return totals;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int nosh_build_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
  struct nosh_build_inflight_syscall inflight;
  struct nosh_build_syscall_totals *totals;
  __u64 pid_tgid;
  __u64 target_id = configured_cgroup_id();

  if (!target_id || !current_is_target_descendant())
    return 0;

  totals = get_syscall_totals(ctx->id);
  if (totals)
    totals->calls += 1;

  pid_tgid = bpf_get_current_pid_tgid();
  inflight.started_ns = bpf_ktime_get_ns();
  inflight.syscall_number = ctx->id;
  if (bpf_map_update_elem(&inflight_syscalls, &pid_tgid,
                          &inflight, BPF_ANY) != 0)
    increment_stat(NOSH_BUILD_STAT_INFLIGHT_MAP_FULL);
  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int nosh_build_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
  struct nosh_build_inflight_syscall *inflight;
  struct nosh_build_syscall_totals *totals;
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 duration;

  inflight = bpf_map_lookup_elem(&inflight_syscalls, &pid_tgid);
  if (!inflight)
    return 0;

  totals = get_syscall_totals(inflight->syscall_number);
  if (totals) {
    duration = bpf_ktime_get_ns() - inflight->started_ns;
    totals->completions += 1;
    totals->total_duration_ns += duration;
    if (ctx->ret < 0 && ctx->ret >= -4095)
      totals->errors += 1;
    if (duration > totals->max_duration_ns)
      totals->max_duration_ns = duration;
  }

  bpf_map_delete_elem(&inflight_syscalls, &pid_tgid);
  return 0;
}

static __always_inline void add_file_access_counts(
    struct nosh_build_file_totals *totals,
    __u32 access)
{
  __sync_fetch_and_add(&totals->opens, 1);
  if (access & NOSH_BUILD_FILE_ACCESS_READ)
    __sync_fetch_and_add(&totals->read_opens, 1);
  if (access & NOSH_BUILD_FILE_ACCESS_WRITE)
    __sync_fetch_and_add(&totals->write_opens, 1);
  if (access & NOSH_BUILD_FILE_ACCESS_EXECUTE)
    __sync_fetch_and_add(&totals->execute_opens, 1);
  if (access & NOSH_BUILD_FILE_ACCESS_CREATE)
    __sync_fetch_and_add(&totals->create_opens, 1);
}

/*
 * file_open is sleepable, so bpf_d_path can resolve a metadata-only absolute
 * path without reading file contents. The program is autoloaded only for the
 * capability-gated policy depth and always preserves prior LSM decisions.
 */
SEC("lsm.s/file_open")
int BPF_PROG(nosh_build_file_open, struct file *file, int ret)
{
  struct nosh_build_file_key key = {};
  struct nosh_build_file_totals initial = {};
  struct nosh_build_file_totals *totals;
  struct nosh_build_config *config;
  __u64 timestamp_ns;
  __u32 config_key = 0;
  __u32 mode;
  __u32 access = 0;
  long path_length;

  if (ret)
    return ret;
  config = bpf_map_lookup_elem(&session_config, &config_key);
  if (!config || !config->target_cgroup_id) {
    increment_stat(NOSH_BUILD_STAT_CONFIG_MISSING);
    return ret;
  }
  if (config->collection_depth != NOSH_BUILD_DEPTH_POLICY)
    return ret;
  if (!current_is_target_descendant())
    return ret;

  path_length = bpf_d_path(&file->f_path, key.path, sizeof(key.path));
  if (path_length <= 1 || path_length > sizeof(key.path)) {
    increment_stat(NOSH_BUILD_STAT_FILE_PATH_ERRORS);
    return ret;
  }

  mode = BPF_CORE_READ(file, f_mode);
  if (mode & NOSH_BUILD_FMODE_READ)
    access |= NOSH_BUILD_FILE_ACCESS_READ;
  if (mode & NOSH_BUILD_FMODE_WRITE)
    access |= NOSH_BUILD_FILE_ACCESS_WRITE;
  if (mode & NOSH_BUILD_FMODE_EXEC)
    access |= NOSH_BUILD_FILE_ACCESS_EXECUTE;
  if (mode & NOSH_BUILD_FMODE_CREATED)
    access |= NOSH_BUILD_FILE_ACCESS_CREATE;

  timestamp_ns = bpf_ktime_get_ns();
  totals = bpf_map_lookup_elem(&file_totals, &key);
  if (!totals) {
    initial.first_seen_ns = timestamp_ns;
    initial.last_seen_ns = timestamp_ns;
    initial.opens = 1;
    initial.read_opens = !!(access & NOSH_BUILD_FILE_ACCESS_READ);
    initial.write_opens = !!(access & NOSH_BUILD_FILE_ACCESS_WRITE);
    initial.execute_opens = !!(access & NOSH_BUILD_FILE_ACCESS_EXECUTE);
    initial.create_opens = !!(access & NOSH_BUILD_FILE_ACCESS_CREATE);
    if (bpf_map_update_elem(&file_totals, &key, &initial,
                            BPF_NOEXIST) == 0) {
      increment_stat(NOSH_BUILD_STAT_FILE_OPEN_OBSERVATIONS);
      return ret;
    }
    /* A concurrent CPU may have inserted the same path. */
    totals = bpf_map_lookup_elem(&file_totals, &key);
    if (!totals) {
      increment_stat(NOSH_BUILD_STAT_FILE_MAP_FULL);
      return ret;
    }
  }

  add_file_access_counts(totals, access);
  totals->last_seen_ns = timestamp_ns;
  increment_stat(NOSH_BUILD_STAT_FILE_OPEN_OBSERVATIONS);
  return ret;
}

static __always_inline int load_network_bytes(struct __sk_buff *skb,
                                               __u32 offset,
                                               void *destination,
                                               __u32 length)
{
  return bpf_skb_load_bytes_relative(skb, offset, destination, length,
                                     NOSH_BUILD_HDR_START_NET);
}

static __always_inline int load_dns_bytes(struct __sk_buff *skb,
                                          __u32 dns_end,
                                          __u32 offset,
                                          void *destination,
                                          __u32 length)
{
  if (offset > dns_end || length > dns_end - offset)
    return -1;
  return load_network_bytes(skb, offset, destination, length);
}

static __always_inline int parse_udp_packet(struct __sk_buff *skb,
                                            struct nosh_build_dns_packet *packet)
{
  struct nosh_build_udp_header udp = {};
  __u32 network_end = 0;
  __u32 udp_length;
  __u8 first_byte = 0;

  __builtin_memset(packet, 0, sizeof(*packet));
  if (load_network_bytes(skb, 0, &first_byte, sizeof(first_byte)) < 0)
    return -1;
  if ((first_byte >> 4) == NOSH_BUILD_FAMILY_IPV4) {
    struct nosh_build_ipv4_header ipv4 = {};
    __u16 fragment_offset;

    if (load_network_bytes(skb, 0, &ipv4, sizeof(ipv4)) < 0)
      return -1;
    packet->udp_offset = (ipv4.version_ihl & 0x0f) * 4;
    if (packet->udp_offset < sizeof(ipv4) ||
        ipv4.protocol != NOSH_BUILD_IPPROTO_UDP)
      return 1;
    network_end = bpf_ntohs(ipv4.total_length);
    if (network_end < packet->udp_offset + sizeof(udp))
      return -1;
    fragment_offset = bpf_ntohs(ipv4.fragment_offset);
    if (fragment_offset & (NOSH_BUILD_IPV4_FRAGMENT_OFFSET_MASK |
                           NOSH_BUILD_IPV4_MORE_FRAGMENTS))
      return 1;
    packet->family = NOSH_BUILD_FAMILY_IPV4;
    __builtin_memcpy(packet->source_address, &ipv4.source_address,
                     sizeof(ipv4.source_address));
    __builtin_memcpy(packet->destination_address, &ipv4.destination_address,
                     sizeof(ipv4.destination_address));
  } else if ((first_byte >> 4) == NOSH_BUILD_FAMILY_IPV6) {
    struct nosh_build_ipv6_header ipv6 = {};

    if (load_network_bytes(skb, 0, &ipv6, sizeof(ipv6)) < 0)
      return -1;
    if (ipv6.next_header != NOSH_BUILD_IPPROTO_UDP)
      return 1;
    packet->family = NOSH_BUILD_FAMILY_IPV6;
    packet->udp_offset = sizeof(ipv6);
    network_end = sizeof(ipv6) + bpf_ntohs(ipv6.payload_length);
    if (network_end < packet->udp_offset + sizeof(udp))
      return -1;
    __builtin_memcpy(packet->source_address, ipv6.source_address,
                     sizeof(packet->source_address));
    __builtin_memcpy(packet->destination_address, ipv6.destination_address,
                     sizeof(packet->destination_address));
  } else {
    return 1;
  }
  if (load_network_bytes(skb, packet->udp_offset, &udp, sizeof(udp)) < 0)
    return -1;
  packet->source_port = bpf_ntohs(udp.source_port);
  packet->destination_port = bpf_ntohs(udp.destination_port);
  packet->dns_offset = packet->udp_offset + sizeof(udp);
  udp_length = bpf_ntohs(udp.length);
  if (udp_length >= sizeof(udp) + sizeof(struct nosh_build_dns_header) &&
      packet->udp_offset + udp_length >= packet->udp_offset &&
      packet->udp_offset + udp_length <= network_end)
    packet->dns_end = packet->udp_offset + udp_length;
  return 0;
}

/* Avoid reserving ring space for the overwhelmingly common non-DNS packet. */
static __always_inline int udp_dns_candidate(
    struct __sk_buff *skb,
    bool response,
    struct nosh_build_dns_packet *packet,
    struct nosh_build_dns_header *dns)
{
  __u16 flags;
  int result = parse_udp_packet(skb, packet);

  if (result)
    return result;
  if ((!response && packet->destination_port != NOSH_BUILD_DNS_PORT) ||
      (response && packet->source_port != NOSH_BUILD_DNS_PORT))
    return 1;
  if (!(response ? packet->destination_port : packet->source_port))
    return -1;
  if (packet->dns_end <
      packet->dns_offset + sizeof(struct nosh_build_dns_header))
    return -1;
  if (load_dns_bytes(skb, packet->dns_end, packet->dns_offset,
                     dns, sizeof(*dns)) < 0)
    return -1;
  flags = bpf_ntohs(dns->flags);
  if (!!(flags & NOSH_BUILD_DNS_RESPONSE) != response ||
      !bpf_ntohs(dns->question_count))
    return 1;
  return 0;
}

/*
 * Keep the kernel-side DNS collector deliberately small. It scopes packets,
 * retains correlation metadata, and copies one bounded DNS message. Trusted
 * userspace owns all label, compression, and answer decoding.
 */
static __always_inline void clear_dns_wire_event(
    struct nosh_build_dns_wire_event *event)
{
  volatile __u64 *words = (volatile __u64 *)event;
  __u32 index;

  _Static_assert(sizeof(*event) % sizeof(*words) == 0,
                 "DNS wire event must be word aligned");
#pragma clang loop unroll(disable)
  for (index = 0; index < sizeof(*event) / sizeof(*words); index++)
    words[index] = 0;
}

static __always_inline int copy_dns_wire(
    struct __sk_buff *skb,
    const struct nosh_build_dns_packet *packet,
    struct nosh_build_dns_wire_event *event,
    __u32 wire_length)
{
  __u32 offset = 0;
  __u32 tail;

#pragma clang loop unroll(disable)
  for (offset = 0; offset < NOSH_BUILD_DNS_WIRE_LEN;
       offset += NOSH_BUILD_DNS_COPY_CHUNK_LEN) {
    if (offset > NOSH_BUILD_DNS_WIRE_LEN -
                 NOSH_BUILD_DNS_COPY_CHUNK_LEN ||
        offset > wire_length ||
        NOSH_BUILD_DNS_COPY_CHUNK_LEN > wire_length - offset)
      break;
    if (load_dns_bytes(skb, packet->dns_end, packet->dns_offset + offset,
                       event->wire + offset,
                       NOSH_BUILD_DNS_COPY_CHUNK_LEN) < 0)
      return -1;
  }
#pragma clang loop unroll(disable)
  for (tail = 0; tail < NOSH_BUILD_DNS_COPY_CHUNK_LEN; tail++) {
    if (offset + tail >= wire_length)
      break;
    if (offset + tail >= NOSH_BUILD_DNS_WIRE_LEN)
      return -1;
    if (load_dns_bytes(skb, packet->dns_end,
                       packet->dns_offset + offset + tail,
                       event->wire + offset + tail, 1) < 0)
      return -1;
  }
  return 0;
}

static __always_inline int capture_dns_wire(
    struct __sk_buff *skb,
    const struct nosh_build_dns_packet *packet,
    bool response,
    __u64 target_id)
{
  struct nosh_build_dns_wire_event *event;
  __u32 original_length = packet->dns_end - packet->dns_offset;
  __u32 wire_length = original_length;

  if (wire_length > NOSH_BUILD_DNS_WIRE_LEN)
    wire_length = NOSH_BUILD_DNS_WIRE_LEN;
  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    increment_stat(NOSH_BUILD_STAT_RINGBUF_DROPS);
    return -1;
  }
  clear_dns_wire_event(event);
  event->header.timestamp_ns = bpf_ktime_get_ns();
  event->header.cgroup_id = target_id;
  event->header.schema_version = NOSH_BUILD_SCHEMA_VERSION;
  event->header.event_size = sizeof(*event);
  event->header.event_kind = response ? NOSH_BUILD_EVENT_DNS_RESPONSE :
    NOSH_BUILD_EVENT_DNS_QUERY;
  event->socket_cookie = bpf_get_socket_cookie(skb);
  event->client_port = response ? packet->destination_port :
    packet->source_port;
  event->server_port = response ? packet->source_port :
    packet->destination_port;
  event->wire_length = wire_length;
  event->original_length = original_length > 0xffffu ? 0xffffu :
    original_length;
  event->family = packet->family;
  if (response)
    __builtin_memcpy(event->server_address, packet->source_address,
                     sizeof(event->server_address));
  else
    __builtin_memcpy(event->server_address, packet->destination_address,
                     sizeof(event->server_address));
  if (!event->socket_cookie)
    increment_stat(NOSH_BUILD_STAT_DNS_CORRELATION_MISSING);
  if (original_length > wire_length)
    increment_stat(response ? NOSH_BUILD_STAT_DNS_TRUNCATED_RESPONSES :
                   NOSH_BUILD_STAT_DNS_TRUNCATED_NAMES);
  if (copy_dns_wire(skb, packet, event, wire_length) < 0) {
    bpf_ringbuf_discard(event, 0);
    increment_stat(NOSH_BUILD_STAT_DNS_PARSE_ERRORS);
    return -1;
  }
  bpf_ringbuf_submit(event, 0);
  increment_stat(response ? NOSH_BUILD_STAT_DNS_RESPONSE_OBSERVATIONS :
                 NOSH_BUILD_STAT_DNS_QUERY_OBSERVATIONS);
  return 0;
}

SEC("cgroup_skb/egress")
int nosh_build_dns_egress(struct __sk_buff *skb)
{
  struct nosh_build_dns_packet packet = {};
  struct nosh_build_dns_header dns = {};
  __u64 target_id = configured_cgroup_id();
  int parse_result;

  if (!target_id)
    return NOSH_BUILD_ALLOW;
  parse_result = udp_dns_candidate(skb, false, &packet, &dns);
  if (parse_result) {
    if (parse_result < 0)
      increment_stat(NOSH_BUILD_STAT_DNS_PARSE_ERRORS);
    return NOSH_BUILD_ALLOW;
  }
  capture_dns_wire(skb, &packet, false, target_id);
  return NOSH_BUILD_ALLOW;
}

SEC("cgroup_skb/ingress")
int nosh_build_dns_ingress(struct __sk_buff *skb)
{
  struct nosh_build_dns_packet packet = {};
  struct nosh_build_dns_header dns = {};
  __u64 target_id = configured_cgroup_id();
  int parse_result;

  if (!target_id)
    return NOSH_BUILD_ALLOW;
  parse_result = udp_dns_candidate(skb, true, &packet, &dns);
  if (parse_result) {
    if (parse_result < 0)
      increment_stat(NOSH_BUILD_STAT_DNS_PARSE_ERRORS);
    return NOSH_BUILD_ALLOW;
  }
  capture_dns_wire(skb, &packet, true, target_id);
  return NOSH_BUILD_ALLOW;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
