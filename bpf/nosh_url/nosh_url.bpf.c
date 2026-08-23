// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "include/nosh_url.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, NOSH_URL_STAT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct nosh_url_config);
} session_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} target_cgroup SEC(".maps");

static __always_inline void increment_stat(enum nosh_url_stat stat)
{
  __u32 key = stat;
  __u64 *value = bpf_map_lookup_elem(&stats, &key);

  if (value)
    *value += 1;
}

static __always_inline struct nosh_url_config *configured_session(void)
{
  __u32 key = 0;
  struct nosh_url_config *config =
    bpf_map_lookup_elem(&session_config, &key);

  if (!config || !config->target_cgroup_id) {
    increment_stat(NOSH_URL_STAT_CONFIG_MISSING);
    return NULL;
  }
  return config;
}

/* Uprobes are global; this kernel-side test includes descendant cgroups. */
static __always_inline bool current_is_target_descendant(void)
{
  long result = bpf_current_task_under_cgroup(&target_cgroup, 0);

  if (result < 0) {
    increment_stat(NOSH_URL_STAT_CGROUP_FILTER_ERRORS);
    return false;
  }
  return result == 1;
}

/*
 * Clang 14 does not lower a memset covering the full URL event: the raw URL
 * buffer makes the object large enough that it leaves an unsupported memset
 * intrinsic in the BPF program. Clear it a word at a time instead. Volatile
 * stores keep LLVM from folding this bounded loop back into the unsupported
 * intrinsic, while initializing the unread URL tail before the fixed-size
 * ring-buffer record reaches userspace.
 */
static __always_inline void clear_url_event(struct nosh_url_event *event)
{
  volatile __u64 *words = (volatile __u64 *)event;
  __u32 index;

  _Static_assert(sizeof(*event) % sizeof(*words) == 0,
                 "URL event must be word aligned");
#pragma clang loop unroll(disable)
  for (index = 0; index < sizeof(*event) / sizeof(*words); index++)
    words[index] = 0;
}

SEC("uprobe")
int nosh_url_curl_easy_setopt(struct pt_regs *ctx)
{
  struct nosh_url_config *config;
  struct nosh_url_event *event;
  const char *url;
  __u64 pid_tgid;
  long option;
  long length;

  option = (long)PT_REGS_PARM2(ctx);
  if (option != NOSH_URL_CURLOPT_URL)
    return 0;

  config = configured_session();
  if (!config || !current_is_target_descendant())
    return 0;

  increment_stat(NOSH_URL_STAT_OPTION_CALLS);
  url = (const char *)PT_REGS_PARM3(ctx);
  if (!url) {
    increment_stat(NOSH_URL_STAT_READ_ERRORS);
    return 0;
  }

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event) {
    increment_stat(NOSH_URL_STAT_RINGBUF_DROPS);
    return 0;
  }
  clear_url_event(event);

  length = bpf_probe_read_user_str(event->raw_url,
                                   sizeof(event->raw_url), url);
  if (length <= 1 || length >= NOSH_URL_RAW_MAX) {
    increment_stat(NOSH_URL_STAT_READ_ERRORS);
    bpf_ringbuf_discard(event, 0);
    return 0;
  }

  pid_tgid = bpf_get_current_pid_tgid();
  event->timestamp_ns = bpf_ktime_get_ns();
  event->target_cgroup_id = config->target_cgroup_id;
  event->observed_cgroup_id = bpf_get_current_cgroup_id();
  event->pid = pid_tgid >> 32;
  event->tid = (__u32)pid_tgid;
  event->schema_version = NOSH_URL_SCHEMA_VERSION;
  event->event_size = sizeof(*event);
  event->raw_length = length;
  event->event_kind = NOSH_URL_EVENT_URL;
  event->provider = NOSH_URL_PROVIDER_LIBCURL;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  increment_stat(NOSH_URL_STAT_OBSERVATIONS);
  bpf_ringbuf_submit(event, 0);
  return 0;
}
