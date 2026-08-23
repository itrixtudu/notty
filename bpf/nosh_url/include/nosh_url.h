// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#ifndef NOSH_URL_H
#define NOSH_URL_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define NOSH_URL_SCHEMA_VERSION 1
#define NOSH_URL_COMM_LEN 16
#define NOSH_URL_RAW_MAX 2048
#define NOSH_URL_PATH_MAX 512
#define NOSH_URL_PROVIDER_LIBCURL 1
#define NOSH_URL_CURLOPT_URL 10002L

enum nosh_url_event_kind {
  NOSH_URL_EVENT_UNSPECIFIED = 0,
  NOSH_URL_EVENT_URL = 1,
};

enum nosh_url_stat {
  NOSH_URL_STAT_RINGBUF_DROPS = 0,
  NOSH_URL_STAT_CONFIG_MISSING = 1,
  NOSH_URL_STAT_CGROUP_FILTER_ERRORS = 2,
  NOSH_URL_STAT_READ_ERRORS = 3,
  NOSH_URL_STAT_OPTION_CALLS = 4,
  NOSH_URL_STAT_OBSERVATIONS = 5,
  NOSH_URL_STAT_MAX = 6,
};

struct nosh_url_config {
  __u64 target_cgroup_id;
};

/*
 * raw_url is an internal kernel-to-loader transport field. The loader must
 * sanitize it before writing any evidence and must never log it on failure.
 */
struct nosh_url_event {
  __u64 timestamp_ns;
  __u64 target_cgroup_id;
  __u64 observed_cgroup_id;
  __u32 pid;
  __u32 tid;
  __u16 schema_version;
  __u16 event_size;
  __u16 raw_length;
  __u8 event_kind;
  __u8 provider;
  char comm[NOSH_URL_COMM_LEN];
  char raw_url[NOSH_URL_RAW_MAX];
};

#endif
