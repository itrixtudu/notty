// SPDX-License-Identifier: 0BSD

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "nosh_url.skel.h"

#define NOSH_URL_TEST_CONSUME_MAX 8
#define NOSH_URL_TEST_TRACE_MAX 32

static bool lifecycle_test_active;
static int lifecycle_consume_results[NOSH_URL_TEST_CONSUME_MAX];
static size_t lifecycle_consume_count;
static size_t lifecycle_consume_index;
static char lifecycle_trace[NOSH_URL_TEST_TRACE_MAX];
static size_t lifecycle_trace_length;

static void lifecycle_trace_append(char value)
{
  if (lifecycle_trace_length + 1 >= sizeof(lifecycle_trace))
    return;
  lifecycle_trace[lifecycle_trace_length++] = value;
  lifecycle_trace[lifecycle_trace_length] = '\0';
}

void nosh_url_test_lifecycle_reset(const int *consume_results,
                                   size_t consume_count)
{
  size_t index;

  lifecycle_test_active = true;
  lifecycle_consume_count = consume_count > NOSH_URL_TEST_CONSUME_MAX
    ? NOSH_URL_TEST_CONSUME_MAX : consume_count;
  lifecycle_consume_index = 0;
  lifecycle_trace_length = 0;
  lifecycle_trace[0] = '\0';
  for (index = 0; index < lifecycle_consume_count; index++)
    lifecycle_consume_results[index] = consume_results[index];
}

bool nosh_url_test_lifecycle_matches(const char *expected)
{
  return expected && !strcmp(lifecycle_trace, expected);
}

int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
  (void)fd;
  (void)key;
  if (lifecycle_test_active) {
    *(__u64 *)value = 0;
    return 0;
  }
  (void)value;
  errno = ENOSYS;
  return -1;
}

int bpf_map_update_elem(int fd,
                        const void *key,
                        const void *value,
                        __u64 flags)
{
  (void)fd;
  (void)key;
  (void)value;
  (void)flags;
  errno = ENOSYS;
  return -1;
}

int libbpf_set_strict_mode(enum libbpf_strict_mode mode)
{
  (void)mode;
  return 0;
}

long libbpf_get_error(const void *pointer)
{
  return pointer ? 0 : -EINVAL;
}

int libbpf_num_possible_cpus(void)
{
  return 1;
}

int bpf_map__fd(const struct bpf_map *map)
{
  (void)map;
  return -1;
}

struct bpf_link *bpf_program__attach_uprobe_opts(
  const struct bpf_program *program,
  pid_t pid,
  const char *binary_path,
  size_t function_offset,
  const struct bpf_uprobe_opts *options)
{
  (void)program;
  (void)pid;
  (void)binary_path;
  (void)function_offset;
  (void)options;
  return NULL;
}

int bpf_link__destroy(struct bpf_link *link)
{
  (void)link;
  if (lifecycle_test_active)
    lifecycle_trace_append('D');
  return 0;
}

struct ring_buffer *ring_buffer__new(int map_fd,
                                    ring_buffer_sample_fn callback,
                                    void *context,
                                    const void *options)
{
  (void)map_fd;
  (void)callback;
  (void)context;
  (void)options;
  return NULL;
}

int ring_buffer__poll(struct ring_buffer *ring, int timeout_ms)
{
  (void)ring;
  (void)timeout_ms;
  return -ENOSYS;
}

int ring_buffer__consume(struct ring_buffer *ring)
{
  (void)ring;
  if (lifecycle_test_active) {
    lifecycle_trace_append('C');
    if (lifecycle_consume_index < lifecycle_consume_count)
      return lifecycle_consume_results[lifecycle_consume_index++];
  }
  return 0;
}

void ring_buffer__free(struct ring_buffer *ring)
{
  (void)ring;
}

struct nosh_url_bpf *nosh_url_bpf__open(void)
{
  return NULL;
}

int nosh_url_bpf__load(struct nosh_url_bpf *skeleton)
{
  (void)skeleton;
  return -ENOSYS;
}

void nosh_url_bpf__destroy(struct nosh_url_bpf *skeleton)
{
  (void)skeleton;
}
