// SPDX-License-Identifier: 0BSD

#ifndef NOSH_URL_TEST_LIBBPF_H
#define NOSH_URL_TEST_LIBBPF_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct bpf_link;
struct bpf_map;
struct bpf_program;
struct ring_buffer;

enum libbpf_strict_mode {
  LIBBPF_STRICT_ALL = 0xffffffff,
};

struct bpf_uprobe_opts {
  size_t sz;
  size_t ref_ctr_offset;
  __u64 bpf_cookie;
  bool retprobe;
  const char *func_name;
};

typedef int (*ring_buffer_sample_fn)(void *context, void *data, size_t size);

int libbpf_set_strict_mode(enum libbpf_strict_mode mode);
long libbpf_get_error(const void *pointer);
int libbpf_num_possible_cpus(void);
int bpf_map__fd(const struct bpf_map *map);
struct bpf_link *bpf_program__attach_uprobe_opts(
  const struct bpf_program *program,
  pid_t pid,
  const char *binary_path,
  size_t function_offset,
  const struct bpf_uprobe_opts *options);
int bpf_link__destroy(struct bpf_link *link);
struct ring_buffer *ring_buffer__new(int map_fd,
                                    ring_buffer_sample_fn callback,
                                    void *context,
                                    const void *options);
int ring_buffer__poll(struct ring_buffer *ring, int timeout_ms);
int ring_buffer__consume(struct ring_buffer *ring);
void ring_buffer__free(struct ring_buffer *ring);

#endif
