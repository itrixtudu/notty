// SPDX-License-Identifier: 0BSD

#ifndef NOSH_URL_TEST_BPF_H
#define NOSH_URL_TEST_BPF_H

#include <linux/bpf.h>

int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_update_elem(int fd,
                        const void *key,
                        const void *value,
                        __u64 flags);

#endif
