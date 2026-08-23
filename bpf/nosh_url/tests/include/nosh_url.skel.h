// SPDX-License-Identifier: 0BSD

#ifndef NOSH_URL_TEST_SKEL_H
#define NOSH_URL_TEST_SKEL_H

#include <bpf/libbpf.h>

struct nosh_url_bpf {
  struct {
    struct bpf_map *events;
    struct bpf_map *stats;
    struct bpf_map *session_config;
    struct bpf_map *target_cgroup;
  } maps;
  struct {
    struct bpf_program *nosh_url_curl_easy_setopt;
  } progs;
};

struct nosh_url_bpf *nosh_url_bpf__open(void);
int nosh_url_bpf__load(struct nosh_url_bpf *skeleton);
void nosh_url_bpf__destroy(struct nosh_url_bpf *skeleton);

#endif
