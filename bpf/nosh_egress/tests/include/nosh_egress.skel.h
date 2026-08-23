/* Syntax-check stand-in; production builds generate this file with bpftool. */
#ifndef NOSH_EGRESS_TEST_SKEL_H
#define NOSH_EGRESS_TEST_SKEL_H

struct nosh_egress_bpf {
  struct {
    struct bpf_map *session_config;
    struct bpf_map *policy_identity;
    struct bpf_map *containment;
    struct bpf_map *static_v4;
    struct bpf_map *static_v6;
    struct bpf_map *domain_rules;
    struct bpf_map *resolvers;
    struct bpf_map *dynamic_grants;
    struct bpf_map *dns_transactions;
    struct bpf_map *dns_transaction_scratch;
    struct bpf_map *dns_response_scratch;
    struct bpf_map *stats;
    struct bpf_map *events;
  } maps;
  struct {
    struct bpf_program *nosh_egress_connect4;
    struct bpf_program *nosh_egress_connect6;
    struct bpf_program *nosh_egress_sendmsg4;
    struct bpf_program *nosh_egress_sendmsg6;
    struct bpf_program *nosh_egress_ingress;
    struct bpf_program *nosh_egress_egress;
  } progs;
};

static inline struct nosh_egress_bpf *nosh_egress_bpf__open_and_load(void)
{
  return (struct nosh_egress_bpf *)0;
}

static inline void nosh_egress_bpf__destroy(struct nosh_egress_bpf *object)
{
  (void)object;
}

#endif
