// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
#ifndef NOSH_EGRESS_DNS_MATCH_H
#define NOSH_EGRESS_DNS_MATCH_H

struct nosh_dns_match_context {
  const struct nosh_dns_name *name;
  const char *expected;
  int matches;
};

static long compare_dns_character(__u32 index, void *opaque)
{
  struct nosh_dns_match_context *context = opaque;

  if (index >= NOSH_EGRESS_DOMAIN_LEN || index >= context->name->length)
    return 1;
  if (context->name->bytes[index] != context->expected[index]) {
    context->matches = 0;
    return 1;
  }
  return 0;
}

__noinline int dns_name_matches(
    const struct nosh_dns_name *name,
    const struct nosh_egress_dns_tx_value *transaction)
{
  if (!name || !transaction)
    return 0;
  struct nosh_dns_match_context context = {
    .name = name, .expected = transaction->question, .matches = 1,
  };

  if (name->length != transaction->question_length)
    return 0;
  if (bpf_loop(NOSH_EGRESS_DOMAIN_LEN, compare_dns_character, &context, 0) < 0)
    return 0;
  return context.matches;
}

__noinline int dns_name_matches_alias(
    const struct nosh_dns_name *name,
    const struct nosh_egress_dns_tx_value *transaction)
{
  if (!name || !transaction)
    return 0;
  struct nosh_dns_match_context context = {
    .name = name, .expected = transaction->alias, .matches = 1,
  };

  if (!transaction->alias_length || name->length != transaction->alias_length)
    return 0;
  if (bpf_loop(NOSH_EGRESS_DOMAIN_LEN, compare_dns_character, &context, 0) < 0)
    return 0;
  return context.matches;
}
#endif
