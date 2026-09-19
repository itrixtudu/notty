// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
static __always_inline int reference_dns_name_matches(
    const struct nosh_dns_name *name,
    const struct nosh_egress_dns_tx_value *transaction)
{
  int index;

  if (name->length != transaction->question_length)
    return 0;
  for (index = 0; index < NOSH_EGRESS_DOMAIN_LEN; index++) {
    if (index >= name->length)
      break;
    if (name->bytes[index] != transaction->question[index])
      return 0;
  }
  return 1;
}

static __always_inline int reference_dns_name_matches_alias(
    const struct nosh_dns_name *name,
    const struct nosh_egress_dns_tx_value *transaction)
{
  int index;

  if (!transaction->alias_length ||
      name->length != transaction->alias_length)
    return 0;
  for (index = 0; index < NOSH_EGRESS_DOMAIN_LEN; index++) {
    if (index >= name->length)
      break;
    if (name->bytes[index] != transaction->alias[index])
      return 0;
  }
  return 1;
}

