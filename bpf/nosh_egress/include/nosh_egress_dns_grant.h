// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
#ifndef NOSH_EGRESS_DNS_GRANT_H
#define NOSH_EGRESS_DNS_GRANT_H

/* Verifier-isolated helpers take typed leaf objects, not pointer bundles. */
__noinline int record_dns_answer(
    const struct nosh_egress_config *config, const struct nosh_packet *packet,
    const struct nosh_dns_name *question, const struct nosh_egress_dns_answer *answer,
    __u32 metadata)
{
  if (!config || !packet || !question || !answer)
    return -1;
  emit_dns_answer_record(config, metadata >> 16, packet, metadata, question, answer);
  return 0;
}

__noinline int commit_one_dns_grant(
    const struct nosh_egress_config *config,
    const struct nosh_egress_dns_tx_value *transaction,
    const struct nosh_egress_dns_answer *answer, __u32 slot, __u64 *expires)
{
  if (!config || !transaction || !answer || !expires ||
      slot >= NOSH_EGRESS_DOMAIN_RULE_SLOTS)
    return -1;
  return insert_dns_grant(config, transaction->rule_ids[slot],
      transaction->protocols[slot], transaction->ports[slot], answer->family,
      answer->address, answer->ttl, expires);
}

struct nosh_dns_grant_record {
  __u64 expires;
  __u32 rule;
  __u16 port;
  __u16 txid;
  __u8 protocol;
  __u8 hook;
};

__noinline int record_dns_grant(
    const struct nosh_egress_config *config, const struct nosh_packet *packet,
    const struct nosh_dns_name *question, const struct nosh_egress_dns_answer *answer,
    const struct nosh_dns_grant_record *record)
{
  if (!config || !packet || !question || !answer || !record)
    return -1;
  emit_event(config, record->hook, answer->family, record->protocol, 53,
      record->port, packet->source, answer->address, NOSH_EGRESS_VERDICT_ALLOW,
      NOSH_EGRESS_REASON_DNS_GRANT, record->rule, 0, record->txid,
      question, record->expires);
  return 0;
}

#endif
