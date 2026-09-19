// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
#ifndef NOSH_EGRESS_DNS_COMMIT_H
#define NOSH_EGRESS_DNS_COMMIT_H

struct nosh_dns_commit_context {
  const struct nosh_egress_config *config;
  const struct nosh_packet *packet;
  struct nosh_egress_dns_tx_value *transaction;
  struct nosh_egress_dns_response_scratch *scratch;
  const struct nosh_dns_name *question;
  __u32 grants;
  __u16 flags;
  __u16 txid;
  __u8 hook;
};

/* One bounded helper iteration replaces one answer/rule pair. The verifier
 * can converge on the callback instead of expanding 64 paths through grant
 * insertion and ring-buffer emission. Called only after full validation. */
static long commit_dns_answer_rule(__u32 index, void *opaque)
{
  struct nosh_dns_commit_context *context = opaque;
  struct nosh_egress_dns_answer *candidate;
  __u32 answer_index = index / NOSH_EGRESS_DOMAIN_RULE_SLOTS;
  __u32 rule_slot = index % NOSH_EGRESS_DOMAIN_RULE_SLOTS;
  __u64 grant_expires_ns = 0;

  if (index >= NOSH_EGRESS_DNS_ANSWER_SLOTS * NOSH_EGRESS_DOMAIN_RULE_SLOTS ||
      answer_index >= context->scratch->answer_count)
    return 1;
  candidate = &context->scratch->answers[answer_index];
  if (!rule_slot)
    record_dns_answer(context->config, context->packet, context->question,
                       candidate, ((__u32)context->hook << 16) | context->txid);
  if ((context->flags & 0x000f) || !candidate->ttl ||
      rule_slot >= context->transaction->rule_count)
    return 0;
  if (commit_one_dns_grant(context->config, context->transaction, candidate,
                            rule_slot, &grant_expires_ns) == 0) {
    context->grants++;
    struct nosh_dns_grant_record record = {
      .expires = grant_expires_ns,
      .rule = context->transaction->rule_ids[rule_slot],
      .port = context->transaction->ports[rule_slot],
      .protocol = context->transaction->protocols[rule_slot],
      .txid = context->txid,
      .hook = context->hook,
    };
    record_dns_grant(context->config, context->packet, context->question,
                      candidate, &record);
  }
  return 0;
}
#endif
