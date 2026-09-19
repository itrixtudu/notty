// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "nosh_egress.h"

struct nosh_packet { __u8 source[16]; };
struct nosh_dns_name { __u8 length; char bytes[NOSH_EGRESS_DOMAIN_LEN]; };
struct trace_record { unsigned kind, answer, rule, protocol, port, ttl; };
static struct trace_record trace[144];
static unsigned trace_count;
static int fail_odd_rules;

static void emit_dns_answer_record(const struct nosh_egress_config *config,
    __u8 hook, const struct nosh_packet *packet, __u16 txid,
    const struct nosh_dns_name *question,
    const struct nosh_egress_dns_answer *answer)
{
  assert(config && packet && question && hook == 5 && txid == 42);
  assert(trace_count < 144);
  trace[trace_count++] = (struct trace_record){1, answer->address[0], 0, 0, 0, answer->ttl};
}

static int insert_dns_grant(const struct nosh_egress_config *config,
    __u32 rule_id, __u8 protocol, __u16 port, __u8 family,
    const __u8 address[16], __u32 ttl, __u64 *expires_ns)
{
  assert(config && ttl && (family == 4 || family == 6));
  assert(protocol == (rule_id % 2 ? 6 : 17));
  assert(port == 440 + rule_id);
  assert(trace_count < 144);
  trace[trace_count++] = (struct trace_record){2, address[0], rule_id, protocol, port, ttl};
  *expires_ns = 1000ULL * ttl;
  return fail_odd_rules && rule_id % 2 ? -1 : 0;
}

static void emit_event(const struct nosh_egress_config *config,
    __u8 hook, __u8 family, __u8 protocol, __u16 source_port,
    __u16 port, const __u8 source[16], const __u8 destination[16],
    __u8 verdict, __u8 reason, __u32 rule, __u32 packet_len, __u16 txid,
    const struct nosh_dns_name *name, __u64 expires_ns)
{
  assert(config && name && source && (family == 4 || family == 6));
  assert(hook == 5 && source_port == 53 && txid == 42 && !packet_len);
  assert(verdict == NOSH_EGRESS_VERDICT_ALLOW && reason == NOSH_EGRESS_REASON_DNS_GRANT);
  assert(trace_count < 144);
  trace[trace_count++] = (struct trace_record){3, destination[0], rule, protocol, port, expires_ns / 1000};
}

#define __noinline __attribute__((noinline))
#include "nosh_egress_dns_grant.h"
#include "nosh_egress_dns_commit.h"

/* Original nested-loop order, retained as the behavioral reference. */
static void reference_commit(struct nosh_dns_commit_context *c)
{
  for (unsigned answer = 0; answer < NOSH_EGRESS_DNS_ANSWER_SLOTS; answer++) {
    if (answer >= c->scratch->answer_count) break;
    const struct nosh_egress_dns_answer *candidate = &c->scratch->answers[answer];
    emit_dns_answer_record(c->config, c->hook, c->packet, c->txid, c->question, candidate);
    if ((c->flags & 15) || !candidate->ttl) continue;
    for (unsigned rule = 0; rule < NOSH_EGRESS_DOMAIN_RULE_SLOTS; rule++) {
      __u64 expires = 0;
      if (rule >= c->transaction->rule_count) break;
      if (insert_dns_grant(c->config, c->transaction->rule_ids[rule],
          c->transaction->protocols[rule], c->transaction->ports[rule],
          candidate->family, candidate->address, candidate->ttl, &expires) == 0) {
        c->grants++;
        emit_event(c->config, c->hook, candidate->family, c->transaction->protocols[rule],
          53, c->transaction->ports[rule], c->packet->source, candidate->address,
          NOSH_EGRESS_VERDICT_ALLOW, NOSH_EGRESS_REASON_DNS_GRANT,
          c->transaction->rule_ids[rule], 0, c->txid, c->question, expires);
      }
    }
  }
}

int main(void)
{
  const unsigned counts[] = {0, 1, 7, 8, 255};
  struct nosh_egress_config config = {0};
  struct nosh_packet packet = {0};
  struct nosh_dns_name question = {0};
  struct nosh_egress_dns_tx_value transaction = {0};
  struct nosh_egress_dns_response_scratch scratch = {0};
  struct trace_record expected[144];
  unsigned cases = 0;
  for (unsigned a = 0; a < 5; a++)
  for (unsigned r = 0; r < 5; r++)
  for (unsigned flags = 0; flags < 4; flags++)
  for (unsigned ttls = 0; ttls < 3; ttls++)
  for (fail_odd_rules = 0; fail_odd_rules < 2; fail_odd_rules++) {
    scratch.answer_count = counts[a];
    transaction.rule_count = counts[r];
    for (unsigned i = 0; i < 8; i++) {
      scratch.answers[i].address[0] = i;
      scratch.answers[i].family = i % 2 ? 4 : 6;
      scratch.answers[i].ttl = ttls == 0 ? 0 : ttls == 1 ? 10 : i % 2 ? 20 : 0;
      transaction.rule_ids[i] = i + 1;
      transaction.protocols[i] = (i + 1) % 2 ? 6 : 17;
      transaction.ports[i] = 441 + i;
    }
    struct nosh_dns_commit_context context = {
      .config = &config, .packet = &packet, .transaction = &transaction,
      .scratch = &scratch, .question = &question, .flags = flags, .txid = 42, .hook = 5,
    };
    trace_count = 0;
    reference_commit(&context);
    const unsigned expected_count = trace_count, expected_grants = context.grants;
    memcpy(expected, trace, sizeof(trace));
    context.grants = 0;
    trace_count = 0;
    for (unsigned index = 0; index < 64; index++)
      if (commit_dns_answer_rule(index, &context)) break;
    assert(context.grants == expected_grants && trace_count == expected_count);
    assert(!memcmp(trace, expected, trace_count * sizeof(trace[0])));
    assert(commit_dns_answer_rule(64, &context) == 1);
    assert(commit_dns_answer_rule(0xffffffffU, &context) == 1);
    cases++;
  }
  printf("DNS commit equivalence: %u cases passed\n", cases);
  return 0;
}
