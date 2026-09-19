// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "nosh_egress.h"

#define NOSH_EGRESS_DNS_HEADER_LEN 12
struct __sk_buff {
  const unsigned char *data;
  size_t length;
};
struct nosh_dns_name {
  __u8 length;
  char bytes[NOSH_EGRESS_DOMAIN_LEN];
};
static void clear_dns_name(struct nosh_dns_name *name)
{
  memset(name, 0, sizeof(*name));
}
static int load_bytes(struct __sk_buff *skb, __u32 offset,
                      void *destination, __u32 length)
{
  if (offset > skb->length || length > skb->length - offset)
    return -1;
  memcpy(destination, skb->data + offset, length);
  return 0;
}
static int helper_failure;
static long bpf_loop(__u32 count, long (*callback)(__u32, void *),
                     void *context, __u64 flags)
{
  assert(flags == 0);
  assert(count == NOSH_EGRESS_DNS_MAX_LABELS * 64 || count == 8 || count == NOSH_EGRESS_DOMAIN_LEN);
  if (helper_failure)
    return -22;
  for (__u32 index = 0; index < count; index++) {
    long result = callback(index, context);
    assert(result == 0 || result == 1);
    if (result)
      return index + 1;
  }
  return count;
}
#include "nosh_egress_dns_parse.h"

#include <arpa/inet.h>
#define bpf_ntohs ntohs
#define bpf_ntohl ntohl
#define NOSH_EGRESS_DNS_MAX_ANSWERS NOSH_EGRESS_DNS_ANSWER_SLOTS
#include "nosh_egress_dns_wire.h"
static unsigned stats[256];
static void increment_stat(unsigned stat)
{
  assert(stat < 256);
  stats[stat]++;
}
#include "nosh_egress_dns_match.h"
#include "nosh_egress_dns_stage.h"
#include "dns-stage-reference.h"
static unsigned cases;
static uint32_t random_state = 0x5416283;
static uint32_t random_number(void)
{
  random_state ^= random_state << 13;
  random_state ^= random_state >> 17;
  random_state ^= random_state << 5;
  return random_state;
}
static void compare(const unsigned char *bytes, size_t size, __u32 end,
                    unsigned answers, unsigned flags, unsigned qtype,
                    int expected_valid, int expected_count)
{
  struct __sk_buff skb = {.data = bytes, .length = size};
  struct nosh_dns_name actual_name = {0}, reference_name = {0};
  struct nosh_egress_dns_tx_value actual_tx = {0}, reference_tx;
  struct nosh_egress_dns_response_scratch actual_scratch = {0}, reference_scratch = {0};
  actual_tx.question[0] = 'q';
  actual_tx.question_length = 1;
  actual_tx.question_type = qtype;
  reference_tx = actual_tx;
  struct nosh_dns_stage_context actual = {
    .skb = &skb, .question = &actual_name, .transaction = &actual_tx,
    .scratch = &actual_scratch, .offset = 12, .message_end = end,
    .answers = answers, .flags = flags, .response_valid = 1,
    .response_gap_reason = NOSH_EGRESS_REASON_PARSE_ERROR,
  }, reference = actual;
  reference.question = &reference_name;
  reference.transaction = &reference_tx;
  reference.scratch = &reference_scratch;
  memset(stats, 0, sizeof(stats));
  reference_stage(&reference);
  unsigned reference_stats[256];
  memcpy(reference_stats, stats, sizeof(stats));
  memset(stats, 0, sizeof(stats));
  assert(bpf_loop(8, stage_dns_answer, &actual, 0) >= 0);
  if (actual.offset != reference.offset ||
      actual.response_valid != reference.response_valid ||
      actual.response_gap_reason != reference.response_gap_reason ||
      memcmp(&actual_name, &reference_name, sizeof(actual_name)) ||
      memcmp(&actual_tx, &reference_tx, sizeof(actual_tx)) ||
      memcmp(&actual_scratch, &reference_scratch, sizeof(actual_scratch)) ||
      memcmp(stats, reference_stats, sizeof(stats)) ||
      (expected_valid >= 0 && actual.response_valid != expected_valid) ||
      (expected_count >= 0 && actual_scratch.answer_count != expected_count)) {
    fprintf(stderr, "stage case %u: answers %u flags %u qtype %u valid %d/%d expected %d; staged %u expected %d\n",
      cases, answers, flags, qtype, actual.response_valid,
      reference.response_valid, expected_valid, actual_scratch.answer_count, expected_count);
    assert(0);
  }
  cases++;
}
static void put_wire_u16(unsigned char *bytes, unsigned value)
{
  bytes[0] = value >> 8;
  bytes[1] = value;
}
static void put_wire_u32(unsigned char *bytes, unsigned value)
{
  bytes[0] = value >> 24;
  bytes[1] = value >> 16;
  bytes[2] = value >> 8;
  bytes[3] = value;
}
/* Write DNS wire bytes independently of the decoder's C structure layout. */
static size_t append_answer(unsigned char *bytes, size_t cursor,
                            char owner, unsigned type, unsigned ttl,
                            unsigned klass, int wrong_length)
{
  bytes[cursor++] = 1;
  bytes[cursor++] = owner;
  bytes[cursor++] = 0;
  unsigned length = type == 5 ? 3 : type == 1 ? 4 : 16;
  put_wire_u16(bytes + cursor, type);
  put_wire_u16(bytes + cursor + 2, klass);
  put_wire_u32(bytes + cursor + 4, ttl);
  put_wire_u16(bytes + cursor + 8, length + wrong_length);
  cursor += 10;
  memset(bytes + cursor, 1, length);
  if (type == 5) {
    bytes[cursor] = 1;
    bytes[cursor + 1] = 'a';
    bytes[cursor + 2] = 0;
  }
  return cursor + length;
}
struct wire_result {
  struct nosh_dns_name name;
  struct nosh_egress_dns_tx_value transaction;
  struct nosh_egress_dns_response_scratch scratch;
  unsigned offset;
  int valid;
  unsigned gap_reason;
};
static void stage_wire(const unsigned char *bytes, size_t size,
                       __u32 answer_offset, unsigned answers,
                       const char *question, unsigned qtype,
                       struct wire_result *result)
{
  struct __sk_buff skb = {.data = bytes, .length = size};
  memset(result, 0, sizeof(*result));
  size_t length = strlen(question);
  assert(length < sizeof(result->transaction.question));
  memcpy(result->transaction.question, question, length);
  result->transaction.question_length = length;
  result->transaction.question_type = qtype;
  struct nosh_dns_stage_context context = {
    .skb = &skb, .question = &result->name,
    .transaction = &result->transaction, .scratch = &result->scratch,
    .offset = answer_offset, .message_end = size, .answers = answers,
    .response_valid = 1, .response_gap_reason = NOSH_EGRESS_REASON_PARSE_ERROR,
  };
  memset(stats, 0, sizeof(stats));
  assert(bpf_loop(NOSH_EGRESS_DNS_ANSWER_SLOTS, stage_dns_answer, &context, 0) >= 0);
  result->offset = context.offset;
  result->valid = context.response_valid;
  result->gap_reason = context.response_gap_reason;
}
static void wire_fixtures(void)
{
  /* Literal packets include the DNS header/question so name pointers address
   * their real wire offsets. Each RR's RDATA follows exactly ten fixed bytes. */
  static const unsigned char ipv4[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
    1, 'q', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 1, 0, 1, 1, 2, 3, 4, 0, 4,
    192, 0, 2, 17,
  };
  static const unsigned char ipv6[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
    1, 'q', 0, 0, 28, 0, 1,
    0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16,
    0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6,
  };
  static const unsigned char cname[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0,
    1, 'q', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 20, 0, 3,
    1, 'a', 0,
    0xc0, 0x1f, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
    192, 0, 2, 21,
  };
  static const unsigned char compressed_cname[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0,
    1, 'q', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 4,
    1, 'a', 0xc0, 0x0e,
    0xc0, 0x27, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
    198, 51, 100, 37,
  };
  static const unsigned char truncated_later[] = {
    0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0,
    1, 'q', 0, 0, 1, 0, 1,
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
    192, 0, 2, 41,
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
    192, 0, 2,
  };
  struct wire_result result;
  static const unsigned char expected_v4[16] = {192, 0, 2, 17};
  stage_wire(ipv4, sizeof(ipv4), 19, 1, "q", 1, &result);
  assert(result.valid && result.offset == sizeof(ipv4));
  assert(result.scratch.answer_count == 1);
  assert(result.scratch.answers[0].family == NOSH_EGRESS_FAMILY_IPV4);
  assert(result.scratch.answers[0].ttl == 0x01020304);
  assert(!memcmp(result.scratch.answers[0].address, expected_v4, 16));

  stage_wire(ipv6, sizeof(ipv6), 19, 1, "q", 28, &result);
  assert(result.valid && result.offset == sizeof(ipv6));
  assert(result.scratch.answer_count == 1);
  assert(result.scratch.answers[0].family == NOSH_EGRESS_FAMILY_IPV6);
  assert(result.scratch.answers[0].ttl == 60);
  assert(!memcmp(result.scratch.answers[0].address, ipv6 + 31, 16));

  static const unsigned char expected_alias_v4[16] = {192, 0, 2, 21};
  stage_wire(cname, sizeof(cname), 19, 2, "q", 1, &result);
  assert(result.valid && result.offset == sizeof(cname));
  assert(result.scratch.cname_seen && result.scratch.cname_ttl == 20);
  assert(result.transaction.alias_length == 1 && result.transaction.alias[0] == 'a');
  assert(result.scratch.answer_count == 1 && result.scratch.answers[0].ttl == 20);
  assert(!memcmp(result.scratch.answers[0].address, expected_alias_v4, 16));

  unsigned char varied_cname[sizeof(cname)];
  memcpy(varied_cname, cname, sizeof(cname));
  varied_cname[28] = 120;
  stage_wire(varied_cname, sizeof(varied_cname), 19, 2, "q", 1, &result);
  assert(result.valid && result.scratch.cname_ttl == 120);
  assert(result.scratch.answer_count == 1 && result.scratch.answers[0].ttl == 60);
  varied_cname[28] = 0;
  stage_wire(varied_cname, sizeof(varied_cname), 19, 2, "q", 1, &result);
  assert(result.valid && result.scratch.cname_seen && !result.scratch.answer_count);

  static const unsigned char expected_compressed_v4[16] = {198, 51, 100, 37};
  stage_wire(compressed_cname, sizeof(compressed_cname), 27, 2, "q.example", 1, &result);
  assert(result.valid && result.offset == sizeof(compressed_cname));
  assert(result.transaction.alias_length == 9);
  assert(!memcmp(result.transaction.alias, "a.example", 9));
  assert(result.scratch.answer_count == 1 && result.scratch.answers[0].ttl == 30);
  assert(!memcmp(result.scratch.answers[0].address, expected_compressed_v4, 16));

  stage_wire(truncated_later, sizeof(truncated_later), 19, 2, "q", 1, &result);
  assert(!result.valid && result.gap_reason == NOSH_EGRESS_REASON_PARSE_ERROR);
  assert(stats[NOSH_EGRESS_STAT_PARSE_ERRORS] == 1);
  /* A candidate from answer one must not turn a malformed response valid.
   * The response handler commits only after checking response_valid. */
  assert(result.scratch.answer_count == 1);
  stage_wire(truncated_later, 40, 19, 2, "q", 1, &result);
  assert(!result.valid && stats[NOSH_EGRESS_STAT_PARSE_ERRORS] == 1);
  assert(result.scratch.answer_count == 1);
  puts("DNS wire fixtures: A, AAAA, CNAME TTL bounds, compressed names and truncated later answers passed");
}
int main(void)
{
  unsigned char bytes[4096], mutated[4096];
  (void)parse_dns_name;
  wire_fixtures();
  for (unsigned answers = 0; answers <= 8; answers++)
  for (unsigned profile = 0; profile < 8; profile++)
  for (unsigned flags = 0; flags <= 3; flags += 3)
  for (unsigned qtype_index = 0; qtype_index < 2; qtype_index++) {
    unsigned qtype = qtype_index ? 28 : 1;
    size_t size = 12;
    memset(bytes, 0, sizeof(bytes));
    for (unsigned i = 0; i < answers; i++) {
      char owner = 'q';
      unsigned type = qtype, ttl = 60, klass = 1;
      int wrong_length = 0;
      if (profile == 1 || profile == 2) {
        owner = i ? 'a' : 'q';
        type = i ? qtype : 5;
        ttl = i ? 60 : 20;
        if (profile == 2 && i == 1) type = 5;
      } else if (profile == 3) {
        owner = 'x';
      } else if (profile == 4) {
        ttl = 0;
      } else if (profile == 5) {
        klass = 2;
      } else if (profile == 6) {
        type = qtype == 1 ? 28 : 1;
      } else if (profile == 7 && i + 1 == answers) {
        wrong_length = 1;
      }
      size = append_answer(bytes, size, owner, type, ttl, klass, wrong_length);
    }
    int valid = (profile == 2 && answers > 1) ||
      ((profile == 6 || profile == 7) && answers) ? 0 : 1;
    int count = flags || profile >= 3 ? 0 : profile == 0 ? answers : answers ? answers - 1 : 0;
    if (!valid) count = -1;
    compare(bytes, size, size, answers, flags, qtype, valid, count);
    for (size_t end = 12; end < size; end++) {
      compare(bytes, size, end, answers, flags, qtype, -1, -1);
      compare(bytes, end, size, answers, flags, qtype, -1, -1);
    }
    for (unsigned trial = 0; trial < 100; trial++) {
      memcpy(mutated, bytes, size);
      mutated[random_number() % size] = random_number();
      compare(mutated, size, size, answers, flags, qtype, -1, -1);
    }
  }
  struct nosh_dns_stage_context context = {0};
  assert(stage_dns_answer(8, &context) == 1);
  assert(stage_dns_answer(UINT32_MAX, &context) == 1);
  printf("DNS staging equivalence: %u cases; CNAME, TTL, family, truncation and malformed-later-answer checks passed\n", cases);
  return 0;
}
