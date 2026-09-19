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
  assert(count == NOSH_EGRESS_DNS_MAX_LABELS * 64 || count == NOSH_EGRESS_DOMAIN_LEN);
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
#include "dns-parse-reference.h"
#include "dns-query-parse-reference.h"
#include "nosh_egress_dns_match.h"
#include "dns-match-reference.h"

static unsigned cases;
static unsigned accepted;
static unsigned rejected;
static uint32_t random_state = 0xabc1293;
static uint32_t random_number(void)
{
  random_state ^= random_state << 13;
  random_state ^= random_state >> 17;
  random_state ^= random_state << 5;
  return random_state;
}
static void compare(const unsigned char *bytes, size_t size,
                    __u32 base, __u32 end, __u32 start, int expected)
{
  struct __sk_buff skb = { .data = bytes, .length = size };
  struct nosh_dns_name actual, reference;
  __u32 actual_offset = start, reference_offset = start;
  int a = parse_compressed_dns_name(&skb, base, end, &actual_offset, &actual);
  int b = reference_parse_compressed_dns_name(&skb, base, end,
                                             &reference_offset, &reference);
  if (a != b || actual_offset != reference_offset ||
      memcmp(&actual, &reference, sizeof(actual)) ||
      (expected != 2 && a != expected)) {
    fprintf(stderr, "case %u: size=%zu base=%u end=%u start=%u: result %d/%d expected %d, offset %u/%u\n",
            cases, size, base, end, start, a, b, expected,
            actual_offset, reference_offset);
    assert(0);
  }
  actual_offset = reference_offset = start;
  a = parse_dns_name(&skb, &actual_offset, &actual);
  b = reference_parse_dns_name(&skb, &reference_offset, &reference);
  assert(a == b && actual_offset == reference_offset);
  assert(!memcmp(&actual, &reference, sizeof(actual)));
  cases++;
  if (a == 0) accepted++; else rejected++;
}
static size_t append_label(unsigned char *bytes, size_t cursor,
                           unsigned length)
{
  static const char allowed[] = "AbZ-0_9";
  assert(length <= 63);
  bytes[cursor++] = length;
  for (unsigned i = 0; i < length; i++)
    bytes[cursor++] = allowed[i % (sizeof(allowed) - 1)];
  return cursor;
}
static void exercise(unsigned char *bytes, size_t size,
                     __u32 base, __u32 start, int expected)
{
  unsigned char mutated[4096];
  compare(bytes, size, base, size, start, expected);
  // Message-boundary truncation and packet-load failure are independent.
  for (size_t end = base; end < size; end++) {
    compare(bytes, size, base, end, start, 2);
    compare(bytes, end, base, size, start, 2);
  }
  for (unsigned trial = 0; trial < 700; trial++) {
    memcpy(mutated, bytes, size);
    for (unsigned edit = 0; edit < 1 + trial % 4; edit++)
      mutated[random_number() % size] = random_number();
    compare(mutated, size, base, size, start, 2);
  }
}
int main(void)
{
  unsigned char bytes[4096];
  // Normalization, maximum label/name sizes, and header iteration limit.
  for (unsigned prefix = 0; prefix <= 28; prefix += 28) {
    for (unsigned labels = 1; labels <= 17; labels++) {
      for (unsigned length_index = 0; length_index < 3; length_index++) {
        unsigned length = (unsigned[]){1, 7, 63}[length_index];
        memset(bytes, 0, sizeof(bytes));
        size_t cursor = prefix + 12;
        for (unsigned label = 0; label < labels; label++)
          cursor = append_label(bytes, cursor, length);
        bytes[cursor++] = 0;
        int expected = labels < 16 && labels * (length + 1) - 1 < 128 ? 0 : -1;
        exercise(bytes, cursor, prefix, prefix + 12, expected);
      }
    }
    memset(bytes, 0, sizeof(bytes));
    size_t cursor = append_label(bytes, prefix + 12, 63);
    cursor = append_label(bytes, cursor, 63);
    bytes[cursor++] = 0;
    exercise(bytes, cursor, prefix, prefix + 12, 0); // exactly 127 output bytes

    memset(bytes, 0, sizeof(bytes));
    exercise(bytes, prefix + 13, prefix, prefix + 12, -1); // root name
    cursor = append_label(bytes, prefix + 12, 3);
    bytes[cursor++] = 0;
    size_t first_pointer = cursor;
    bytes[cursor++] = 0xc0;
    bytes[cursor++] = 12;
    exercise(bytes, cursor, prefix, first_pointer, 0);
    size_t second_pointer = cursor;
    bytes[cursor++] = 0xc0;
    bytes[cursor++] = first_pointer - prefix;
    exercise(bytes, cursor, prefix, second_pointer, 0);
    size_t third_pointer = cursor;
    bytes[cursor++] = 0xc0;
    bytes[cursor++] = second_pointer - prefix;
    exercise(bytes, cursor, prefix, third_pointer, -1);
    size_t mixed = cursor;
    cursor = append_label(bytes, cursor, 2);
    bytes[cursor++] = 0xc0;
    bytes[cursor++] = 12;
    exercise(bytes, cursor, prefix, mixed, 0); // literal prefix then pointer

    memset(bytes, 0, sizeof(bytes));
    bytes[prefix + 12] = 0xc0;
    bytes[prefix + 13] = 12;
    exercise(bytes, prefix + 14, prefix, prefix + 12, -1); // self cycle
    bytes[prefix + 13] = 14;
    bytes[prefix + 14] = 0xc0;
    bytes[prefix + 15] = 12;
    exercise(bytes, prefix + 16, prefix, prefix + 12, -1); // two-node cycle
    bytes[prefix + 13] = 11;
    exercise(bytes, prefix + 16, prefix, prefix + 12, -1); // header pointer
    bytes[prefix + 13] = 16;
    exercise(bytes, prefix + 16, prefix, prefix + 12, -1); // end pointer

    for (unsigned invalid = 0; invalid < 256; invalid++) {
      memset(bytes, 0, sizeof(bytes));
      bytes[prefix + 12] = 1;
      bytes[prefix + 13] = invalid;
      compare(bytes, prefix + 15, prefix, prefix + 15, prefix + 12, 2);
    }
  }
  // Loads at extreme offsets must fail without wraparound access.
  compare(bytes, sizeof(bytes), 0, UINT32_MAX, UINT32_MAX - 1, -1);
  compare(bytes, sizeof(bytes), UINT32_MAX - 16, UINT32_MAX, 12, 2);
  struct __sk_buff skb = {.data = bytes, .length = sizeof(bytes)};
  struct nosh_dns_name name;
  __u32 offset = 12;
  struct nosh_egress_dns_tx_value tx = {0};
  unsigned comparisons = 0;
  for (unsigned length = 0; length < 256; length++) {
    memset(name.bytes, 'a', sizeof(name.bytes));
    memset(tx.question, 'a', sizeof(tx.question));
    memset(tx.alias, 'a', sizeof(tx.alias));
    name.length = tx.question_length = tx.alias_length = length;
    for (unsigned mismatch = 0; mismatch <= 128; mismatch++) {
      if (mismatch < 128) name.bytes[mismatch] = 'b';
      assert(dns_name_matches(&name, &tx) == reference_dns_name_matches(&name, &tx));
      assert(dns_name_matches_alias(&name, &tx) == reference_dns_name_matches_alias(&name, &tx));
      comparisons += 2;
      if (mismatch < 128) name.bytes[mismatch] = 'a';
    }
    tx.question_length = tx.alias_length = (length + 1) % 256;
    assert(!dns_name_matches(&name, &tx) && !dns_name_matches_alias(&name, &tx));
  }
  helper_failure = 1;
  name.length = tx.question_length = tx.alias_length = 1;
  assert(!dns_name_matches(&name, &tx) && !dns_name_matches_alias(&name, &tx));
  assert(parse_compressed_dns_name(&skb, 0, sizeof(bytes), &offset, &name) == -1);
  assert(offset == 12 && name.length == 0);
  assert(accepted > 100 && rejected > 100);
  printf("DNS name comparisons: %u cases passed\n", comparisons);
  printf("DNS compressed/query parser equivalence: %u cases (%u accepted, %u rejected); helper failure denies\n",
         cases, accepted, rejected);
  return 0;
}
