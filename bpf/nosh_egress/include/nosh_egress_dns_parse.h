// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
#ifndef NOSH_EGRESS_DNS_PARSE_H
#define NOSH_EGRESS_DNS_PARSE_H

struct nosh_dns_parse_context {
  struct __sk_buff *skb;
  struct nosh_dns_name *name;
  __u32 message_offset;
  __u32 message_end;
  __u32 cursor;
  __u32 next;
  int result;
  __u8 remaining;
  __u8 labels;
  __u8 pointers;
  __u8 jumped;
  __u8 terminated;
};

/* Consume one label header, pointer, terminator, or character per helper
 * iteration. This preserves the original 16 header / 63 character / two
 * pointer limits without nested verifier-expanded loops. */
static long parse_compressed_dns_step(__u32 index, void *opaque)
{
  struct nosh_dns_parse_context *context = opaque;
  struct nosh_dns_name *name = context->name;
  __u8 byte = 0;

  (void)index;
  if (context->remaining) {
    if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1 ||
        load_bytes(context->skb, context->cursor, &byte, 1) < 0)
      return 1;
    context->cursor++;
    if (byte >= 'A' && byte <= 'Z')
      byte += 'a' - 'A';
    if ((byte < 'a' || byte > 'z') &&
        (byte < '0' || byte > '9') && byte != '-' && byte != '_')
      return 1;
    __u32 output_index = name->length;
    if (output_index >= NOSH_EGRESS_DOMAIN_LEN - 1)
      return 1;
    name->bytes[output_index] = byte;
    name->length = output_index + 1;
    context->remaining--;
    if (!context->remaining && !context->jumped)
      context->next = context->cursor;
    return 0;
  }
  if (context->labels >= NOSH_EGRESS_DNS_MAX_LABELS ||
      context->cursor >= context->message_end ||
      load_bytes(context->skb, context->cursor, &byte, 1) < 0)
    return 1;
  context->labels++;
  if (!byte) {
    if (!context->jumped)
      context->next = context->cursor + 1;
    context->terminated = 1;
    context->result = name->length ? 0 : -1;
    return 1;
  }
  if ((byte & 0xc0) == 0xc0) {
    __u8 second = 0;
    __u16 pointer;

    if (context->cursor + 1 >= context->message_end ||
        load_bytes(context->skb, context->cursor + 1, &second, 1) < 0 ||
        context->pointers >= 2)
      return 1;
    pointer = ((__u16)(byte & 0x3f) << 8) | second;
    if (pointer < NOSH_EGRESS_DNS_HEADER_LEN ||
        context->message_offset + pointer >= context->message_end)
      return 1;
    if (!context->jumped)
      context->next = context->cursor + 2;
    context->cursor = context->message_offset + pointer;
    context->jumped = 1;
    context->pointers++;
    return 0;
  }
  if (byte & 0xc0 || byte > 63)
    return 1;
  context->cursor++;
  if ((__u32)byte > context->message_end - context->cursor)
    return 1;
  if (name->length) {
    if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1)
      return 1;
    name->bytes[name->length++] = '.';
  }
  context->remaining = byte;
  return 0;
}

__noinline int parse_compressed_dns_name(
    struct __sk_buff *skb, __u32 message_offset, __u32 message_end,
    __u32 *offset, struct nosh_dns_name *name)
{
  if (!offset || !name)
    return -1;
  struct nosh_dns_parse_context context = {
    .skb = skb,
    .name = name,
    .message_offset = message_offset,
    .message_end = message_end,
    .cursor = *offset,
    .next = *offset,
    .result = -1,
  };

  clear_dns_name(name);
  if (bpf_loop(NOSH_EGRESS_DNS_MAX_LABELS * (63 + 1),
               parse_compressed_dns_step, &context, 0) < 0)
    return -1;
  if (context.terminated)
    *offset = context.next;
  return context.result;
}

/* Query names reject compression and publish the consumed offset even on
 * failure, matching the original parser's caller-visible behavior. */
static long parse_dns_query_step(__u32 index, void *opaque)
{
  struct nosh_dns_parse_context *context = opaque;
  struct nosh_dns_name *name = context->name;
  __u8 byte = 0;

  (void)index;
  if (context->remaining) {
    if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1 ||
        load_bytes(context->skb, context->cursor, &byte, 1) < 0)
      return 1;
    context->cursor++;
    if (byte >= 'A' && byte <= 'Z')
      byte += 'a' - 'A';
    if ((byte < 'a' || byte > 'z') &&
        (byte < '0' || byte > '9') && byte != '-' && byte != '_')
      return 1;
    __u32 output_index = name->length;
    if (output_index >= NOSH_EGRESS_DOMAIN_LEN - 1)
      return 1;
    name->bytes[output_index] = byte;
    name->length = output_index + 1;
    context->remaining--;
    return 0;
  }
  if (context->labels >= NOSH_EGRESS_DNS_MAX_LABELS ||
      load_bytes(context->skb, context->cursor, &byte, 1) < 0)
    return 1;
  context->labels++;
  context->cursor++;
  if (!byte) {
    context->result = name->length ? 0 : -1;
    return 1;
  }
  if (byte & 0xc0 || byte > 63)
    return 1;
  if (name->length) {
    if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1)
      return 1;
    name->bytes[name->length++] = '.';
  }
  context->remaining = byte;
  return 0;
}

__noinline int parse_dns_name(struct __sk_buff *skb,
                                          __u32 *offset,
                                          struct nosh_dns_name *name)
{
  if (!offset || !name)
    return -1;
  struct nosh_dns_parse_context context = {
    .skb = skb, .name = name, .cursor = *offset, .result = -1,
  };

  clear_dns_name(name);
  if (bpf_loop(NOSH_EGRESS_DNS_MAX_LABELS * (63 + 1),
               parse_dns_query_step, &context, 0) < 0)
    return -1;
  *offset = context.cursor;
  return context.result;
}
#endif
