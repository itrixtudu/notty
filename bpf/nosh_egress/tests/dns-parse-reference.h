// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
/* Pre-refactor parser retained as an independent behavior oracle. */
static __always_inline int reference_parse_compressed_dns_name(
    struct __sk_buff *skb, __u32 message_offset, __u32 message_end,
    __u32 *offset, struct nosh_dns_name *name)
{
  __u32 cursor = *offset;
  __u32 next = cursor;
  int jumped = 0;
  int pointers = 0;
  int label_index;

  clear_dns_name(name);
  for (label_index = 0; label_index < NOSH_EGRESS_DNS_MAX_LABELS;
       label_index++) {
    __u8 length = 0;
    int byte_index;

    if (cursor >= message_end ||
        load_bytes(skb, cursor, &length, 1) < 0)
      return -1;
    if (!length) {
      if (!jumped)
        next = cursor + 1;
      *offset = next;
      return name->length ? 0 : -1;
    }
    if ((length & 0xc0) == 0xc0) {
      __u8 second = 0;
      __u16 pointer;

      if (cursor + 1 >= message_end ||
          load_bytes(skb, cursor + 1, &second, 1) < 0 || pointers >= 2)
        return -1;
      pointer = ((__u16)(length & 0x3f) << 8) | second;
      if (pointer < NOSH_EGRESS_DNS_HEADER_LEN ||
          message_offset + pointer >= message_end)
        return -1;
      if (!jumped)
        next = cursor + 2;
      cursor = message_offset + pointer;
      jumped = 1;
      pointers++;
      continue;
    }
    if (length & 0xc0 || length > 63)
      return -1;
    cursor++;
    if ((__u32)length > message_end - cursor)
      return -1;
    if (name->length) {
      if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1)
        return -1;
      name->bytes[name->length++] = '.';
    }
    for (byte_index = 0; byte_index < 63; byte_index++) {
      __u8 byte;

      if (byte_index >= length)
        break;
      if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1 ||
          load_bytes(skb, cursor, &byte, 1) < 0)
        return -1;
      cursor++;
      if (byte >= 'A' && byte <= 'Z')
        byte += 'a' - 'A';
      if ((byte < 'a' || byte > 'z') &&
          (byte < '0' || byte > '9') && byte != '-' && byte != '_')
        return -1;
      name->bytes[name->length++] = byte;
    }
    if (!jumped)
      next = cursor;
  }
  return -1;
}

