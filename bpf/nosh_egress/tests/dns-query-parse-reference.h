// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
static __always_inline int reference_parse_dns_name(struct __sk_buff *skb,
                                          __u32 *offset,
                                          struct nosh_dns_name *name)
{
  int label_index;

  clear_dns_name(name);
  for (label_index = 0; label_index < NOSH_EGRESS_DNS_MAX_LABELS;
       label_index++) {
    __u8 label_length = 0;
    int byte_index;

    if (load_bytes(skb, *offset, &label_length, 1) < 0)
      return -1;
    *offset += 1;
    if (!label_length)
      return name->length ? 0 : -1;
    if (label_length & 0xc0 || label_length > 63)
      return -1;
    if (name->length) {
      if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1)
        return -1;
      name->bytes[name->length++] = '.';
    }
    for (byte_index = 0; byte_index < 63; byte_index++) {
      __u8 byte;

      if (byte_index >= label_length)
        break;
      if (name->length >= NOSH_EGRESS_DOMAIN_LEN - 1 ||
          load_bytes(skb, *offset, &byte, 1) < 0)
        return -1;
      *offset += 1;
      if (byte >= 'A' && byte <= 'Z')
        byte += 'a' - 'A';
      if ((byte < 'a' || byte > 'z') &&
          (byte < '0' || byte > '9') && byte != '-' && byte != '_')
        return -1;
      name->bytes[name->length++] = byte;
    }
  }
  return -1;
}

