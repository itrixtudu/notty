// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
#ifndef NOSH_EGRESS_DNS_WIRE_H
#define NOSH_EGRESS_DNS_WIRE_H

#include "nosh_egress.h"

/* DNS resource records have a ten-byte fixed header after the owner name.
 * The wire format has no trailing padding before RDATA. */
struct nosh_dns_rr_fixed {
  __be16 type;
  __be16 class;
  __be32 ttl;
  __be16 data_length;
} __attribute__((packed));

_Static_assert(sizeof(struct nosh_dns_rr_fixed) == 10,
               "DNS resource record fixed header must occupy ten wire bytes");
_Static_assert(__builtin_offsetof(struct nosh_dns_rr_fixed, data_length) == 8,
               "DNS resource record RDLENGTH must start at wire offset eight");

#endif
