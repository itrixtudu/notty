// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
/* Original validate-before-commit loop, retained as a behavior oracle. */
static void reference_stage(struct nosh_dns_stage_context *context)
{
  int answer_index;
  /* First pass: validate and stage.  No dynamic grant is mutated here. */
  for (answer_index = 0; answer_index < NOSH_EGRESS_DNS_MAX_ANSWERS;
       answer_index++) {
    struct nosh_dns_rr_fixed fixed = {};
    __u16 type;
    __u16 data_length;
    __u32 ttl;
    __u8 address[16] = {};
    __u32 data_offset;
    int owner_authorized;
    int owner_is_question;
    int owner_is_alias;

    if (answer_index >= context->answers)
      break;
    if (parse_compressed_dns_name(context->skb, context->dns_offset, context->message_end,
                                  &context->offset, context->question) < 0 ||
        load_bytes(context->skb, context->offset, &fixed, sizeof(fixed)) < 0) {
      increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
      context->response_valid = 0;
      break;
    }
    owner_is_question = dns_name_matches(context->question, context->transaction);
    owner_is_alias = dns_name_matches_alias(context->question, context->transaction);
    owner_authorized = owner_is_question || owner_is_alias;
    context->offset += sizeof(fixed);
    data_offset = context->offset;
    type = bpf_ntohs(fixed.type);
    data_length = bpf_ntohs(fixed.data_length);
    ttl = bpf_ntohl(fixed.ttl);
    if (data_offset > context->message_end || data_length > context->message_end - data_offset) {
      increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
      context->response_valid = 0;
      break;
    }
    if (bpf_ntohs(fixed.class) == 1 && type == 5) {
      __u32 cname_offset = data_offset;

      if (parse_compressed_dns_name(context->skb, context->dns_offset, context->message_end,
                                    &cname_offset, context->question) < 0 ||
          cname_offset != data_offset + data_length) {
        increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
        context->response_valid = 0;
        break;
      }
      if (owner_authorized) {
        /* v2 supports one CNAME hop rooted at the observed context->question. */
        if (!owner_is_question || context->scratch->cname_seen ||
            context->scratch->answer_count) {
          increment_stat(NOSH_EGRESS_STAT_DNS_UNSUPPORTED);
          context->response_gap_reason = NOSH_EGRESS_REASON_UNSUPPORTED;
          context->response_valid = 0;
          break;
        }
        context->scratch->cname_seen = 1;
        context->scratch->cname_ttl = ttl;
        context->transaction->alias_length = context->question->length;
        __builtin_memcpy(context->transaction->alias, context->question->bytes,
                         sizeof(context->transaction->alias));
      }
    } else if (bpf_ntohs(fixed.class) == 1 && (type == 1 || type == 28)) {
      __u8 family = type == 1 ? NOSH_EGRESS_FAMILY_IPV4 :
        NOSH_EGRESS_FAMILY_IPV6;
      __u16 expected_length = type == 1 ? 4 : 16;

      if (data_length != expected_length ||
          load_bytes(context->skb, context->offset, address, expected_length) < 0) {
        increment_stat(NOSH_EGRESS_STAT_PARSE_ERRORS);
        context->response_valid = 0;
        break;
      }
      if (owner_authorized) {
        struct nosh_egress_dns_answer *candidate;

        if ((context->scratch->cname_seen && owner_is_question) ||
            type != context->transaction->question_type ||
            context->scratch->answer_count >= NOSH_EGRESS_DNS_ANSWER_SLOTS) {
          increment_stat(NOSH_EGRESS_STAT_DNS_UNSUPPORTED);
          context->response_gap_reason = NOSH_EGRESS_REASON_UNSUPPORTED;
          context->response_valid = 0;
          break;
        }
        if (!(context->flags & 0x000f) && ttl &&
            (!owner_is_alias || (context->scratch->cname_seen && context->scratch->cname_ttl))) {
          candidate = &context->scratch->answers[context->scratch->answer_count++];
          candidate->family = family;
          candidate->ttl = owner_is_alias && context->scratch->cname_ttl < ttl
            ? context->scratch->cname_ttl : ttl;
          __builtin_memcpy(candidate->address, address,
                           sizeof(candidate->address));
        }
      }
    }
    context->offset += data_length;
  }
}
