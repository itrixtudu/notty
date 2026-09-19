// Exercise the production userspace decoder without attaching BPF programs.
#define main nosh_build_loader_main
#include "../loader/nosh_build_loader.c"
#undef main
#include <assert.h>

static void check_response(unsigned int count, bool truncated)
{
  struct loader_context context = {};
  struct nosh_build_dns_wire_event event = {};
  char *output = NULL;
  size_t output_size = 0;
  size_t cursor = 19;
  unsigned int captured = count > 16 ? 16 : count;
  char expected[64];
  const unsigned char question[] = { 1, 'a', 0, 0, 1, 0, 1 };
  const unsigned char answer[] = {
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1
  };

  context.event_stream = open_memstream(&output, &output_size);
  assert(context.event_stream);
  event.header.event_kind = NOSH_BUILD_EVENT_DNS_RESPONSE;
  event.family = NOSH_BUILD_FAMILY_IPV4;
  event.server_port = 53;
  event.client_port = 12345;
  event.socket_cookie = 1;
  event.wire[2] = truncated ? 0x82 : 0x80;
  event.wire[5] = 1;
  event.wire[7] = count;
  memcpy(event.wire + 12, question, sizeof(question));
  for (unsigned int index = 0; index < count; index++) {
    memcpy(event.wire + cursor, answer, sizeof(answer));
    event.wire[cursor + 15] = index + 1;
    cursor += sizeof(answer);
  }
  event.wire_length = cursor;
  event.original_length = cursor;
  assert(decode_and_emit_dns_response(&context, &event) == 1);
  assert(fclose(context.event_stream) == 0);
  snprintf(expected, sizeof(expected), "\"answersCaptured\":%u", captured);
  assert(strstr(output, expected));
  snprintf(expected, sizeof(expected), "192.0.2.%u", captured);
  assert(strstr(output, expected));
  assert(strstr(output, count > 16 || truncated
    ? "\"parseComplete\":false" : "\"parseComplete\":true"));
  assert(context.dns_answer_limit_reached == (count > 16 ? 1 : 0));
  assert(context.dns_truncated_responses == (truncated ? 1 : 0));
  assert(context.dns_parse_errors == 0);
  free(output);
}

int main(void)
{
  check_response(8, false);
  check_response(9, false);
  check_response(12, false);
  check_response(16, false);
  check_response(17, false);
  check_response(12, true);
  puts("DNS response capacity, overflow, and truncation checks passed");
  return 0;
}
