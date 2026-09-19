// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
/* Kernel-only packet regression. Loads fresh programs/maps, runs synthetic
 * Ethernet frames via BPF_PROG_TEST_RUN, then closes everything. No program
 * is attached or pinned and no frame is transmitted to a network. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "nosh_egress.h"
#include "nosh_egress.skel.h"

static unsigned checks;
static struct nosh_egress_event observed[64];
static size_t observed_count;

#define CHECK(condition, message) do { \
  checks++; \
  if (!(condition)) { \
    fprintf(stderr, "FAIL: %s (errno=%d: %s)\n", message, errno, strerror(errno)); \
    exit(1); \
  } \
} while (0)

static int receive_event(void *context, void *data, size_t size)
{
  (void)context;
  CHECK(size == sizeof(struct nosh_egress_event), "event ABI size");
  CHECK(observed_count < sizeof(observed) / sizeof(observed[0]), "event buffer capacity");
  memcpy(&observed[observed_count++], data, size);
  return 0;
}

static void put16(unsigned char *bytes, unsigned value)
{
  bytes[0] = value >> 8;
  bytes[1] = value;
}

static void put32(unsigned char *bytes, uint32_t value)
{
  put16(bytes, value >> 16);
  put16(bytes + 2, value);
}

static void address(unsigned char *bytes, const char *text)
{
  CHECK(inet_pton(AF_INET, text, bytes) == 1, "IPv4 fixture address");
}

static size_t frame(unsigned char *bytes, const char *source, const char *destination,
                    unsigned protocol, unsigned source_port, unsigned destination_port,
                    const unsigned char *payload, size_t payload_size)
{
  size_t transport_size = protocol == IPPROTO_TCP ? 20 : 8;
  size_t network_size = 20 + transport_size + payload_size;
  memset(bytes, 0, 14 + network_size);
  bytes[0] = bytes[6] = 2;
  put16(bytes + 12, 0x0800);
  bytes[14] = 0x45;
  put16(bytes + 16, network_size);
  bytes[22] = 64;
  bytes[23] = protocol;
  address(bytes + 26, source);
  address(bytes + 30, destination);
  put16(bytes + 34, source_port);
  put16(bytes + 36, destination_port);
  if (protocol == IPPROTO_TCP) {
    bytes[46] = 0x50;
    bytes[47] = 0x02;
  } else {
    put16(bytes + 38, transport_size + payload_size);
  }
  if (payload_size)
    memcpy(bytes + 34 + transport_size, payload, payload_size);
  return 14 + network_size;
}

static size_t dns_name(unsigned char *bytes, const char *name)
{
  size_t size = 0;
  while (*name) {
    const char *dot = strchr(name, '.');
    size_t length = dot ? (size_t)(dot - name) : strlen(name);
    CHECK(length > 0 && length <= 63, "DNS fixture label length");
    bytes[size++] = length;
    memcpy(bytes + size, name, length);
    size += length;
    name += length;
    if (*name == '.')
      name++;
  }
  bytes[size++] = 0;
  return size;
}

static size_t dns_message(unsigned char *bytes, uint16_t txid, const char *question,
                          int response, const char *answer, int truncated_second)
{
  memset(bytes, 0, 512);
  put16(bytes, txid);
  put16(bytes + 2, response ? 0x8180 : 0x0100);
  put16(bytes + 4, 1);
  put16(bytes + 6, response ? (truncated_second ? 2 : 1) : 0);
  size_t size = 12 + dns_name(bytes + 12, question);
  put16(bytes + size, 1);
  put16(bytes + size + 2, 1);
  size += 4;
  if (response) {
    put16(bytes + size, 0xc00c);
    put16(bytes + size + 2, 1);
    put16(bytes + size + 4, 1);
    put32(bytes + size + 6, 120);
    put16(bytes + size + 10, 4);
    address(bytes + size + 12, answer);
    size += 16;
    if (truncated_second) {
      /* A valid first RR must not grant when the later RR is incomplete. */
      put16(bytes + size, 0xc00c);
      put16(bytes + size + 2, 1);
      size += 4;
    }
  }
  return size;
}

static void set_mode(struct nosh_egress_bpf *skeleton, unsigned mode)
{
  uint32_t key = 0;
  struct nosh_egress_config config = {
    .target_cgroup_id = 1, .policy_generation = 1,
    .magic = NOSH_EGRESS_CONFIG_MAGIC, .map_abi = NOSH_EGRESS_MAP_ABI,
    .program_abi = NOSH_EGRESS_PROGRAM_ABI, .mode = mode,
    .policy_loaded = 1, .containment_loaded = 1,
  };
  CHECK(bpf_map_update_elem(bpf_map__fd(skeleton->maps.session_config), &key,
                            &config, BPF_ANY) == 0, "set test configuration");
}

static void run_packet(struct bpf_program *program, struct ring_buffer *ring,
                        const unsigned char *bytes, size_t size, unsigned expected,
                        const char *description)
{
  struct bpf_test_run_opts options = {
    .sz = sizeof(options), .data_in = bytes, .data_size_in = size, .repeat = 1,
  };
  observed_count = 0;
  CHECK(bpf_prog_test_run_opts(bpf_program__fd(program), &options) == 0,
         "BPF_PROG_TEST_RUN succeeds");
  CHECK(options.retval == expected, description);
  CHECK(ring_buffer__consume(ring) >= 0, "consume kernel decision events");
  printf("ok: %s\n", description);
}

static void expect_event(unsigned hook, unsigned reason, unsigned txid,
                          unsigned rule, unsigned kind)
{
  size_t index;
  for (index = 0; index < observed_count; index++) {
    const struct nosh_egress_event *event = &observed[index];
    if (event->hook == hook && event->reason == reason &&
        event->transaction_id == txid && event->rule_id == rule &&
        event->event_kind == kind)
      break;
  }
  CHECK(index < observed_count, "event hook/reason/transaction/rule/kind fields");
}

static void expect_dns_response_events(uint16_t txid)
{
  unsigned answer_records = 0;
  unsigned grant_records = 0;
  unsigned response_records = 0;
  CHECK(observed_count == 3, "one answer, grant, and aggregate DNS response event");
  for (size_t index = 0; index < observed_count; index++) {
    const struct nosh_egress_event *event = &observed[index];
    CHECK(event->hook == NOSH_EGRESS_HOOK_INGRESS && event->transaction_id == txid,
           "all DNS event wrappers preserve hook and high-bit transaction ID");
    CHECK(event->family == 4 && event->source_port == 53 &&
           event->verdict == NOSH_EGRESS_VERDICT_ALLOW && event->expires_ns > 0,
           "DNS event address family, source, verdict, and expiry");
    CHECK(event->domain_length == strlen("allowed.example") &&
           memcmp(event->domain, "allowed.example", event->domain_length) == 0,
           "DNS event question survives scratch phase reuse");
    if (event->event_kind == NOSH_EGRESS_EVENT_DNS_ANSWER) {
      answer_records++;
      CHECK(event->reason == NOSH_EGRESS_REASON_DNS_ANSWER && event->rule_id == 0 &&
             event->protocol == IPPROTO_UDP && event->destination_port == 53000 &&
             event->dns_record_type == 1 && !event->enforcement_applied,
             "DNS answer wrapper emits observation fields");
    } else if (event->packet_len == 0) {
      grant_records++;
      CHECK(event->reason == NOSH_EGRESS_REASON_DNS_GRANT && event->rule_id == 77 &&
             event->protocol == IPPROTO_TCP && event->destination_port == 443 &&
             event->enforcement_applied,
             "DNS grant wrapper emits reviewed transport and rule fields");
    } else {
      response_records++;
      CHECK(event->reason == NOSH_EGRESS_REASON_DNS_GRANT && event->rule_id == 77 &&
             event->protocol == IPPROTO_UDP && event->destination_port == 53000 &&
             event->enforcement_applied,
             "aggregate DNS response wrapper decodes packed reason correctly");
    }
  }
  CHECK(answer_records == 1 && grant_records == 1 && response_records == 1,
         "all three extracted DNS wrappers produce separate events");
}

static void static_rule(struct nosh_egress_bpf *skeleton)
{
  struct nosh_egress_v4_lpm_key key = {
    .prefixlen = 96, .generation = 1, .protocol = IPPROTO_TCP, .selector = 443,
  };
  struct nosh_egress_rule_value value = {.generation = 1, .rule_id = 42};
  address((unsigned char *)&key.address, "1.1.1.1");
  CHECK(bpf_map_update_elem(bpf_map__fd(skeleton->maps.static_v4), &key,
                            &value, BPF_ANY) == 0, "install exact IPv4 rule");
}

static void dns_policy(struct nosh_egress_bpf *skeleton)
{
  struct nosh_egress_resolver_key resolver = {.generation = 1, .family = 4};
  unsigned char allowed = 1;
  const char *name = "allowed.example";
  size_t length = strlen(name);
  struct nosh_egress_domain_key key = {.generation = 1, .prefixlen = 64 + length * 8};
  struct nosh_egress_domain_value value = {
    .generation = 1, .rule_id = 77, .port = 443, .protocol = IPPROTO_TCP,
    .name_length = length,
  };
  address(resolver.address, "8.8.8.8");
  CHECK(bpf_map_update_elem(bpf_map__fd(skeleton->maps.resolvers), &resolver,
                            &allowed, BPF_ANY) == 0, "install test resolver");
  for (size_t index = 0; index < length; index++)
    key.reversed_name[index] = name[length - index - 1];
  CHECK(bpf_map_update_elem(bpf_map__fd(skeleton->maps.domain_rules), &key,
                            &value, BPF_ANY) == 0, "install exact DNS rule");
}

static void expect_grant(struct nosh_egress_bpf *skeleton, const char *destination,
                          int expected)
{
  struct nosh_egress_grant_key key = {
    .generation = 1, .port = 443, .family = 4, .protocol = IPPROTO_TCP,
  };
  struct nosh_egress_grant_value value = {};
  address(key.address, destination);
  int result = bpf_map_lookup_elem(bpf_map__fd(skeleton->maps.dynamic_grants), &key, &value);
  CHECK(expected ? result == 0 && value.rule_id == 77 && value.expires_ns > 0 :
                   result < 0 && errno == ENOENT, "DNS grant map contents");
}

static void scratch_tests(struct nosh_egress_bpf *skeleton, struct ring_buffer *ring,
                           const unsigned char *bytes, size_t size)
{
  /* busy is the first u32 of the private per-CPU map. Discover the remaining
   * layout from libbpf rather than duplicating the private packet structure. */
  struct bpf_map *map = skeleton->maps.packet_scratch;
  size_t stride = (bpf_map__value_size(map) + 7U) & ~7U;
  int cpus = libbpf_num_possible_cpus();
  CHECK(cpus > 0 && stride >= sizeof(uint32_t), "scratch map CPU layout");
  size_t bytes_size = stride * (size_t)cpus;
  unsigned char *before = calloc(1, bytes_size);
  unsigned char *after = calloc(1, bytes_size);
  CHECK(before && after, "scratch inspection allocation");
  uint32_t key = 0;
  for (int cpu = 0; cpu < cpus; cpu++) {
    uint32_t busy = 1;
    memcpy(before + stride * cpu, &busy, sizeof(busy));
  }
  CHECK(bpf_map_update_elem(bpf_map__fd(map), &key, before, BPF_ANY) == 0,
         "preclaim every CPU scratch entry");
  run_packet(skeleton->progs.nosh_egress_egress, ring, bytes, size, 0,
              "busy scratch denies an otherwise allowed egress packet");
  expect_event(NOSH_EGRESS_HOOK_EGRESS, NOSH_EGRESS_REASON_CONFIG_INVALID, 0, 0,
                NOSH_EGRESS_EVENT_DECISION);
  run_packet(skeleton->progs.nosh_egress_ingress, ring, bytes, size, 0,
              "busy scratch denies ingress too");
  CHECK(bpf_map_lookup_elem(bpf_map__fd(map), &key, after) == 0,
         "inspect unowned scratch after rejection");
  CHECK(memcmp(before, after, bytes_size) == 0, "unowned scratch remains unchanged and busy");
  memset(before, 0, bytes_size);
  CHECK(bpf_map_update_elem(bpf_map__fd(map), &key, before, BPF_ANY) == 0,
         "release test scratch claims");
  run_packet(skeleton->progs.nosh_egress_egress, ring, bytes, size, 1,
              "egress runs after scratch claim release");
  CHECK(bpf_map_lookup_elem(bpf_map__fd(map), &key, after) == 0,
         "inspect scratch after owned processing");
  for (int cpu = 0; cpu < cpus; cpu++) {
    uint32_t busy;
    memcpy(&busy, after + stride * cpu, sizeof(busy));
    CHECK(busy == 0, "owned processing releases scratch");
  }
  free(after);
  free(before);
}

int main(void)
{
  struct nosh_egress_bpf *skeleton = nosh_egress_bpf__open_and_load();
  CHECK(skeleton != NULL, "load unattached BPF object");
  struct ring_buffer *ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
                                              receive_event, NULL, NULL);
  CHECK(ring != NULL, "create event reader");
  unsigned char packet[1024];
  unsigned char dns[512];
  size_t size;
  size_t dns_size;

  set_mode(skeleton, NOSH_EGRESS_MODE_ENFORCE);
  size = frame(packet, "10.0.0.2", "1.1.1.1", IPPROTO_TCP, 40000, 443, NULL, 0);
  run_packet(skeleton->progs.nosh_egress_egress, ring, packet, size, 0,
              "enforce default denies TCP443");
  expect_event(NOSH_EGRESS_HOOK_EGRESS, NOSH_EGRESS_REASON_DEFAULT_DENY, 0, 0, 1);
  static_rule(skeleton);
  run_packet(skeleton->progs.nosh_egress_egress, ring, packet, size, 1,
              "exact rule permits 1.1.1.1 TCP443");
  expect_event(NOSH_EGRESS_HOOK_EGRESS, NOSH_EGRESS_REASON_STATIC, 0, 42, 1);
  scratch_tests(skeleton, ring, packet, size);
  size = frame(packet, "1.1.1.1", "10.0.0.2", IPPROTO_TCP, 443, 40000, NULL, 0);
  run_packet(skeleton->progs.nosh_egress_ingress, ring, packet, size, 1,
              "ingress evaluates remote source and runs after scratch tests");
  expect_event(NOSH_EGRESS_HOOK_INGRESS, NOSH_EGRESS_REASON_STATIC, 0, 42, 1);
  size = frame(packet, "10.0.0.2", "1.0.0.1", IPPROTO_TCP, 40000, 443, NULL, 0);
  run_packet(skeleton->progs.nosh_egress_egress, ring, packet, size, 0,
              "exact rule leaves 1.0.0.1 TCP443 denied");
  set_mode(skeleton, NOSH_EGRESS_MODE_LEARN);
  run_packet(skeleton->progs.nosh_egress_egress, ring, packet, size, 1,
              "learn permits an unmatched destination");
  expect_event(NOSH_EGRESS_HOOK_EGRESS, NOSH_EGRESS_REASON_LEARN, 0, 0, 1);
  set_mode(skeleton, NOSH_EGRESS_MODE_ENFORCE);
  dns_policy(skeleton);

  for (unsigned scenario = 0; scenario < 3; scenario++) {
    uint16_t txid = 0xabcd + scenario;
    const char *destination = scenario == 0 ? "9.9.9.9" :
                              scenario == 1 ? "9.9.9.10" : "9.9.9.11";
    dns_size = dns_message(dns, txid, "allowed.example", 0, NULL, 0);
    size = frame(packet, "10.0.0.2", "8.8.8.8", IPPROTO_UDP, 53000, 53, dns, dns_size);
    run_packet(skeleton->progs.nosh_egress_egress, ring, packet, size, 1,
                "reviewed DNS question creates an observed transaction");
    expect_event(NOSH_EGRESS_HOOK_EGRESS, NOSH_EGRESS_REASON_DNS_RESOLVER, txid, 77, 1);
    dns_size = dns_message(dns, txid, scenario == 2 ? "unrelated.example" : "allowed.example",
                            1, destination, scenario == 1);
    size = frame(packet, "8.8.8.8", "10.0.0.2", IPPROTO_UDP, 53, 53000, dns, dns_size);
    run_packet(skeleton->progs.nosh_egress_ingress, ring, packet, size, scenario == 0,
                scenario == 0 ? "matching DNS response permits a staged grant" :
                scenario == 1 ? "later malformed DNS answer denies the complete response" :
                                "unrelated DNS question denies the response");
    expect_grant(skeleton, destination, scenario == 0);
    if (scenario == 0) {
      expect_event(NOSH_EGRESS_HOOK_INGRESS, NOSH_EGRESS_REASON_DNS_ANSWER, txid, 0, 2);
      expect_event(NOSH_EGRESS_HOOK_INGRESS, NOSH_EGRESS_REASON_DNS_GRANT, txid, 77, 1);
      expect_dns_response_events(txid);
    }
    size = frame(packet, "10.0.0.2", destination, IPPROTO_TCP, 40000, 443, NULL, 0);
    run_packet(skeleton->progs.nosh_egress_egress, ring, packet, size, scenario == 0,
                scenario == 0 ? "DNS grant permits TCP443 to the resolved address" :
                                "rejected DNS response leaves resolved address denied");
  }

  size = frame(packet, "10.0.0.2", "9.9.9.9", IPPROTO_TCP, 40000, 80, NULL, 0);
  run_packet(skeleton->progs.nosh_egress_egress, ring, packet, size, 0,
              "DNS grant for TCP443 does not authorize TCP80");
  ring_buffer__free(ring);
  nosh_egress_bpf__destroy(skeleton);
  printf("kernel packet regression: %u checks passed; no programs attached or pinned; no network traffic\n",
          checks);
  return 0;
}
