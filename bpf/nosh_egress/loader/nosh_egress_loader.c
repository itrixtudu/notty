// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "nosh_egress.h"
#include "nosh_egress.skel.h"
#include "nosh_egress_object_digest.h"

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#define LOADER_VERSION "2"
#define PROGRAM_COUNT 6
#define MAP_COUNT 12
#define FILE_HANDLE_BYTES 128
#define POLICY_LINE_MAX 1024
#define POLICY_RULE_MAX 32768
#define PIN_BASE "/sys/fs/bpf/nosh-guard"

static volatile sig_atomic_t stop_requested;

struct options {
  const char *command;
  const char *cgroup_path;
  const char *policy_path;
  const char *policy_digest;
  const char *pin_root;
  const char *run_id;
  const char *image_digest;
  const char *workspace_key;
  __u64 expected_cgroup_id;
  __u32 generation;
  __u8 mode;
  int status_fd;
  bool expected_cgroup_id_set;
};

struct cgroup_target {
  int fd;
  __u64 id;
  char path[PATH_MAX];
};

struct cidr_rule {
  __u8 family;
  __u8 protocol;
  __u8 selector_flags;
  __u8 reserved;
  __u16 port;
  __u16 selector;
  __u8 prefix;
  __u8 address[16];
  __u32 rule_id;
};

struct domain_rule {
  char name[NOSH_EGRESS_DOMAIN_LEN];
  __u8 length;
  __u8 wildcard;
  __u8 protocol;
  __u16 port;
  __u32 rule_id;
};

struct resolver_rule {
  __u8 family;
  __u8 address[16];
};

struct containment_rule {
  char id[NOSH_EGRESS_CONTAINMENT_ID_LEN];
  __u8 id_length;
  __u8 family;
  __u8 address[16];
};

struct policy {
  struct cidr_rule *cidrs;
  struct domain_rule *domains;
  struct resolver_rule *resolvers;
  struct containment_rule *containments;
  size_t cidr_count;
  size_t domain_count;
  size_t resolver_count;
  size_t containment_count;
  char containment_digest[NOSH_EGRESS_DIGEST_LEN];
};

struct runtime {
  FILE *events;
  __u64 cgroup_id;
  __u64 generation;
  __u8 mode;
  int stats_fd;
  int possible_cpus;
  __u64 *per_cpu;
  __u64 events_seen;
  __u64 decoder_errors;
};

struct sha256_context {
  __u32 state[8];
  __u64 bytes;
  __u8 block[64];
  size_t block_length;
};

static const __u32 sha256_constants[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static __u32 rotate_right(__u32 value, unsigned int bits)
{
  return (value >> bits) | (value << (32 - bits));
}

static void sha256_transform(struct sha256_context *context,
                             const __u8 block[64])
{
  __u32 words[64];
  __u32 a, b, c, d, e, f, g, h;
  int index;

  for (index = 0; index < 16; index++)
    words[index] = ((__u32)block[index * 4] << 24) |
      ((__u32)block[index * 4 + 1] << 16) |
      ((__u32)block[index * 4 + 2] << 8) | block[index * 4 + 3];
  for (index = 16; index < 64; index++) {
    __u32 left = words[index - 15];
    __u32 right = words[index - 2];
    __u32 s0 = rotate_right(left, 7) ^ rotate_right(left, 18) ^ (left >> 3);
    __u32 s1 = rotate_right(right, 17) ^ rotate_right(right, 19) ^ (right >> 10);
    words[index] = words[index - 16] + s0 + words[index - 7] + s1;
  }
  a = context->state[0]; b = context->state[1];
  c = context->state[2]; d = context->state[3];
  e = context->state[4]; f = context->state[5];
  g = context->state[6]; h = context->state[7];
  for (index = 0; index < 64; index++) {
    __u32 s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    __u32 choice = (e & f) ^ (~e & g);
    __u32 temporary1 = h + s1 + choice + sha256_constants[index] + words[index];
    __u32 s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    __u32 majority = (a & b) ^ (a & c) ^ (b & c);
    __u32 temporary2 = s0 + majority;
    h = g; g = f; f = e; e = d + temporary1;
    d = c; c = b; b = a; a = temporary1 + temporary2;
  }
  context->state[0] += a; context->state[1] += b;
  context->state[2] += c; context->state[3] += d;
  context->state[4] += e; context->state[5] += f;
  context->state[6] += g; context->state[7] += h;
}

static void sha256_init(struct sha256_context *context)
{
  memset(context, 0, sizeof(*context));
  context->state[0] = 0x6a09e667; context->state[1] = 0xbb67ae85;
  context->state[2] = 0x3c6ef372; context->state[3] = 0xa54ff53a;
  context->state[4] = 0x510e527f; context->state[5] = 0x9b05688c;
  context->state[6] = 0x1f83d9ab; context->state[7] = 0x5be0cd19;
}

static void sha256_update(struct sha256_context *context,
                          const void *data_value, size_t length)
{
  const __u8 *data = data_value;
  size_t take;

  context->bytes += length;
  while (length) {
    take = sizeof(context->block) - context->block_length;
    if (take > length)
      take = length;
    memcpy(context->block + context->block_length, data, take);
    context->block_length += take;
    data += take;
    length -= take;
    if (context->block_length == sizeof(context->block)) {
      sha256_transform(context, context->block);
      context->block_length = 0;
    }
  }
}

static void sha256_final(struct sha256_context *context, __u8 digest[32])
{
  __u64 bits = context->bytes * 8;
  __u8 padding[128] = {0x80};
  __u8 length_bytes[8];
  size_t padding_length;
  int index;

  for (index = 0; index < 8; index++)
    length_bytes[7 - index] = bits >> (index * 8);
  padding_length = context->block_length < 56 ?
    56 - context->block_length : 120 - context->block_length;
  sha256_update(context, padding, padding_length);
  sha256_update(context, length_bytes, sizeof(length_bytes));
  for (index = 0; index < 8; index++) {
    digest[index * 4] = context->state[index] >> 24;
    digest[index * 4 + 1] = context->state[index] >> 16;
    digest[index * 4 + 2] = context->state[index] >> 8;
    digest[index * 4 + 3] = context->state[index];
  }
}

static void sha256_text(const __u8 digest[32], char output[72])
{
  static const char hex[] = "0123456789abcdef";
  int index;

  memcpy(output, "sha256:", 7);
  for (index = 0; index < 32; index++) {
    output[7 + index * 2] = hex[digest[index] >> 4];
    output[8 + index * 2] = hex[digest[index] & 15];
  }
  output[71] = 0;
}

static const char *const link_names[PROGRAM_COUNT] = {
  "connect4", "connect6", "sendmsg4", "sendmsg6", "ingress", "egress",
};

/* Pinned policy ABI inventory. Private packet_scratch and events maps live
 * through program/loader references and are not part of this inventory. */
static const char *const map_names[MAP_COUNT] = {
  "session_config", "policy_identity", "containment", "static_v4", "static_v6",
  "domain_rules", "resolvers", "dynamic_grants", "dns_transactions",
  "dns_transaction_scratch", "dns_response_scratch", "stats",
};

struct map_contract {
  __u32 type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 required_flags;
};

static const struct map_contract map_contracts[MAP_COUNT] = {
  {BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(struct nosh_egress_config), 1, 0},
  {BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(struct nosh_egress_identity), 1, 0},
  {BPF_MAP_TYPE_HASH, sizeof(struct nosh_egress_containment_key),
   sizeof(struct nosh_egress_containment_value), NOSH_EGRESS_CONTAINMENT_MAX,
   0},
  {BPF_MAP_TYPE_LPM_TRIE, sizeof(struct nosh_egress_v4_lpm_key),
   sizeof(struct nosh_egress_rule_value), NOSH_EGRESS_STATIC_V4_MAX,
   BPF_F_NO_PREALLOC},
  {BPF_MAP_TYPE_LPM_TRIE, sizeof(struct nosh_egress_v6_lpm_key),
   sizeof(struct nosh_egress_rule_value), NOSH_EGRESS_STATIC_V6_MAX,
   BPF_F_NO_PREALLOC},
  {BPF_MAP_TYPE_LPM_TRIE, sizeof(struct nosh_egress_domain_key),
   sizeof(struct nosh_egress_domain_value), NOSH_EGRESS_DOMAIN_MAX,
   BPF_F_NO_PREALLOC},
  {BPF_MAP_TYPE_HASH, sizeof(struct nosh_egress_resolver_key), sizeof(__u8),
   NOSH_EGRESS_RESOLVER_MAX, 0},
  {BPF_MAP_TYPE_LRU_HASH, sizeof(struct nosh_egress_grant_key),
   sizeof(struct nosh_egress_grant_value), NOSH_EGRESS_GRANT_MAX, 0},
  {BPF_MAP_TYPE_LRU_HASH, sizeof(struct nosh_egress_dns_tx_key),
   sizeof(struct nosh_egress_dns_tx_value), NOSH_EGRESS_DNS_TX_MAX, 0},
  {BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(__u32),
   sizeof(struct nosh_egress_dns_tx_value), 1, 0},
  {BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(__u32),
   sizeof(struct nosh_egress_dns_response_scratch), 1, 0},
  {BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(__u32), sizeof(__u64),
   NOSH_EGRESS_STAT_MAX, 0},
};

static __u64 realtime_ns(void)
{
  struct timespec now = {};

  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    return 0;
  return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec;
}

static void usage(FILE *stream, const char *program)
{
  fprintf(stream,
          "Usage:\n"
          "  %s health [--cgroup ABS --cgroup-id UINT64]\n"
          "  %s verify  (load into kernel, then close; never attach or pin)\n"
          "  %s run --cgroup ABS --cgroup-id UINT64 --mode learn|audit|enforce\\\n\n"
          "      --policy FILE --policy-digest sha256:HEX --pin-root ABS\\\n\n"
          "      [--generation UINT32] [--run-id ID] [--image-digest DIGEST]\\\n\n"
          "      [--workspace-key KEY] [--status-fd FD]\n"
          "  %s status|snapshot|detach --pin-root ABS\n"
          "  %s --version\n",
          program, program, program, program, program);
}

static int parse_u64(const char *text, __u64 *value)
{
  char *end = NULL;
  unsigned long long parsed;

  if (!text || !*text || *text == '-')
    return -1;
  errno = 0;
  parsed = strtoull(text, &end, 10);
  if (errno || !end || *end)
    return -1;
  *value = parsed;
  return 0;
}

static int safe_identity(const char *text, size_t maximum)
{
  size_t index;

  if (!text || !*text || strlen(text) >= maximum)
    return 0;
  for (index = 0; text[index]; index++) {
    unsigned char byte = text[index];
    if (!((byte >= 'a' && byte <= 'z') ||
          (byte >= 'A' && byte <= 'Z') ||
          (byte >= '0' && byte <= '9') ||
          byte == ':' || byte == '.' || byte == '_' || byte == '-' ||
          byte == '+' || byte == '/' || byte == '@'))
      return 0;
  }
  return 1;
}

static int valid_pin_root(const char *root)
{
  const char *suffix;
  size_t index;

  if (!root || strncmp(root, PIN_BASE "/", strlen(PIN_BASE) + 1))
    return 0;
  suffix = root + strlen(PIN_BASE) + 1;
  if (!*suffix || strlen(root) >= PATH_MAX - 32)
    return 0;
  for (index = 0; suffix[index]; index++) {
    unsigned char byte = suffix[index];
    if (!((byte >= 'a' && byte <= 'z') ||
          (byte >= 'A' && byte <= 'Z') ||
          (byte >= '0' && byte <= '9') || byte == '.' || byte == '_' ||
          byte == '-'))
      return 0;
  }
  return strcmp(suffix, ".") && strcmp(suffix, "..");
}

static int valid_digest(const char *digest)
{
  size_t index;

  if (!digest || strlen(digest) != 71 || strncmp(digest, "sha256:", 7))
    return 0;
  for (index = 7; index < 71; index++)
    if (!((digest[index] >= '0' && digest[index] <= '9') ||
          (digest[index] >= 'a' && digest[index] <= 'f')))
      return 0;
  return 1;
}

static int parse_mode(const char *text, __u8 *mode)
{
  if (!strcmp(text, "learn"))
    *mode = NOSH_EGRESS_MODE_LEARN;
  else if (!strcmp(text, "audit"))
    *mode = NOSH_EGRESS_MODE_AUDIT;
  else if (!strcmp(text, "enforce"))
    *mode = NOSH_EGRESS_MODE_ENFORCE;
  else
    return -1;
  return 0;
}

static const char *mode_name(__u8 mode)
{
  if (mode == NOSH_EGRESS_MODE_LEARN)
    return "learn";
  if (mode == NOSH_EGRESS_MODE_AUDIT)
    return "audit";
  if (mode == NOSH_EGRESS_MODE_ENFORCE)
    return "enforce";
  return "unknown";
}

static int parse_options(int argc, char **argv, struct options *options)
{
  int index;

  memset(options, 0, sizeof(*options));
  options->generation = 1;
  options->status_fd = STDERR_FILENO;
  if (argc < 2)
    return -1;
  if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
    options->command = "help";
    return argc == 2 ? 0 : -1;
  }
  if (!strcmp(argv[1], "--version")) {
    options->command = "version";
    return argc == 2 ? 0 : -1;
  }
  options->command = argv[1];
  if (!strcmp(options->command, "verify"))
    return argc == 2 ? 0 : -1;
  if (strcmp(options->command, "health") &&
      strcmp(options->command, "run") &&
      strcmp(options->command, "status") &&
      strcmp(options->command, "snapshot") &&
      strcmp(options->command, "detach"))
    return -1;

  for (index = 2; index < argc; index++) {
    const char *argument = argv[index];
    const char *value;
    __u64 parsed;

    if (!strcmp(argument, "--help") || !strcmp(argument, "-h")) {
      options->command = "help";
      return 0;
    }
    if (++index >= argc)
      return -1;
    value = argv[index];
    if (!strcmp(argument, "--cgroup")) {
      if (options->cgroup_path)
        return -1;
      options->cgroup_path = value;
    } else if (!strcmp(argument, "--cgroup-id")) {
      if (options->expected_cgroup_id_set ||
          parse_u64(value, &options->expected_cgroup_id) ||
          !options->expected_cgroup_id)
        return -1;
      options->expected_cgroup_id_set = true;
    } else if (!strcmp(argument, "--mode")) {
      if (options->mode || parse_mode(value, &options->mode))
        return -1;
    } else if (!strcmp(argument, "--policy")) {
      if (options->policy_path)
        return -1;
      options->policy_path = value;
    } else if (!strcmp(argument, "--policy-digest")) {
      if (options->policy_digest || !valid_digest(value))
        return -1;
      options->policy_digest = value;
    } else if (!strcmp(argument, "--pin-root")) {
      if (options->pin_root || !valid_pin_root(value))
        return -1;
      options->pin_root = value;
    } else if (!strcmp(argument, "--generation")) {
      if (parse_u64(value, &parsed) || !parsed || parsed > UINT32_MAX)
        return -1;
      options->generation = parsed;
    } else if (!strcmp(argument, "--run-id")) {
      if (options->run_id || !safe_identity(value, NOSH_EGRESS_IDENTITY_LEN))
        return -1;
      options->run_id = value;
    } else if (!strcmp(argument, "--image-digest")) {
      if (options->image_digest ||
          !safe_identity(value, NOSH_EGRESS_IDENTITY_LEN))
        return -1;
      options->image_digest = value;
    } else if (!strcmp(argument, "--workspace-key")) {
      if (options->workspace_key ||
          !safe_identity(value, NOSH_EGRESS_IDENTITY_LEN))
        return -1;
      options->workspace_key = value;
    } else if (!strcmp(argument, "--status-fd")) {
      if (parse_u64(value, &parsed) || parsed < 2 || parsed > INT32_MAX ||
          fcntl((int)parsed, F_GETFD) < 0)
        return -1;
      options->status_fd = parsed;
    } else {
      return -1;
    }
  }

  if (!strcmp(options->command, "run"))
    return options->cgroup_path && options->expected_cgroup_id_set &&
      options->mode && options->policy_path && options->policy_digest &&
      options->pin_root ? 0 : -1;
  if (!strcmp(options->command, "health"))
    return options->cgroup_path == NULL || options->expected_cgroup_id_set ?
      0 : -1;
  return options->pin_root ? 0 : -1;
}

static int path_is_fs(const char *path, unsigned long magic)
{
  struct statfs filesystem = {};

  return statfs(path, &filesystem) == 0 &&
    (unsigned long)filesystem.f_type == magic;
}

static int cgroup_id_from_fd(int fd, __u64 *id)
{
  size_t size = sizeof(struct file_handle) + FILE_HANDLE_BYTES;
  struct file_handle *handle = calloc(1, size);
  int mount_id = 0;
  int result = -1;

  if (!handle)
    return -1;
  handle->handle_bytes = FILE_HANDLE_BYTES;
  if (name_to_handle_at(fd, ".", handle, &mount_id, 0) == 0 &&
      handle->handle_bytes >= sizeof(*id)) {
    memcpy(id, handle->f_handle, sizeof(*id));
    result = *id ? 0 : -1;
  }
  free(handle);
  return result;
}

static int resolve_cgroup(const struct options *options,
                          struct cgroup_target *target)
{
  char proc_path[64];
  ssize_t length;

  memset(target, 0, sizeof(*target));
  target->fd = -1;
  if (!options->cgroup_path || options->cgroup_path[0] != '/')
    return -1;
  target->fd = open(options->cgroup_path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (target->fd < 0 ||
      !path_is_fs(options->cgroup_path, CGROUP2_SUPER_MAGIC) ||
      cgroup_id_from_fd(target->fd, &target->id) ||
      (options->expected_cgroup_id_set &&
       target->id != options->expected_cgroup_id))
    goto fail;
  snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", target->fd);
  length = readlink(proc_path, target->path, sizeof(target->path) - 1);
  if (length < 0 || (size_t)length >= sizeof(target->path) - 1)
    goto fail;
  target->path[length] = 0;
  if (!strcmp(target->path, "/sys/fs/cgroup"))
    goto fail;
  return 0;
fail:
  if (target->fd >= 0)
    close(target->fd);
  target->fd = -1;
  return -1;
}

static int protocol_number(const char *text, __u8 *protocol)
{
  if (!strcmp(text, "any"))
    *protocol = NOSH_EGRESS_PROTOCOL_ANY;
  else if (!strcmp(text, "tcp"))
    *protocol = NOSH_EGRESS_PROTOCOL_TCP;
  else if (!strcmp(text, "udp"))
    *protocol = NOSH_EGRESS_PROTOCOL_UDP;
  else if (!strcmp(text, "icmp"))
    *protocol = NOSH_EGRESS_PROTOCOL_ICMP;
  else if (!strcmp(text, "icmpv6"))
    *protocol = NOSH_EGRESS_PROTOCOL_ICMPV6;
  else
    return -1;
  return 0;
}

static int parse_u32(const char *text, __u32 *value)
{
  __u64 parsed;

  if (parse_u64(text, &parsed) || parsed > UINT32_MAX)
    return -1;
  *value = parsed;
  return 0;
}

static int parse_port(const char *text, __u16 *port)
{
  __u64 parsed;

  if (parse_u64(text, &parsed) || parsed > UINT16_MAX)
    return -1;
  *port = parsed;
  return 0;
}

static int parse_icmp_selector(const char *text, __u8 *value,
                               __u8 flag, __u8 *flags)
{
  __u64 parsed;

  if (!strcmp(text, "any"))
    return 0;
  if (parse_u64(text, &parsed) || parsed > UINT8_MAX)
    return -1;
  *value = parsed;
  *flags |= flag;
  return 0;
}

static int canonical_network(__u8 *address, size_t bytes, unsigned int prefix)
{
  unsigned int index;

  for (index = prefix; index < bytes * 8; index++)
    if (address[index / 8] & (0x80U >> (index % 8)))
      return 0;
  return 1;
}

static int parse_cidr(char *text, struct cidr_rule *rule)
{
  char *slash = strrchr(text, '/');
  __u64 prefix;

  if (!slash)
    return -1;
  *slash++ = 0;
  if (parse_u64(slash, &prefix))
    return -1;
  if (inet_pton(AF_INET, text, rule->address) == 1) {
    if (prefix > 32 || !canonical_network(rule->address, 4, prefix))
      return -1;
    rule->family = NOSH_EGRESS_FAMILY_IPV4;
  } else if (inet_pton(AF_INET6, text, rule->address) == 1) {
    if (prefix > 128 || !canonical_network(rule->address, 16, prefix))
      return -1;
    rule->family = NOSH_EGRESS_FAMILY_IPV6;
  } else {
    return -1;
  }
  rule->prefix = prefix;
  return 0;
}

static int parse_containment(char *text, const char *explicit_id,
                             struct containment_rule *rule)
{
  char canonical[INET6_ADDRSTRLEN] = {};
  char *slash = strrchr(text, '/');
  __u64 prefix;
  int written;

  if (!slash)
    return -1;
  *slash++ = 0;
  if (parse_u64(slash, &prefix))
    return -1;
  if (inet_pton(AF_INET, text, rule->address) == 1) {
    if (prefix != 32 ||
        !inet_ntop(AF_INET, rule->address, canonical, sizeof(canonical)))
      return -1;
    rule->family = NOSH_EGRESS_FAMILY_IPV4;
  } else if (inet_pton(AF_INET6, text, rule->address) == 1) {
    if (prefix != 128 ||
        !inet_ntop(AF_INET6, rule->address, canonical, sizeof(canonical)))
      return -1;
    rule->family = NOSH_EGRESS_FAMILY_IPV6;
  } else {
    return -1;
  }
  if (explicit_id) {
    if (!safe_identity(explicit_id, sizeof(rule->id)))
      return -1;
    written = snprintf(rule->id, sizeof(rule->id), "%s", explicit_id);
  } else {
    written = snprintf(rule->id, sizeof(rule->id),
                       "platform-endpoint:%s", canonical);
  }
  if (written <= 0 || (size_t)written >= sizeof(rule->id))
    return -1;
  rule->id_length = written;
  return 0;
}

static int containment_digest(struct policy *policy)
{
  struct sha256_context hash;
  __u8 digest[32];
  size_t index;

  sha256_init(&hash);
  for (index = 0; index < policy->containment_count; index++) {
    const struct containment_rule *rule = &policy->containments[index];
    char address[INET6_ADDRSTRLEN] = {};
    char record[NOSH_EGRESS_CONTAINMENT_ID_LEN + INET6_ADDRSTRLEN + 16];
    int family = rule->family == NOSH_EGRESS_FAMILY_IPV4 ? AF_INET : AF_INET6;
    int prefix = rule->family == NOSH_EGRESS_FAMILY_IPV4 ? 32 : 128;
    int length;

    if (!inet_ntop(family, rule->address, address, sizeof(address)))
      return -1;
    length = snprintf(record, sizeof(record), "%s\t%s/%d\n",
                      rule->id, address, prefix);
    if (length <= 0 || (size_t)length >= sizeof(record))
      return -1;
    sha256_update(&hash, record, (size_t)length);
  }
  sha256_final(&hash, digest);
  sha256_text(digest, policy->containment_digest);
  return 0;
}

static int parse_domain(char *text, struct domain_rule *rule)
{
  size_t index;
  size_t label_length = 0;
  size_t label_count = 0;

  if (!strncmp(text, "*.", 2)) {
    rule->wildcard = 1;
    text += 2;
  }
  rule->length = strlen(text);
  if (!rule->length || rule->length >= NOSH_EGRESS_DOMAIN_LEN ||
      text[0] == '.' || text[rule->length - 1] == '.')
    return -1;
  for (index = 0; index < rule->length; index++) {
    unsigned char byte = text[index];

    if (byte >= 'A' && byte <= 'Z')
      byte += 'a' - 'A';
    if (byte == '.') {
      if (!label_length || label_length > 63 || text[index - 1] == '-')
        return -1;
      label_count++;
      label_length = 0;
    } else if ((byte >= 'a' && byte <= 'z') ||
               (byte >= '0' && byte <= '9')) {
      label_length++;
    } else if (byte == '-' && label_length) {
      label_length++;
    } else {
      return -1;
    }
    rule->name[index] = byte;
  }
  if (!label_length || label_length > 63 || text[rule->length - 1] == '-')
    return -1;
  label_count++;
  return label_count <= (rule->wildcard ?
    NOSH_EGRESS_DNS_MAX_LABELS - 1 : NOSH_EGRESS_DNS_MAX_LABELS) ? 0 : -1;
}

static int next_field(char **cursor, char **field)
{
  char *tab;

  if (!*cursor)
    return -1;
  *field = *cursor;
  tab = strchr(*cursor, '\t');
  if (tab) {
    *tab = 0;
    *cursor = tab + 1;
  } else {
    *cursor = NULL;
  }
  return **field ? 0 : -1;
}

static int load_policy(const char *path, const char *expected_digest,
                       struct policy *policy)
{
  FILE *stream = NULL;
  struct stat metadata = {};
  struct sha256_context hash;
  __u8 digest[32];
  char digest_text[72];
  char *line = NULL;
  size_t capacity = 0;
  ssize_t length;
  bool header_seen = false;
  int result = -1;
  int fd = -1;

  memset(policy, 0, sizeof(*policy));
  policy->cidrs = calloc(POLICY_RULE_MAX, sizeof(*policy->cidrs));
  policy->domains = calloc(POLICY_RULE_MAX, sizeof(*policy->domains));
  policy->resolvers = calloc(NOSH_EGRESS_RESOLVER_MAX,
                             sizeof(*policy->resolvers));
  policy->containments = calloc(NOSH_EGRESS_CONTAINMENT_MAX,
                                sizeof(*policy->containments));
  if (!policy->cidrs || !policy->domains || !policy->resolvers ||
      !policy->containments)
    goto out;
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0 || fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) ||
      metadata.st_uid != 0 || (metadata.st_mode & 022) || metadata.st_nlink != 1)
    goto out;
  stream = fdopen(fd, "r");
  if (!stream)
    goto out;
  fd = -1;
  sha256_init(&hash);
  while ((length = getline(&line, &capacity, stream)) >= 0) {
    char *cursor;
    char *kind;

    if (length > POLICY_LINE_MAX)
      goto out;
    sha256_update(&hash, line, (size_t)length);
    while (length && (line[length - 1] == '\n' || line[length - 1] == '\r'))
      line[--length] = 0;
    if (!length || line[0] == '#')
      continue;
    if (!header_seen) {
      if (strcmp(line, "NOSH_EGRESS_POLICY_V2"))
        goto out;
      header_seen = true;
      continue;
    }
    cursor = line;
    if (next_field(&cursor, &kind))
      goto out;
    if (!strcmp(kind, "resolver")) {
      struct resolver_rule *resolver;
      char *address;

      if (policy->resolver_count >= NOSH_EGRESS_RESOLVER_MAX ||
          next_field(&cursor, &address) || cursor)
        goto out;
      resolver = &policy->resolvers[policy->resolver_count];
      if (inet_pton(AF_INET, address, resolver->address) == 1)
        resolver->family = NOSH_EGRESS_FAMILY_IPV4;
      else if (inet_pton(AF_INET6, address, resolver->address) == 1)
        resolver->family = NOSH_EGRESS_FAMILY_IPV6;
      else
        goto out;
      policy->resolver_count++;
    } else if (!strcmp(kind, "containment")) {
      struct containment_rule *rule;
      char *first;
      char *endpoint;
      const char *explicit_id = NULL;
      size_t prior;

      if (policy->containment_count >= NOSH_EGRESS_CONTAINMENT_MAX ||
          next_field(&cursor, &first))
        goto out;
      if (cursor) {
        explicit_id = first;
        if (next_field(&cursor, &endpoint) || cursor)
          goto out;
      } else {
        endpoint = first;
      }
      rule = &policy->containments[policy->containment_count];
      if (parse_containment(endpoint, explicit_id, rule))
        goto out;
      for (prior = 0; prior < policy->containment_count; prior++) {
        const struct containment_rule *candidate = &policy->containments[prior];
        size_t bytes = rule->family == NOSH_EGRESS_FAMILY_IPV4 ? 4 : 16;

        if (!strcmp(candidate->id, rule->id) ||
            (candidate->family == rule->family &&
             !memcmp(candidate->address, rule->address, bytes)))
          goto out;
      }
      policy->containment_count++;
    } else if (!strcmp(kind, "cidr")) {
      struct cidr_rule *rule;
      char *cidr;
      char *protocol;
      char *port;
      char *rule_id;
      char *icmp_type = NULL;
      char *icmp_code = NULL;
      __u8 type = 0;
      __u8 code = 0;

      if (policy->cidr_count >= POLICY_RULE_MAX ||
          next_field(&cursor, &cidr) ||
          next_field(&cursor, &protocol) ||
          next_field(&cursor, &port) ||
          next_field(&cursor, &rule_id))
        goto out;
      if (cursor && (next_field(&cursor, &icmp_type) ||
                     next_field(&cursor, &icmp_code) || cursor))
        goto out;
      rule = &policy->cidrs[policy->cidr_count];
      if (parse_cidr(cidr, rule) || protocol_number(protocol, &rule->protocol) ||
          parse_port(port, &rule->port) || parse_u32(rule_id, &rule->rule_id) ||
          !rule->rule_id ||
          ((rule->protocol == NOSH_EGRESS_PROTOCOL_ICMP ||
            rule->protocol == NOSH_EGRESS_PROTOCOL_ICMPV6) && rule->port) ||
          ((rule->protocol == NOSH_EGRESS_PROTOCOL_ICMP) !=
           (rule->family == NOSH_EGRESS_FAMILY_IPV4) &&
           rule->protocol != NOSH_EGRESS_PROTOCOL_ANY &&
           rule->protocol != NOSH_EGRESS_PROTOCOL_TCP &&
           rule->protocol != NOSH_EGRESS_PROTOCOL_UDP) ||
          ((icmp_type || icmp_code) &&
           rule->protocol != NOSH_EGRESS_PROTOCOL_ICMP &&
           rule->protocol != NOSH_EGRESS_PROTOCOL_ICMPV6) ||
          ((icmp_type || icmp_code) &&
           (parse_icmp_selector(icmp_type, &type,
                                NOSH_EGRESS_SELECTOR_ICMP_TYPE,
                                &rule->selector_flags) ||
            parse_icmp_selector(icmp_code, &code,
                                NOSH_EGRESS_SELECTOR_ICMP_CODE,
                                &rule->selector_flags))))
        goto out;
      rule->selector = ((__u16)type << 8) | code;
      policy->cidr_count++;
    } else if (!strcmp(kind, "domain")) {
      struct domain_rule *rule;
      char *domain;
      char *protocol;
      char *port;
      char *rule_id;

      if (policy->domain_count >= POLICY_RULE_MAX ||
          next_field(&cursor, &domain) ||
          next_field(&cursor, &protocol) ||
          next_field(&cursor, &port) ||
          next_field(&cursor, &rule_id) || cursor)
        goto out;
      rule = &policy->domains[policy->domain_count];
      if (parse_domain(domain, rule) ||
          protocol_number(protocol, &rule->protocol) ||
          (rule->protocol != NOSH_EGRESS_PROTOCOL_ANY &&
           rule->protocol != NOSH_EGRESS_PROTOCOL_TCP &&
           rule->protocol != NOSH_EGRESS_PROTOCOL_UDP) ||
          parse_port(port, &rule->port) || parse_u32(rule_id, &rule->rule_id) ||
          !rule->rule_id)
        goto out;
      policy->domain_count++;
    } else {
      goto out;
    }
  }
  sha256_final(&hash, digest);
  sha256_text(digest, digest_text);
  if (!header_seen || ferror(stream) || !policy->resolver_count ||
      !policy->containment_count || containment_digest(policy) ||
      strcmp(digest_text, expected_digest))
    goto out;
  result = 0;
out:
  free(line);
  if (stream)
    fclose(stream);
  if (fd >= 0)
    close(fd);
  return result;
}

static void free_policy(struct policy *policy)
{
  free(policy->cidrs);
  free(policy->domains);
  free(policy->resolvers);
  free(policy->containments);
  memset(policy, 0, sizeof(*policy));
}

static int populate_policy(struct nosh_egress_bpf *skeleton,
                           const struct policy *policy, __u32 generation)
{
  size_t index;

  for (index = 0; index < policy->containment_count; index++) {
    const struct containment_rule *rule = &policy->containments[index];
    struct nosh_egress_containment_key key = {
      .generation = generation,
      .family = rule->family,
    };
    struct nosh_egress_containment_value value = {
      .generation = generation,
      .id_length = rule->id_length,
    };

    memcpy(key.address, rule->address, sizeof(key.address));
    memcpy(value.id, rule->id, sizeof(value.id));
    if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.containment),
                            &key, &value, BPF_NOEXIST))
      return -1;
  }
  for (index = 0; index < policy->resolver_count; index++) {
    struct nosh_egress_resolver_key key = {
      .generation = generation,
      .family = policy->resolvers[index].family,
    };
    __u8 value = 1;
    memcpy(key.address, policy->resolvers[index].address, 16);
    if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.resolvers),
                            &key, &value, BPF_NOEXIST))
      return -1;
  }
  for (index = 0; index < policy->cidr_count; index++) {
    const struct cidr_rule *rule = &policy->cidrs[index];
    struct nosh_egress_rule_value value = {
      .generation = generation,
      .rule_id = rule->rule_id,
    };
    if (rule->family == NOSH_EGRESS_FAMILY_IPV4) {
      struct nosh_egress_v4_lpm_key key = {
        .prefixlen = 64 + rule->prefix,
        .generation = generation,
        .protocol = rule->protocol,
        .selector_flags = rule->selector_flags,
        .selector = rule->selector_flags ? rule->selector : rule->port,
      };
      memcpy(&key.address, rule->address, 4);
      if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.static_v4),
                              &key, &value, BPF_NOEXIST))
        return -1;
    } else {
      struct nosh_egress_v6_lpm_key key = {
        .prefixlen = 64 + rule->prefix,
        .generation = generation,
        .protocol = rule->protocol,
        .selector_flags = rule->selector_flags,
        .selector = rule->selector_flags ? rule->selector : rule->port,
      };
      memcpy(key.address, rule->address, 16);
      if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.static_v6),
                              &key, &value, BPF_NOEXIST))
        return -1;
    }
  }
  for (index = 0; index < policy->domain_count; index++) {
    const struct domain_rule *rule = &policy->domains[index];
    size_t prior;
    __u8 slot = 0;
    struct nosh_egress_domain_key key = {
      .prefixlen = 64 + (__u32)rule->length * 8,
      .generation = generation,
      .wildcard = rule->wildcard,
    };
    struct nosh_egress_domain_value value = {
      .generation = generation,
      .rule_id = rule->rule_id,
      .port = rule->port,
      .protocol = rule->protocol,
      .flags = rule->wildcard ? NOSH_EGRESS_DOMAIN_WILDCARD : 0,
      .name_length = rule->length,
    };
    size_t byte;
    for (prior = 0; prior < index; prior++) {
      const struct domain_rule *candidate = &policy->domains[prior];
      if (candidate->wildcard == rule->wildcard &&
          candidate->length == rule->length &&
          !memcmp(candidate->name, rule->name, rule->length))
        slot++;
    }
    if (slot >= NOSH_EGRESS_DOMAIN_RULE_SLOTS)
      return -1;
    key.slot = slot;
    for (byte = 0; byte < rule->length; byte++)
      key.reversed_name[byte] = rule->name[rule->length - byte - 1];
    if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.domain_rules),
                            &key, &value, BPF_NOEXIST))
      return -1;
  }
  return 0;
}

static int ensure_pin_root(const char *root)
{
  char maps[PATH_MAX];
  char links[PATH_MAX];
  struct stat metadata = {};

  if (!valid_pin_root(root))
    return -1;
  if (!path_is_fs("/sys/fs/bpf", BPF_FS_MAGIC))
    return -1;
  if (mkdir(PIN_BASE, 0755) && errno != EEXIST)
    return -1;
  if (lstat(PIN_BASE, &metadata) || !S_ISDIR(metadata.st_mode) ||
      S_ISLNK(metadata.st_mode) || metadata.st_uid != 0 ||
      (metadata.st_mode & 022))
    return -1;
  if (mkdir(root, 0700))
    return -1;
  snprintf(maps, sizeof(maps), "%s/maps", root);
  snprintf(links, sizeof(links), "%s/links", root);
  if (mkdir(maps, 0700) || mkdir(links, 0700))
    return -1;
  if (lstat(root, &metadata) || !S_ISDIR(metadata.st_mode) ||
      S_ISLNK(metadata.st_mode) || metadata.st_uid != 0 ||
      (metadata.st_mode & 077) || !path_is_fs(root, BPF_FS_MAGIC))
    return -1;
  return 0;
}

static int validate_pin_root(const char *root)
{
  struct stat metadata = {};

  return valid_pin_root(root) && !lstat(root, &metadata) &&
    S_ISDIR(metadata.st_mode) && !S_ISLNK(metadata.st_mode) &&
    metadata.st_uid == 0 && !(metadata.st_mode & 077) &&
    path_is_fs(root, BPF_FS_MAGIC);
}

static void pin_path(char *destination, size_t size, const char *root,
                     const char *kind, const char *name)
{
  snprintf(destination, size, "%s/%s/%s", root, kind, name);
}

static int pin_all(struct nosh_egress_bpf *skeleton,
                   struct bpf_link *links[PROGRAM_COUNT], const char *root)
{
  struct bpf_map *maps[MAP_COUNT] = {
    skeleton->maps.session_config, skeleton->maps.policy_identity,
    skeleton->maps.containment, skeleton->maps.static_v4,
    skeleton->maps.static_v6,
    skeleton->maps.domain_rules, skeleton->maps.resolvers,
    skeleton->maps.dynamic_grants, skeleton->maps.dns_transactions,
    skeleton->maps.dns_transaction_scratch, skeleton->maps.dns_response_scratch,
    skeleton->maps.stats,
  };
  char path[PATH_MAX];
  int index;

  for (index = 0; index < MAP_COUNT; index++) {
    pin_path(path, sizeof(path), root, "maps", map_names[index]);
    if (bpf_map__pin(maps[index], path))
      return -1;
  }
  for (index = 0; index < PROGRAM_COUNT; index++) {
    pin_path(path, sizeof(path), root, "links", link_names[index]);
    if (bpf_link__pin(links[index], path))
      return -1;
  }
  return 0;
}

static void unlink_pins(const char *root)
{
  char path[PATH_MAX];
  int index;

  for (index = PROGRAM_COUNT - 1; index >= 0; index--) {
    pin_path(path, sizeof(path), root, "links", link_names[index]);
    unlink(path);
  }
  for (index = MAP_COUNT - 1; index >= 0; index--) {
    pin_path(path, sizeof(path), root, "maps", map_names[index]);
    unlink(path);
  }
  snprintf(path, sizeof(path), "%s/links", root);
  rmdir(path);
  snprintf(path, sizeof(path), "%s/maps", root);
  rmdir(path);
  rmdir(root);
}

static int map_contract_id(int fd, int index)
{
  struct bpf_map_info map = {};
  __u32 length = sizeof(map);
  const struct map_contract *contract;

  if (index < 0 || index >= MAP_COUNT)
    return -1;
  contract = &map_contracts[index];
  if (bpf_obj_get_info_by_fd(fd, &map, &length) ||
      map.type != contract->type || map.key_size != contract->key_size ||
      map.value_size != contract->value_size ||
      map.max_entries != contract->max_entries ||
      (map.map_flags & contract->required_flags) != contract->required_flags)
    return -1;
  return map.id;
}

static int link_info_at(const char *root, const char *name,
                        __u64 expected_cgroup_id, bool allow_detached,
                        __u32 *link_id, __u32 *program_id)
{
  struct bpf_link_info info = {};
  __u32 length = sizeof(info);
  char path[PATH_MAX];
  int fd;

  pin_path(path, sizeof(path), root, "links", name);
  fd = bpf_obj_get(path);
  if (fd < 0)
    return -1;
  if (bpf_obj_get_info_by_fd(fd, &info, &length)) {
    close(fd);
    return -1;
  }
  close(fd);
  if (!expected_cgroup_id || info.type != BPF_LINK_TYPE_CGROUP ||
      !info.id || !info.prog_id)
    return -1;
  /* A pinned cgroup link survives destruction of its target, but the kernel
   * reports cgroup_id zero once detached. Only final snapshots and cleanup
   * may accept that state; it is never evidence of live enforcement. */
  if (info.cgroup.cgroup_id != expected_cgroup_id &&
      !(allow_detached && info.cgroup.cgroup_id == 0)) {
    fprintf(stderr,
            "nosh-egress: pinned link %s has cgroup %" PRIu64
            "; expected %" PRIu64 "%s\n",
            path, (uint64_t)info.cgroup.cgroup_id,
            (uint64_t)expected_cgroup_id,
            allow_detached ? " or an already-detached link" : "");
    return -1;
  }
  *link_id = info.id;
  *program_id = info.prog_id;
  return 0;
}

static int validate_pinned_contract(const char *root, __u64 cgroup_id,
                                    bool allow_detached)
{
  char path[PATH_MAX];
  int index;

  for (index = 0; index < PROGRAM_COUNT; index++) {
    __u32 link_id;
    __u32 program_id;

    if (link_info_at(root, link_names[index], cgroup_id, allow_detached,
                     &link_id, &program_id) || !link_id || !program_id)
      return -1;
  }
  for (index = 0; index < MAP_COUNT; index++) {
    int fd;
    int id;

    pin_path(path, sizeof(path), root, "maps", map_names[index]);
    fd = bpf_obj_get(path);
    if (fd < 0)
      return -1;
    id = map_contract_id(fd, index);
    close(fd);
    if (id <= 0)
      return -1;
  }
  return 0;
}

static int emit_attestation(FILE *stream, const char *status,
                            const char *message, const char *root,
                            const struct nosh_egress_config *config,
                            const struct nosh_egress_identity *identity)
{
  char path[PATH_MAX];
  bool first = true;
  int index;

  fprintf(stream,
          "{\"schemaVersion\":2,\"recordKind\":\"status\","
          "\"timestampUnixNs\":\"%" PRIu64 "\",\"status\":\"%s\","
          "\"cgroupId\":\"%" PRIu64 "\",\"attachedPrograms\":6,"
          "\"mode\":\"%s\",\"policyDigest\":\"%s\","
          "\"objectDigest\":\"%s\",\"containmentDigest\":\"%s\","
          "\"containmentCount\":%u,"
          "\"mapAbi\":%u,\"programAbi\":%u,\"pinRoot\":\"%s\","
          "\"message\":\"%s\",\"attestation\":{"
          "\"targetCgroupId\":\"%" PRIu64 "\","
          "\"policyDigest\":\"%s\",\"containmentDigest\":\"%s\","
          "\"containmentCount\":%u,\"mode\":\"%s\","
          "\"objectDigest\":\"%s\","
          "\"mapAbi\":%u,\"programAbi\":%u,"
          "\"policyGeneration\":\"%" PRIu64 "\","
          "\"runId\":\"%s\",\"imageDigest\":\"%s\","
          "\"workspaceKey\":\"%s\",\"linkIds\":[",
          (uint64_t)realtime_ns(), status,
          (uint64_t)config->target_cgroup_id, mode_name(config->mode),
          identity->policy_digest, identity->object_digest,
          identity->containment_digest, identity->containment_count,
          config->map_abi, config->program_abi,
          root, message, (uint64_t)config->target_cgroup_id,
          identity->policy_digest, identity->containment_digest,
          identity->containment_count, mode_name(config->mode),
          identity->object_digest, config->map_abi,
          config->program_abi, (uint64_t)config->policy_generation,
          identity->run_id, identity->image_digest, identity->workspace_key);
  for (index = 0; index < PROGRAM_COUNT; index++) {
    __u32 link_id;
    __u32 program_id;
    if (link_info_at(root, link_names[index], config->target_cgroup_id, false,
                     &link_id, &program_id))
      return -1;
    fprintf(stream, "%s%u", first ? "" : ",", link_id);
    first = false;
  }
  fputs("],\"programIds\":[", stream);
  first = true;
  for (index = 0; index < PROGRAM_COUNT; index++) {
    __u32 link_id;
    __u32 program_id;
    if (link_info_at(root, link_names[index], config->target_cgroup_id, false,
                     &link_id, &program_id))
      return -1;
    fprintf(stream, "%s%u", first ? "" : ",", program_id);
    first = false;
  }
  fputs("],\"mapIds\":[", stream);
  first = true;
  for (index = 0; index < MAP_COUNT; index++) {
    int fd;
    int id;
    pin_path(path, sizeof(path), root, "maps", map_names[index]);
    fd = bpf_obj_get(path);
    if (fd < 0)
      return -1;
    id = map_contract_id(fd, index);
    close(fd);
    if (id < 0)
      return -1;
    fprintf(stream, "%s%d", first ? "" : ",", id);
    first = false;
  }
  fputs("]}}\n", stream);
  return fflush(stream) ? -1 : 0;
}

static int read_pinned_identity(const char *root,
                                struct nosh_egress_config *config,
                                struct nosh_egress_identity *identity)
{
  char path[PATH_MAX];
  __u32 key = 0;
  int fd;

  if (!validate_pin_root(root))
    return -1;
  pin_path(path, sizeof(path), root, "maps", "session_config");
  fd = bpf_obj_get(path);
  if (fd < 0 || map_contract_id(fd, 0) < 0 ||
      bpf_map_lookup_elem(fd, &key, config)) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  close(fd);
  pin_path(path, sizeof(path), root, "maps", "policy_identity");
  fd = bpf_obj_get(path);
  if (fd < 0 || map_contract_id(fd, 1) < 0 ||
      bpf_map_lookup_elem(fd, &key, identity)) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  close(fd);
  return config->magic == NOSH_EGRESS_CONFIG_MAGIC &&
    config->map_abi == NOSH_EGRESS_MAP_ABI &&
    config->program_abi == NOSH_EGRESS_PROGRAM_ABI &&
    config->target_cgroup_id && config->policy_generation &&
    config->policy_loaded && config->containment_loaded &&
    config->mode >= NOSH_EGRESS_MODE_LEARN &&
    config->mode <= NOSH_EGRESS_MODE_ENFORCE &&
    memchr(identity->policy_digest, 0, sizeof(identity->policy_digest)) &&
    memchr(identity->object_digest, 0, sizeof(identity->object_digest)) &&
    memchr(identity->run_id, 0, sizeof(identity->run_id)) &&
    memchr(identity->image_digest, 0, sizeof(identity->image_digest)) &&
    memchr(identity->workspace_key, 0, sizeof(identity->workspace_key)) &&
    memchr(identity->containment_digest, 0,
           sizeof(identity->containment_digest)) &&
    identity->containment_count > 0 &&
    identity->containment_count <= NOSH_EGRESS_CONTAINMENT_MAX &&
    !strcmp(identity->object_digest, NOSH_EGRESS_OBJECT_DIGEST) &&
    valid_digest(identity->policy_digest) &&
    valid_digest(identity->containment_digest) ? 0 : -1;
}

static __u64 sum_stat(int fd, int possible_cpus, __u64 *values, __u32 key)
{
  __u64 total = 0;
  int cpu;

  memset(values, 0, (size_t)possible_cpus * sizeof(*values));
  if (bpf_map_lookup_elem(fd, &key, values))
    return UINT64_MAX;
  for (cpu = 0; cpu < possible_cpus; cpu++) {
    if (UINT64_MAX - total < values[cpu])
      return UINT64_MAX;
    total += values[cpu];
  }
  return total;
}

static int emit_stats(struct runtime *runtime, bool final)
{
  __u64 counters[NOSH_EGRESS_STAT_MAX];
  int stat;

  for (stat = 0; stat < NOSH_EGRESS_STAT_MAX; stat++)
    counters[stat] = sum_stat(runtime->stats_fd, runtime->possible_cpus,
                              runtime->per_cpu, stat);
  fprintf(runtime->events,
          "{\"schemaVersion\":2,\"recordKind\":\"stats\","
          "\"timestampUnixNs\":\"%" PRIu64 "\","
          "\"cgroupId\":\"%" PRIu64 "\","
          "\"policyGeneration\":\"%" PRIu64 "\","
          "\"mode\":\"%s\",\"final\":%s,"
          "\"eventsSeen\":\"%" PRIu64 "\","
          "\"decoderErrors\":\"%" PRIu64 "\",\"counters\":{"
          "\"allowed\":\"%" PRIu64 "\","
          "\"wouldDeny\":\"%" PRIu64 "\","
          "\"denied\":\"%" PRIu64 "\","
          "\"ringbufDrops\":\"%" PRIu64 "\","
          "\"parseErrors\":\"%" PRIu64 "\","
          "\"fragments\":\"%" PRIu64 "\","
          "\"configInvalid\":\"%" PRIu64 "\","
          "\"policyMisses\":\"%" PRIu64 "\","
          "\"dnsQueries\":\"%" PRIu64 "\","
          "\"dnsResponses\":\"%" PRIu64 "\","
          "\"dnsTransactionMisses\":\"%" PRIu64 "\","
          "\"dnsGrantUpdates\":\"%" PRIu64 "\","
          "\"dnsGrantFailures\":\"%" PRIu64 "\","
          "\"dnsUnsupported\":\"%" PRIu64 "\","
          "\"unsupportedProtocol\":\"%" PRIu64 "\","
          "\"coverageAllowed\":\"%" PRIu64 "\","
          "\"coverageWouldDeny\":\"%" PRIu64 "\","
          "\"coverageDenied\":\"%" PRIu64 "\","
          "\"containmentDenied\":\"%" PRIu64 "\","
          "\"backendDenied\":\"%" PRIu64 "\","
          "\"dnsAnswers\":\"%" PRIu64 "\"}}\n",
          (uint64_t)realtime_ns(), (uint64_t)runtime->cgroup_id,
          (uint64_t)runtime->generation, mode_name(runtime->mode),
          final ? "true" : "false", (uint64_t)runtime->events_seen,
          (uint64_t)runtime->decoder_errors,
          (uint64_t)counters[NOSH_EGRESS_STAT_ALLOWED],
          (uint64_t)counters[NOSH_EGRESS_STAT_WOULD_DENY],
          (uint64_t)counters[NOSH_EGRESS_STAT_DENIED],
          (uint64_t)counters[NOSH_EGRESS_STAT_RINGBUF_DROPS],
          (uint64_t)counters[NOSH_EGRESS_STAT_PARSE_ERRORS],
          (uint64_t)counters[NOSH_EGRESS_STAT_FRAGMENTS],
          (uint64_t)counters[NOSH_EGRESS_STAT_CONFIG_INVALID],
          (uint64_t)counters[NOSH_EGRESS_STAT_POLICY_MISS],
          (uint64_t)counters[NOSH_EGRESS_STAT_DNS_QUERIES],
          (uint64_t)counters[NOSH_EGRESS_STAT_DNS_RESPONSES],
          (uint64_t)counters[NOSH_EGRESS_STAT_DNS_TX_MISS],
          (uint64_t)counters[NOSH_EGRESS_STAT_DNS_GRANT_UPDATES],
          (uint64_t)counters[NOSH_EGRESS_STAT_DNS_GRANT_FAILURES],
          (uint64_t)counters[NOSH_EGRESS_STAT_DNS_UNSUPPORTED],
          (uint64_t)counters[NOSH_EGRESS_STAT_UNSUPPORTED_PROTOCOL],
          (uint64_t)counters[NOSH_EGRESS_STAT_COVERAGE_ALLOWED],
          (uint64_t)counters[NOSH_EGRESS_STAT_COVERAGE_WOULD_DENY],
          (uint64_t)counters[NOSH_EGRESS_STAT_COVERAGE_DENIED],
          (uint64_t)counters[NOSH_EGRESS_STAT_CONTAINMENT_DENIED],
          (uint64_t)counters[NOSH_EGRESS_STAT_BACKEND_DENIED],
          (uint64_t)counters[NOSH_EGRESS_STAT_DNS_ANSWERS]);
  return fflush(runtime->events) ? -1 : 0;
}

static const char *verdict_name(__u8 verdict)
{
  if (verdict == NOSH_EGRESS_VERDICT_ALLOW)
    return "allow";
  if (verdict == NOSH_EGRESS_VERDICT_WOULD_DENY)
    return "would-deny";
  if (verdict == NOSH_EGRESS_VERDICT_DENY)
    return "deny";
  return NULL;
}

static const char *decision_class_name(__u8 decision_class)
{
  switch (decision_class) {
  case NOSH_EGRESS_DECISION_POLICY_ALLOW: return "policy-allow";
  case NOSH_EGRESS_DECISION_OBSERVED: return "observed";
  case NOSH_EGRESS_DECISION_WOULD_DENY: return "would-deny";
  case NOSH_EGRESS_DECISION_POLICY_DENY: return "policy-deny";
  case NOSH_EGRESS_DECISION_CONTAINMENT_DENY: return "containment-deny";
  case NOSH_EGRESS_DECISION_COVERAGE_GAP: return "coverage-gap";
  case NOSH_EGRESS_DECISION_BACKEND_DENY: return "backend-deny";
  case NOSH_EGRESS_DECISION_INFRASTRUCTURE_ALLOW:
    return "infrastructure-allow";
  case NOSH_EGRESS_DECISION_DNS_OBSERVATION: return "dns-observation";
  default: return NULL;
  }
}

static const char *reason_name(__u8 reason)
{
  switch (reason) {
  case NOSH_EGRESS_REASON_STATIC: return "static-policy";
  case NOSH_EGRESS_REASON_DNS_RESOLVER: return "configured-resolver";
  case NOSH_EGRESS_REASON_DNS_GRANT: return "dns-grant";
  case NOSH_EGRESS_REASON_LEARN: return "learn-observed";
  case NOSH_EGRESS_REASON_DEFAULT_DENY: return "default-deny";
  case NOSH_EGRESS_REASON_CONFIG_INVALID: return "backend-invalid";
  case NOSH_EGRESS_REASON_PARSE_ERROR: return "parse-gap";
  case NOSH_EGRESS_REASON_FRAGMENT: return "fragment-gap";
  case NOSH_EGRESS_REASON_DNS_DOMAIN_DENY: return "dns-domain-deny";
  case NOSH_EGRESS_REASON_DNS_RESPONSE_DENY:
    return "dns-response-unmatched";
  case NOSH_EGRESS_REASON_UNSUPPORTED: return "unsupported-gap";
  case NOSH_EGRESS_REASON_IPV6_CONTROL: return "ipv6-control";
  case NOSH_EGRESS_REASON_CONTAINMENT: return "platform-containment";
  case NOSH_EGRESS_REASON_HIDDEN_DESTINATION:
    return "hidden-destination";
  case NOSH_EGRESS_REASON_UNKNOWN_DESTINATION:
    return "unknown-destination";
  case NOSH_EGRESS_REASON_DNS_ANSWER: return "dns-answer";
  case NOSH_EGRESS_REASON_DNS_QUERY_OBSERVED:
    return "dns-query-observed";
  case NOSH_EGRESS_REASON_DNS_RESPONSE: return "dns-response";
  default: return NULL;
  }
}

static int event_callback(void *opaque, void *data, size_t size)
{
  struct runtime *runtime = opaque;
  const struct nosh_egress_event *event = data;
  char source[INET6_ADDRSTRLEN] = {};
  char destination[INET6_ADDRSTRLEN] = {};
  const char *verdict;
  const char *decision_class;
  const char *reason;
  int family;

  if (size != sizeof(*event) ||
      event->schema_version != NOSH_EGRESS_SCHEMA_VERSION ||
      event->event_size != sizeof(*event) ||
      event->cgroup_id != runtime->cgroup_id ||
      event->policy_generation != runtime->generation ||
      !(verdict = verdict_name(event->verdict)) ||
      !(decision_class = decision_class_name(event->decision_class)) ||
      !(reason = reason_name(event->reason)) ||
      event->domain_length >= NOSH_EGRESS_DOMAIN_LEN ||
      event->containment_id_length >= NOSH_EGRESS_CONTAINMENT_ID_LEN ||
      event->enforcement_applied > 1 ||
      (event->event_kind != NOSH_EGRESS_EVENT_DECISION &&
       event->event_kind != NOSH_EGRESS_EVENT_DNS_ANSWER) ||
      (event->event_kind == NOSH_EGRESS_EVENT_DECISION &&
       event->dns_record_type) ||
      (event->event_kind == NOSH_EGRESS_EVENT_DNS_ANSWER &&
       (event->reason != NOSH_EGRESS_REASON_DNS_ANSWER ||
        event->decision_class != NOSH_EGRESS_DECISION_DNS_OBSERVATION ||
        event->verdict != NOSH_EGRESS_VERDICT_ALLOW ||
        (event->family != NOSH_EGRESS_FAMILY_IPV4 &&
         event->family != NOSH_EGRESS_FAMILY_IPV6))) ||
      (event->reason == NOSH_EGRESS_REASON_CONTAINMENT &&
       !event->containment_id_length) ||
      (event->reason != NOSH_EGRESS_REASON_CONTAINMENT &&
       event->containment_id_length)) {
    runtime->decoder_errors++;
    return 0;
  }
  family = event->family == NOSH_EGRESS_FAMILY_IPV4 ? AF_INET : AF_INET6;
  if (event->family == NOSH_EGRESS_FAMILY_IPV4 ||
      event->family == NOSH_EGRESS_FAMILY_IPV6) {
    inet_ntop(family, event->source_address, source, sizeof(source));
    if (event->event_kind == NOSH_EGRESS_EVENT_DECISION)
      inet_ntop(family, event->destination_address, destination,
                sizeof(destination));
  }
  if (event->event_kind == NOSH_EGRESS_EVENT_DNS_ANSWER) {
    int answer_family = event->dns_record_type == 1 ? AF_INET : AF_INET6;

    if ((event->dns_record_type != 1 && event->dns_record_type != 28) ||
        !event->domain_length ||
        !inet_ntop(answer_family, event->destination_address, destination,
                   sizeof(destination))) {
      runtime->decoder_errors++;
      return 0;
    }
    fprintf(runtime->events,
            "{\"schemaVersion\":2,\"recordKind\":\"dns-answer\","
            "\"timestampMonotonicNs\":\"%" PRIu64 "\","
            "\"cgroupId\":\"%" PRIu64 "\","
            "\"policyGeneration\":\"%" PRIu64 "\","
            "\"hook\":%u,\"transportFamily\":%u,"
            "\"transportProtocol\":%u,\"resolverAddress\":\"%s\","
            "\"resolverPort\":%u,\"clientPort\":%u,"
            "\"domain\":\"%.*s\",\"dnsRecordType\":\"%s\","
            "\"answerAddress\":\"%s\",\"decisionClass\":\"%s\","
            "\"reason\":\"%s\",\"reasonCode\":%u,"
            "\"enforcementApplied\":%s,\"transactionId\":%u,"
            "\"expiresMonotonicNs\":\"%" PRIu64 "\"}\n",
            (uint64_t)event->timestamp_ns, (uint64_t)event->cgroup_id,
            (uint64_t)event->policy_generation, event->hook, event->family,
            event->protocol, source, event->source_port,
            event->destination_port, event->domain_length, event->domain,
            event->dns_record_type == 1 ? "A" : "AAAA", destination,
            decision_class, reason, event->reason,
            event->enforcement_applied ? "true" : "false",
            event->transaction_id, (uint64_t)event->expires_ns);
    runtime->events_seen++;
    return fflush(runtime->events) ? -EIO : 0;
  }
  fprintf(runtime->events,
          "{\"schemaVersion\":2,\"recordKind\":\"decision\","
          "\"timestampMonotonicNs\":\"%" PRIu64 "\","
          "\"cgroupId\":\"%" PRIu64 "\","
          "\"policyGeneration\":\"%" PRIu64 "\","
          "\"hook\":%u,\"family\":%u,\"protocol\":%u,"
          "\"sourceAddress\":\"%s\",\"destinationAddress\":\"%s\","
          "\"sourcePort\":%u,\"destinationPort\":%u,"
          "\"verdict\":\"%s\",\"decisionClass\":\"%s\","
          "\"reason\":\"%s\",\"reasonCode\":%u,"
          "\"enforcementApplied\":%s,\"containmentId\":\"%.*s\","
          "\"ruleId\":%u,"
          "\"packetBytes\":%u,\"transactionId\":%u,\"domain\":\"%.*s\","
          "\"expiresMonotonicNs\":\"%" PRIu64 "\"}\n",
          (uint64_t)event->timestamp_ns, (uint64_t)event->cgroup_id,
          (uint64_t)event->policy_generation, event->hook, event->family,
          event->protocol, source, destination, event->source_port,
          event->destination_port, verdict, decision_class, reason,
          event->reason, event->enforcement_applied ? "true" : "false",
          event->containment_id_length, event->containment_id,
          event->rule_id, event->packet_len, event->transaction_id,
          event->domain_length, event->domain, (uint64_t)event->expires_ns);
  runtime->events_seen++;
  return fflush(runtime->events) ? -EIO : 0;
}

static void signal_handler(int signal_number)
{
  (void)signal_number;
  stop_requested = 1;
}

static int run_health(const struct options *options)
{
  struct utsname system = {};
  struct cgroup_target target = {.fd = -1};
  bool root = geteuid() == 0;
  bool kernel = uname(&system) == 0;
  bool btf = access("/sys/kernel/btf/vmlinux", R_OK) == 0;
  bool cgroup = path_is_fs("/sys/fs/cgroup", CGROUP2_SUPER_MAGIC);
  bool bpffs = path_is_fs("/sys/fs/bpf", BPF_FS_MAGIC);
  bool target_ok = !options->cgroup_path || !resolve_cgroup(options, &target);
  bool healthy = root && kernel && btf && cgroup && bpffs && target_ok;
  char cgroup_id[32] = "null";

  if (target.fd >= 0)
    snprintf(cgroup_id, sizeof(cgroup_id), "\"%" PRIu64 "\"",
             (uint64_t)target.id);

  printf("{\"schemaVersion\":2,\"recordKind\":\"status\","
         "\"timestampUnixNs\":\"%" PRIu64 "\",\"status\":\"%s\","
         "\"cgroupId\":%s,\"attachedPrograms\":0,"
         "\"mapAbi\":%d,\"programAbi\":%d,"
         "\"objectDigest\":\"%s\","
         "\"message\":\"%s\",\"checks\":{"
         "\"effectiveRoot\":%s,\"kernelIdentity\":%s,"
         "\"kernelBtf\":%s,\"cgroupV2\":%s,\"bpffs\":%s,"
         "\"targetCgroup\":%s}}\n",
         (uint64_t)realtime_ns(), healthy ? "healthy" : "unhealthy",
         cgroup_id,
         NOSH_EGRESS_MAP_ABI, NOSH_EGRESS_PROGRAM_ABI,
         NOSH_EGRESS_OBJECT_DIGEST,
         healthy ? "host prerequisites satisfied" :
                   "eBPF egress prerequisites are incomplete",
         root ? "true" : "false", kernel ? "true" : "false",
         btf ? "true" : "false", cgroup ? "true" : "false",
         bpffs ? "true" : "false", target_ok ? "true" : "false");
  if (target.fd >= 0)
    close(target.fd);
  return healthy ? 0 : 1;
}

static int run_status(const struct options *options)
{
  struct nosh_egress_config config = {};
  struct nosh_egress_identity identity = {};

  if (read_pinned_identity(options->pin_root, &config, &identity))
    return 1;
  return emit_attestation(stdout, "ready", "pinned enforcement active",
                          options->pin_root, &config, &identity) ? 1 : 0;
}

static int run_snapshot(const struct options *options)
{
  struct nosh_egress_config config = {};
  struct nosh_egress_identity identity = {};
  struct runtime runtime = {};
  char path[PATH_MAX];
  int result;

  if (read_pinned_identity(options->pin_root, &config, &identity))
    return 1;
  if (validate_pinned_contract(options->pin_root, config.target_cgroup_id, true))
    return 1;
  pin_path(path, sizeof(path), options->pin_root, "maps", "stats");
  runtime.stats_fd = bpf_obj_get(path);
  runtime.possible_cpus = libbpf_num_possible_cpus();
  runtime.per_cpu = calloc((size_t)runtime.possible_cpus,
                           sizeof(*runtime.per_cpu));
  runtime.events = stdout;
  runtime.cgroup_id = config.target_cgroup_id;
  runtime.generation = config.policy_generation;
  runtime.mode = config.mode;
  if (runtime.stats_fd < 0 || runtime.possible_cpus <= 0 || !runtime.per_cpu)
    result = 1;
  else {
    printf("{\"schemaVersion\":2,\"recordKind\":\"snapshot-header\","
           "\"policyDigest\":\"%s\",\"objectDigest\":\"%s\","
           "\"containmentDigest\":\"%s\",\"containmentCount\":%u,"
           "\"pinRoot\":\"%s\"}\n",
           identity.policy_digest, identity.object_digest,
           identity.containment_digest, identity.containment_count,
           options->pin_root);
    result = emit_stats(&runtime, true) ? 1 : 0;
  }
  if (runtime.stats_fd >= 0)
    close(runtime.stats_fd);
  free(runtime.per_cpu);
  return result;
}

static int run_detach(const struct options *options)
{
  struct nosh_egress_config config = {};
  struct nosh_egress_identity identity = {};

  if (read_pinned_identity(options->pin_root, &config, &identity))
    return 1;
  if (validate_pinned_contract(options->pin_root, config.target_cgroup_id, true))
    return 1;
  unlink_pins(options->pin_root);
  if (access(options->pin_root, F_OK) == 0 || errno != ENOENT) {
    fprintf(stderr, "nosh-egress: pinned state remains after detach: %s\n",
            options->pin_root);
    return 1;
  }
  printf("{\"schemaVersion\":2,\"recordKind\":\"status\","
         "\"timestampUnixNs\":\"%" PRIu64 "\",\"status\":\"detached\","
         "\"cgroupId\":\"%" PRIu64 "\",\"policyDigest\":\"%s\","
         "\"containmentDigest\":\"%s\",\"containmentCount\":%u,"
         "\"pinRoot\":\"%s\",\"message\":\"pinned enforcement removed\"}\n",
         (uint64_t)realtime_ns(), (uint64_t)config.target_cgroup_id,
         identity.policy_digest, identity.containment_digest,
         identity.containment_count, options->pin_root);
  return 0;
}

/* Exercise the actual kernel verifier without attaching hooks or pinning
 * objects. Closing the skeleton releases the temporary programs and maps. */
static int run_verify(void)
{
  struct nosh_egress_bpf *skeleton;

  if (geteuid() != 0) {
    fprintf(stderr, "nosh-egress verify: root is required\n");
    return 1;
  }
  skeleton = nosh_egress_bpf__open_and_load();
  if (!skeleton)
    return 1;
  nosh_egress_bpf__destroy(skeleton);
  printf("{\"schemaVersion\":2,\"recordKind\":\"verification\","
         "\"status\":\"verified\",\"objectDigest\":\"%s\","
         "\"attachedPrograms\":0,\"pinned\":false}\n",
         NOSH_EGRESS_OBJECT_DIGEST);
  return 0;
}

static int run_loader(const struct options *options)
{
  struct nosh_egress_bpf *skeleton = NULL;
  struct bpf_program *programs[PROGRAM_COUNT];
  struct bpf_link *links[PROGRAM_COUNT] = {};
  struct cgroup_target target = {.fd = -1};
  struct nosh_egress_config config = {};
  struct nosh_egress_identity identity = {};
  struct policy policy = {};
  struct runtime runtime = {.events = stdout, .stats_fd = -1};
  struct ring_buffer *ring = NULL;
  struct sigaction action = {};
  FILE *status = NULL;
  __u32 key = 0;
  bool pin_root_created = false;
  bool pinned = false;
  int status_dup = -1;
  int result = 1;
  int index;

  status_dup = dup(options->status_fd);
  if (status_dup < 0 || !(status = fdopen(status_dup, "a")))
    return 1;
  setvbuf(status, NULL, _IOLBF, 0);
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (resolve_cgroup(options, &target) ||
      load_policy(options->policy_path, options->policy_digest, &policy)) {
    fprintf(status, "{\"schemaVersion\":2,\"recordKind\":\"status\","
            "\"status\":\"error\",\"message\":\"invalid cgroup or policy manifest\"}\n");
    goto out;
  }
  if (ensure_pin_root(options->pin_root)) {
    fprintf(status, "{\"schemaVersion\":2,\"recordKind\":\"status\","
            "\"status\":\"error\",\"message\":\"cannot create exclusive bpffs pin root\"}\n");
    goto out;
  }
  pin_root_created = true;
  skeleton = nosh_egress_bpf__open_and_load();
  if (!skeleton)
    goto out;
  config.target_cgroup_id = target.id;
  config.policy_generation = options->generation;
  config.magic = NOSH_EGRESS_CONFIG_MAGIC;
  config.map_abi = NOSH_EGRESS_MAP_ABI;
  config.program_abi = NOSH_EGRESS_PROGRAM_ABI;
  config.mode = options->mode;
  config.policy_loaded = 0;
  config.containment_loaded = 0;
  snprintf(identity.policy_digest, sizeof(identity.policy_digest), "%s",
           options->policy_digest);
  snprintf(identity.object_digest, sizeof(identity.object_digest), "%s",
           NOSH_EGRESS_OBJECT_DIGEST);
  snprintf(identity.containment_digest,
           sizeof(identity.containment_digest), "%s",
           policy.containment_digest);
  identity.containment_count = policy.containment_count;
  if (options->run_id)
    snprintf(identity.run_id, sizeof(identity.run_id), "%s", options->run_id);
  if (options->image_digest)
    snprintf(identity.image_digest, sizeof(identity.image_digest), "%s",
             options->image_digest);
  if (options->workspace_key)
    snprintf(identity.workspace_key, sizeof(identity.workspace_key), "%s",
             options->workspace_key);
  if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.session_config),
                          &key, &config, BPF_ANY) ||
      bpf_map_update_elem(bpf_map__fd(skeleton->maps.policy_identity),
                          &key, &identity, BPF_ANY) ||
      populate_policy(skeleton, &policy, options->generation))
    goto out;
  config.policy_loaded = 1;
  config.containment_loaded = 1;
  if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.session_config),
                          &key, &config, BPF_ANY))
    goto out;

  programs[0] = skeleton->progs.nosh_egress_connect4;
  programs[1] = skeleton->progs.nosh_egress_connect6;
  programs[2] = skeleton->progs.nosh_egress_sendmsg4;
  programs[3] = skeleton->progs.nosh_egress_sendmsg6;
  programs[4] = skeleton->progs.nosh_egress_ingress;
  programs[5] = skeleton->progs.nosh_egress_egress;
  for (index = 0; index < PROGRAM_COUNT; index++) {
    links[index] = bpf_program__attach_cgroup(programs[index], target.fd);
    if (!links[index] || libbpf_get_error(links[index])) {
      links[index] = NULL;
      goto out;
    }
  }
  if (pin_all(skeleton, links, options->pin_root))
    goto out;
  pinned = true;

  runtime.cgroup_id = target.id;
  runtime.generation = options->generation;
  runtime.mode = options->mode;
  runtime.stats_fd = bpf_map__fd(skeleton->maps.stats);
  runtime.possible_cpus = libbpf_num_possible_cpus();
  runtime.per_cpu = calloc((size_t)runtime.possible_cpus,
                           sizeof(*runtime.per_cpu));
  ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events), event_callback,
                          &runtime, NULL);
  if (!runtime.per_cpu || !ring || runtime.possible_cpus <= 0)
    goto out;
  if (emit_attestation(status, "ready", "all programs attached and pinned",
                       options->pin_root, &config, &identity) ||
      emit_stats(&runtime, false))
    goto out;

  action.sa_handler = signal_handler;
  sigemptyset(&action.sa_mask);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGTERM, &action, NULL);
  while (!stop_requested) {
    int poll_result = ring_buffer__poll(ring, 1000);
    if (poll_result < 0 && poll_result != -EINTR)
      goto out;
  }
  while (ring_buffer__consume(ring) > 0)
    ;
  if (emit_stats(&runtime, true))
    goto out;
  fprintf(status,
          "{\"schemaVersion\":2,\"recordKind\":\"status\","
          "\"timestampUnixNs\":\"%" PRIu64 "\",\"status\":\"stopped\","
          "\"cgroupId\":\"%" PRIu64 "\",\"attachedPrograms\":6,"
          "\"mode\":\"%s\",\"policyDigest\":\"%s\","
          "\"objectDigest\":\"%s\",\"containmentDigest\":\"%s\","
          "\"containmentCount\":%u,"
          "\"mapAbi\":%d,\"programAbi\":%d,\"pinRoot\":\"%s\","
          "\"message\":\"collector stopped; pinned enforcement remains active\"}\n",
          (uint64_t)realtime_ns(), (uint64_t)target.id,
          mode_name(options->mode), options->policy_digest,
          NOSH_EGRESS_OBJECT_DIGEST, identity.containment_digest,
          identity.containment_count,
          NOSH_EGRESS_MAP_ABI, NOSH_EGRESS_PROGRAM_ABI, options->pin_root);
  result = 0;
out:
  if (result && pin_root_created && !pinned)
    unlink_pins(options->pin_root);
  if (result && pinned)
    fprintf(status,
            "{\"schemaVersion\":2,\"recordKind\":\"status\","
            "\"status\":\"error\",\"message\":\"collector failed after attach; pinned enforcement remains active\"}\n");
  if (ring)
    ring_buffer__free(ring);
  free(runtime.per_cpu);
  for (index = 0; index < PROGRAM_COUNT; index++)
    if (links[index])
      bpf_link__destroy(links[index]);
  if (skeleton)
    nosh_egress_bpf__destroy(skeleton);
  if (target.fd >= 0)
    close(target.fd);
  free_policy(&policy);
  fclose(status);
  return result;
}

int main(int argc, char **argv)
{
  struct options options;

  if (parse_options(argc, argv, &options)) {
    usage(stderr, argv[0]);
    return 2;
  }
  if (!strcmp(options.command, "help")) {
    usage(stdout, argv[0]);
    return 0;
  }
  if (!strcmp(options.command, "version")) {
    printf("nosh-egress-loader %s schema %d map-abi %d program-abi %d\n",
           LOADER_VERSION, NOSH_EGRESS_SCHEMA_VERSION,
           NOSH_EGRESS_MAP_ABI, NOSH_EGRESS_PROGRAM_ABI);
    return 0;
  }
  if (!strcmp(options.command, "verify"))
    return run_verify();
  if (!strcmp(options.command, "health"))
    return run_health(&options);
  if (!strcmp(options.command, "status"))
    return run_status(&options);
  if (!strcmp(options.command, "snapshot"))
    return run_snapshot(&options);
  if (!strcmp(options.command, "detach"))
    return run_detach(&options);
  return run_loader(&options);
}
