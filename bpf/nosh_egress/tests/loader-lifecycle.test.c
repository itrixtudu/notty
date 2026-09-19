// SPDX-License-Identifier: 0BSD OR GPL-2.0-only
/* Exercise production loader lifecycle code with in-memory pin and BPF
 * metadata fixtures. No BPF syscall, attachment, or pin operation is run. */
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

static int lifecycle_obj_get(const char *path);
static int lifecycle_obj_info(int fd, void *info, __u32 *length);
static int lifecycle_map_lookup(int fd, const void *key, void *value);
static int lifecycle_close(int fd);
static int lifecycle_lstat(const char *path, struct stat *value);
static int lifecycle_statfs(const char *path, struct statfs *value);
static int lifecycle_unlink(const char *path);
static int lifecycle_rmdir(const char *path);
static int lifecycle_access(const char *path, int mode);
static int lifecycle_cpu_count(void);
static FILE *lifecycle_output;

#define bpf_obj_get lifecycle_obj_get
#define bpf_obj_get_info_by_fd lifecycle_obj_info
#define bpf_map_lookup_elem lifecycle_map_lookup
#define close lifecycle_close
#define lstat lifecycle_lstat
#define statfs(path, value) lifecycle_statfs(path, value)
#define unlink lifecycle_unlink
#define rmdir lifecycle_rmdir
#define access lifecycle_access
#define libbpf_num_possible_cpus lifecycle_cpu_count
#undef stdout
#define stdout lifecycle_output
#define printf(...) fprintf(lifecycle_output, __VA_ARGS__)
#define main loader_program_main
#include "../loader/nosh_egress_loader.c"
#undef main
#undef printf
#undef stdout
#undef libbpf_num_possible_cpus
#undef access
#undef rmdir
#undef unlink
#undef statfs
#undef lstat
#undef close
#undef bpf_map_lookup_elem
#undef bpf_obj_get_info_by_fd
#undef bpf_obj_get

#define TEST_ROOT "/sys/fs/bpf/nosh-guard/lifecycle-test"
#define TEST_CGROUP_ID 7654321ULL
#define LINK_FD_BASE 1000
#define MAP_FD_BASE 2000

static struct bpf_link_info test_links[PROGRAM_COUNT];
static struct bpf_map_info test_maps[MAP_COUNT];
static struct nosh_egress_config test_config;
static struct nosh_egress_identity test_identity;
static bool links_present[PROGRAM_COUNT];
static bool maps_present[MAP_COUNT];
static bool root_present;
static bool link_directory_present;
static bool map_directory_present;
static int unlink_failure;
static unsigned unlink_calls;
static unsigned assertions;

#define CHECK(condition, message) do { \
  assertions++; \
  if (!(condition)) { \
    fprintf(stderr, "FAIL: %s at line %d\n", message, __LINE__); \
    exit(1); \
  } \
} while (0)

static int pin_index(const char *path, const char *kind,
                      const char *const *names, int count)
{
  char expected[PATH_MAX];
  for (int index = 0; index < count; index++) {
    snprintf(expected, sizeof(expected), "%s/%s/%s", TEST_ROOT, kind, names[index]);
    if (!strcmp(path, expected))
      return index;
  }
  return -1;
}

static int lifecycle_obj_get(const char *path)
{
  int index = pin_index(path, "links", link_names, PROGRAM_COUNT);
  if (root_present && index >= 0 && links_present[index])
    return LINK_FD_BASE + index;
  index = pin_index(path, "maps", map_names, MAP_COUNT);
  if (root_present && index >= 0 && maps_present[index])
    return MAP_FD_BASE + index;
  errno = ENOENT;
  return -1;
}

static int lifecycle_obj_info(int fd, void *info, __u32 *length)
{
  if (fd >= LINK_FD_BASE && fd < LINK_FD_BASE + PROGRAM_COUNT &&
      *length == sizeof(struct bpf_link_info)) {
    memcpy(info, &test_links[fd - LINK_FD_BASE], *length);
    return 0;
  }
  if (fd >= MAP_FD_BASE && fd < MAP_FD_BASE + MAP_COUNT &&
      *length == sizeof(struct bpf_map_info)) {
    memcpy(info, &test_maps[fd - MAP_FD_BASE], *length);
    return 0;
  }
  errno = EBADF;
  return -1;
}

static int lifecycle_map_lookup(int fd, const void *key, void *value)
{
  if (fd == MAP_FD_BASE && *(__u32 *)key == 0) {
    memcpy(value, &test_config, sizeof(test_config));
    return 0;
  }
  if (fd == MAP_FD_BASE + 1 && *(__u32 *)key == 0) {
    memcpy(value, &test_identity, sizeof(test_identity));
    return 0;
  }
  if (fd == MAP_FD_BASE + MAP_COUNT - 1 && *(__u32 *)key < NOSH_EGRESS_STAT_MAX) {
    *(__u64 *)value = 10 + *(__u32 *)key;
    return 0;
  }
  errno = EBADF;
  return -1;
}

static int lifecycle_close(int fd)
{
  (void)fd;
  return 0;
}

static int lifecycle_lstat(const char *path, struct stat *value)
{
  if (strcmp(path, TEST_ROOT) || !root_present) {
    errno = ENOENT;
    return -1;
  }
  memset(value, 0, sizeof(*value));
  value->st_mode = S_IFDIR | 0700;
  value->st_uid = 0;
  return 0;
}

static int lifecycle_statfs(const char *path, struct statfs *value)
{
  if (strcmp(path, TEST_ROOT) || !root_present) {
    errno = ENOENT;
    return -1;
  }
  memset(value, 0, sizeof(*value));
  value->f_type = BPF_FS_MAGIC;
  return 0;
}

static int lifecycle_unlink(const char *path)
{
  unlink_calls++;
  int index = pin_index(path, "links", link_names, PROGRAM_COUNT);
  if (index >= 0) {
    if (index == unlink_failure) {
      errno = EACCES;
      return -1;
    }
    links_present[index] = false;
    return 0;
  }
  index = pin_index(path, "maps", map_names, MAP_COUNT);
  if (index >= 0) {
    maps_present[index] = false;
    return 0;
  }
  errno = ENOENT;
  return -1;
}

static int lifecycle_rmdir(const char *path)
{
  if (!strcmp(path, TEST_ROOT "/links")) {
    for (int index = 0; index < PROGRAM_COUNT; index++)
      if (links_present[index])
        goto not_empty;
    link_directory_present = false;
    return 0;
  }
  if (!strcmp(path, TEST_ROOT "/maps")) {
    for (int index = 0; index < MAP_COUNT; index++)
      if (maps_present[index])
        goto not_empty;
    map_directory_present = false;
    return 0;
  }
  if (!strcmp(path, TEST_ROOT) && !link_directory_present && !map_directory_present) {
    root_present = false;
    return 0;
  }
not_empty:
  errno = ENOTEMPTY;
  return -1;
}

static int lifecycle_access(const char *path, int mode)
{
  (void)mode;
  if (!strcmp(path, TEST_ROOT) && root_present)
    return 0;
  errno = ENOENT;
  return -1;
}

static int lifecycle_cpu_count(void)
{
  return 1;
}

static void reset_fixture(void)
{
  static const __u32 attach_types[PROGRAM_COUNT] = {
    BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET6_CONNECT,
    BPF_CGROUP_UDP4_SENDMSG, BPF_CGROUP_UDP6_SENDMSG,
    BPF_CGROUP_INET_INGRESS, BPF_CGROUP_INET_EGRESS,
  };
  root_present = link_directory_present = map_directory_present = true;
  unlink_failure = -1;
  unlink_calls = 0;
  for (int index = 0; index < PROGRAM_COUNT; index++) {
    test_links[index] = (struct bpf_link_info) {
      .type = BPF_LINK_TYPE_CGROUP, .id = 61 + index, .prog_id = 4373 + index,
      .cgroup = {.cgroup_id = TEST_CGROUP_ID, .attach_type = attach_types[index]},
    };
    links_present[index] = true;
  }
  for (int index = 0; index < MAP_COUNT; index++) {
    test_maps[index] = (struct bpf_map_info) {
      .type = map_contracts[index].type, .id = 90 + index,
      .key_size = map_contracts[index].key_size,
      .value_size = map_contracts[index].value_size,
      .max_entries = map_contracts[index].max_entries,
      .map_flags = map_contracts[index].required_flags,
    };
    maps_present[index] = true;
  }
  test_config = (struct nosh_egress_config) {
    .target_cgroup_id = TEST_CGROUP_ID, .policy_generation = 1,
    .magic = NOSH_EGRESS_CONFIG_MAGIC, .map_abi = NOSH_EGRESS_MAP_ABI,
    .program_abi = NOSH_EGRESS_PROGRAM_ABI, .mode = NOSH_EGRESS_MODE_LEARN,
    .policy_loaded = 1, .containment_loaded = 1,
  };
  memset(&test_identity, 0, sizeof(test_identity));
  strcpy(test_identity.object_digest, NOSH_EGRESS_OBJECT_DIGEST);
  strcpy(test_identity.policy_digest, NOSH_EGRESS_OBJECT_DIGEST);
  strcpy(test_identity.containment_digest, NOSH_EGRESS_OBJECT_DIGEST);
  strcpy(test_identity.run_id, "lifecycle-test");
  strcpy(test_identity.image_digest, NOSH_EGRESS_OBJECT_DIGEST);
  strcpy(test_identity.workspace_key, "fixture-workspace");
  test_identity.containment_count = 2;
}

static char *invoke(int (*command)(const struct options *), int expected)
{
  char *text = NULL;
  size_t size = 0;
  struct options options = {.pin_root = TEST_ROOT};
  lifecycle_output = open_memstream(&text, &size);
  CHECK(lifecycle_output != NULL, "create output capture");
  int result = command(&options);
  CHECK(fclose(lifecycle_output) == 0, "finalize output capture");
  lifecycle_output = NULL;
  CHECK(result == expected, "production lifecycle command result");
  return text;
}

static void assert_rejected_without_cleanup(void)
{
  char *output = invoke(run_snapshot, 1);
  CHECK(strstr(output, "snapshot-header") == NULL, "invalid contract has no final snapshot");
  free(output);
  output = invoke(run_detach, 1);
  CHECK(strstr(output, "\"status\":\"detached\"") == NULL, "invalid contract never claims detachment");
  CHECK(unlink_calls == 0 && root_present, "invalid contract preserves existing pins");
  free(output);
}

int main(void)
{
  char *output;
  reset_fixture();
  CHECK(validate_pinned_contract(TEST_ROOT, TEST_CGROUP_ID, false) == 0,
         "live links pass live validation");
  CHECK(validate_pinned_contract(TEST_ROOT, TEST_CGROUP_ID, true) == 0,
         "live links pass post-stop validation");
  output = invoke(run_status, 0);
  CHECK(strstr(output, "\"status\":\"ready\"") != NULL, "live status attests readiness");
  free(output);

  for (int index = 0; index < PROGRAM_COUNT; index++) {
    reset_fixture();
    test_links[index].cgroup.cgroup_id = 0;
    CHECK(validate_pinned_contract(TEST_ROOT, TEST_CGROUP_ID, false) != 0,
           "every detached hook fails live validation");
    CHECK(validate_pinned_contract(TEST_ROOT, TEST_CGROUP_ID, true) == 0,
           "mixed live and detached hooks pass post-stop validation");
    output = invoke(run_status, 1);
    free(output);
    output = invoke(run_snapshot, 0);
    CHECK(strstr(output, "\"final\":true") != NULL, "post-stop snapshot retains final counters");
    CHECK(strstr(output, "\"status\":\"ready\"") == NULL,
           "post-stop snapshot never claims live readiness");
    free(output);
    output = invoke(run_detach, 0);
    CHECK(!root_present && unlink_calls == PROGRAM_COUNT + MAP_COUNT,
           "mixed hooks cleanup removes exactly the known pins");
    CHECK(strstr(output, "\"status\":\"detached\"") != NULL,
           "successful cleanup records detachment");
    free(output);
  }

  reset_fixture();
  for (int index = 0; index < PROGRAM_COUNT; index++)
    test_links[index].cgroup.cgroup_id = 0;
  output = invoke(run_status, 1);
  free(output);
  output = invoke(run_snapshot, 0);
  free(output);
  output = invoke(run_detach, 0);
  CHECK(!root_present, "fully dead cgroup pins can be cleaned");
  free(output);

  for (int invalid = 0; invalid < 5; invalid++) {
    reset_fixture();
    if (invalid == 0)
      test_links[0].cgroup.cgroup_id = TEST_CGROUP_ID + 1;
    else if (invalid == 1)
      test_links[0].type = BPF_LINK_TYPE_RAW_TRACEPOINT;
    else if (invalid == 2)
      test_links[0].id = 0;
    else if (invalid == 3)
      test_links[0].prog_id = 0;
    else
      links_present[0] = false;
    CHECK(validate_pinned_contract(TEST_ROOT, TEST_CGROUP_ID, false) != 0,
           "invalid links fail live validation");
    CHECK(validate_pinned_contract(TEST_ROOT, TEST_CGROUP_ID, true) != 0,
           "invalid links fail post-stop validation");
    assert_rejected_without_cleanup();
  }
  for (int index = 0; index < MAP_COUNT; index++) {
    reset_fixture();
    test_links[0].cgroup.cgroup_id = 0;
    test_maps[index].value_size++;
    CHECK(validate_pinned_contract(TEST_ROOT, TEST_CGROUP_ID, true) != 0,
           "post-stop mode preserves every map ABI check");
    assert_rejected_without_cleanup();
  }
  reset_fixture();
  test_identity.object_digest[7] = 'a';
  assert_rejected_without_cleanup();
  reset_fixture();
  test_config.magic = 0;
  assert_rejected_without_cleanup();
  reset_fixture();
  test_identity.containment_count = 0;
  assert_rejected_without_cleanup();

  reset_fixture();
  unlink_failure = 0;
  output = invoke(run_detach, 1);
  CHECK(root_present, "failed pin removal leaves the root present");
  CHECK(strstr(output, "\"status\":\"detached\"") == NULL,
         "failed pin removal never emits a successful detachment receipt");
  free(output);
  printf("loader lifecycle regression: %u assertions passed; all BPF and pin operations mocked\n",
          assertions);
  return 0;
}
