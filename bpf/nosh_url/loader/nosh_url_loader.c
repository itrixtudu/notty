// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "nosh_url.h"
#include "nosh_url.skel.h"
#include "url_sanitizer.h"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#define NOSH_URL_LOADER_VERSION "1"
#define NOSH_URL_DEFAULT_SCAN_INTERVAL_MS 100
#define NOSH_URL_MIN_SCAN_INTERVAL_MS 50
#define NOSH_URL_MAX_SCAN_INTERVAL_MS 10000
#define NOSH_URL_DEFAULT_STATS_INTERVAL_MS 5000
#define NOSH_URL_MIN_STATS_INTERVAL_MS 100
#define NOSH_URL_MAX_STATS_INTERVAL_MS 3600000
#define NOSH_URL_FILE_HANDLE_BYTES 128
#define NOSH_URL_MAX_EXPLICIT_LIBRARIES 32
#define NOSH_URL_MAX_ATTACHMENTS 128
#define NOSH_URL_MAX_CGROUP_DEPTH 64
#define NOSH_URL_MAX_CGROUP_DIRECTORIES 4096
#define NOSH_URL_MAX_PIDS 8192
#define NOSH_URL_MAX_MAP_LINES 8192
#define NOSH_URL_MAX_MAP_LINE_BYTES 16384
#define NOSH_URL_MAX_LIBRARY_BYTES (512ULL * 1024ULL * 1024ULL)
#define NOSH_URL_RETRY_INTERVAL_MS 1000
#define NOSH_URL_EVIDENCE_LIMIT_BYTES (64ULL * 1024ULL * 1024ULL)
#define NOSH_URL_FINAL_RESERVE_BYTES (64ULL * 1024ULL)

static volatile sig_atomic_t stop_requested;

#ifdef NOSH_URL_TESTING
static bool test_allow_non_cgroup_filesystem;

void nosh_url_test_lifecycle_reset(const int *consume_results,
                                   size_t consume_count);
bool nosh_url_test_lifecycle_matches(const char *expected);
#endif

struct loader_options {
  const char *command;
  const char *cgroup_path;
  const char *libraries[NOSH_URL_MAX_EXPLICIT_LIBRARIES];
  size_t library_count;
  __u64 expected_cgroup_id;
  bool expected_cgroup_id_set;
  unsigned int scan_interval_ms;
  unsigned int stats_interval_ms;
  bool scan_interval_set;
  bool stats_interval_set;
  int status_fd;
  bool status_fd_set;
};

struct cgroup_target {
  int fd;
  __u64 id;
  char path[PATH_MAX];
};

struct attachment {
  dev_t device;
  ino_t inode;
  struct bpf_link *link;
  int64_t last_attempt_ms;
};

struct pid_list {
  pid_t *values;
  size_t count;
  size_t capacity;
};

struct loader_context {
  FILE *evidence;
  FILE *status;
  struct bpf_program *program;
  int stats_map_fd;
  int possible_cpus;
  __u64 *per_cpu_values;
  __u64 target_cgroup_id;
  int64_t realtime_minus_monotonic_ns;
  struct attachment attachments[NOSH_URL_MAX_ATTACHMENTS];
  size_t attachment_slots;
  __u64 discovery_scans;
  __u64 processes_inspected;
  __u64 library_mappings_seen;
  __u64 successful_attachments;
  __u64 discovery_misses;
  __u64 sanitizer_rejects;
  __u64 path_truncations;
  __u64 decoder_errors;
  __u64 emitted_observations;
  __u64 output_limit_reached;
  __u64 evidence_bytes;
  bool initial_scan_complete;
  bool output_failed;
};

static __u64 realtime_ns(void)
{
  struct timespec now;

  if (clock_gettime(CLOCK_REALTIME, &now) != 0)
    return 0;
  return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec;
}

static int64_t monotonic_ms(void)
{
  struct timespec now;

  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return -1;
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int sample_clock_offset(int64_t *offset_ns)
{
  struct timespec realtime;
  struct timespec monotonic;
  int64_t realtime_value;
  int64_t monotonic_value;

  if (clock_gettime(CLOCK_REALTIME, &realtime) != 0 ||
      clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0)
    return -1;
  realtime_value =
    (int64_t)realtime.tv_sec * 1000000000LL + realtime.tv_nsec;
  monotonic_value =
    (int64_t)monotonic.tv_sec * 1000000000LL + monotonic.tv_nsec;
  *offset_ns = realtime_value - monotonic_value;
  return 0;
}

static bool unix_timestamp(__u64 monotonic_ns,
                           int64_t offset_ns,
                           __u64 *unix_ns)
{
  if (offset_ns >= 0) {
    __u64 offset = (__u64)offset_ns;

    if (monotonic_ns > UINT64_MAX - offset)
      return false;
    *unix_ns = monotonic_ns + offset;
    return true;
  }
  if (offset_ns == INT64_MIN || monotonic_ns < (__u64)(-offset_ns))
    return false;
  *unix_ns = monotonic_ns - (__u64)(-offset_ns);
  return true;
}

static void write_json_string(FILE *stream, const char *value, size_t length)
{
  size_t index;

  fputc('"', stream);
  for (index = 0; index < length; index++) {
    unsigned char byte = (unsigned char)value[index];

    switch (byte) {
    case '"': fputs("\\\"", stream); break;
    case '\\': fputs("\\\\", stream); break;
    case '\b': fputs("\\b", stream); break;
    case '\f': fputs("\\f", stream); break;
    case '\n': fputs("\\n", stream); break;
    case '\r': fputs("\\r", stream); break;
    case '\t': fputs("\\t", stream); break;
    default:
      if (byte < 0x20 || byte >= 0x7f)
        fprintf(stream, "\\u%04x", byte);
      else
        fputc(byte, stream);
      break;
    }
  }
  fputc('"', stream);
}

static int evidence_write(struct loader_context *context,
                          const char *line,
                          size_t length,
                          bool final_record)
{
  __u64 limit = final_record ? NOSH_URL_EVIDENCE_LIMIT_BYTES :
    NOSH_URL_EVIDENCE_LIMIT_BYTES - NOSH_URL_FINAL_RESERVE_BYTES;

  if (context->evidence_bytes > limit ||
      length > limit - context->evidence_bytes) {
    context->output_limit_reached += 1;
    if (!final_record)
      stop_requested = 1;
    else
      context->output_failed = true;
    return -1;
  }
  if (fwrite(line, 1, length, context->evidence) != length ||
      fflush(context->evidence) != 0) {
    context->output_failed = true;
    stop_requested = 1;
    return -1;
  }
  context->evidence_bytes += length;
  return 0;
}

static int emit_status(FILE *stream,
                       const char *status,
                       const struct cgroup_target *target,
                       __u64 attached_objects,
                       const char *message)
{
  fprintf(stream,
          "{\"schemaVersion\":1,\"recordKind\":\"status\","
          "\"timestampUnixNs\":\"%" PRIu64 "\",\"status\":",
          (uint64_t)realtime_ns());
  write_json_string(stream, status, strlen(status));
  fputs(",\"cgroupPath\":", stream);
  if (target)
    write_json_string(stream, target->path, strlen(target->path));
  else
    fputs("null", stream);
  fputs(",\"cgroupId\":", stream);
  if (target)
    fprintf(stream, "\"%" PRIu64 "\"", (uint64_t)target->id);
  else
    fputs("null", stream);
  fprintf(stream,
          ",\"provider\":\"libcurl\",\"attachedObjects\":%" PRIu64
          ",\"observationOnly\":true,\"coverageComplete\":false,"
          "\"message\":",
          (uint64_t)attached_objects);
  if (message)
    write_json_string(stream, message, strlen(message));
  else
    fputs("null", stream);
  fputs("}\n", stream);
  return fflush(stream) == 0 ? 0 : -1;
}

static int parse_u64(const char *value, __u64 *result)
{
  char *end = NULL;
  unsigned long long parsed;

  if (!value || !*value || value[0] == '-' || value[0] == '+')
    return -1;
  errno = 0;
  parsed = strtoull(value, &end, 10);
  if (errno || !end || *end)
    return -1;
  *result = (__u64)parsed;
  return 0;
}

static int parse_uint(const char *value, unsigned int *result)
{
  __u64 parsed;

  if (parse_u64(value, &parsed) != 0 || parsed > UINT_MAX)
    return -1;
  *result = (unsigned int)parsed;
  return 0;
}

static int parse_fd(const char *value, int *result)
{
  __u64 parsed;

  if (parse_u64(value, &parsed) != 0 || parsed > INT_MAX || parsed < 2 ||
      fcntl((int)parsed, F_GETFD) < 0)
    return -1;
  *result = (int)parsed;
  return 0;
}

static bool duplicate_library(const struct loader_options *options,
                              const char *value)
{
  size_t index;

  for (index = 0; index < options->library_count; index++) {
    if (!strcmp(options->libraries[index], value))
      return true;
  }
  return false;
}

static int parse_options(int argc,
                         char **argv,
                         struct loader_options *options)
{
  int index;

  memset(options, 0, sizeof(*options));
  options->scan_interval_ms = NOSH_URL_DEFAULT_SCAN_INTERVAL_MS;
  options->stats_interval_ms = NOSH_URL_DEFAULT_STATS_INTERVAL_MS;
  options->status_fd = STDERR_FILENO;
  if (argc < 2)
    return -1;
  if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
    if (argc != 2)
      return -1;
    options->command = "help";
    return 0;
  }
  if (!strcmp(argv[1], "--version")) {
    if (argc != 2)
      return -1;
    options->command = "version";
    return 0;
  }
  if (strcmp(argv[1], "run") && strcmp(argv[1], "health"))
    return -1;
  options->command = argv[1];

  for (index = 2; index < argc; index++) {
    const char *argument = argv[index];

    if (!strcmp(argument, "--help") || !strcmp(argument, "-h")) {
      options->command = "help";
      return 0;
    }
    if (!strcmp(argument, "--cgroup")) {
      if (++index >= argc || options->cgroup_path)
        return -1;
      options->cgroup_path = argv[index];
      continue;
    }
    if (!strcmp(argument, "--cgroup-id")) {
      if (++index >= argc || options->expected_cgroup_id_set ||
          parse_u64(argv[index], &options->expected_cgroup_id) != 0 ||
          !options->expected_cgroup_id)
        return -1;
      options->expected_cgroup_id_set = true;
      continue;
    }
    if (!strcmp(argument, "--library")) {
      if (++index >= argc || argv[index][0] != '/' ||
          options->library_count >= NOSH_URL_MAX_EXPLICIT_LIBRARIES ||
          duplicate_library(options, argv[index]))
        return -1;
      options->libraries[options->library_count++] = argv[index];
      continue;
    }
    if (!strcmp(argument, "--scan-interval-ms")) {
      if (++index >= argc || options->scan_interval_set ||
          parse_uint(argv[index], &options->scan_interval_ms) != 0 ||
          options->scan_interval_ms < NOSH_URL_MIN_SCAN_INTERVAL_MS ||
          options->scan_interval_ms > NOSH_URL_MAX_SCAN_INTERVAL_MS)
        return -1;
      options->scan_interval_set = true;
      continue;
    }
    if (!strcmp(argument, "--stats-interval-ms")) {
      if (++index >= argc || options->stats_interval_set ||
          parse_uint(argv[index], &options->stats_interval_ms) != 0 ||
          options->stats_interval_ms < NOSH_URL_MIN_STATS_INTERVAL_MS ||
          options->stats_interval_ms > NOSH_URL_MAX_STATS_INTERVAL_MS)
        return -1;
      options->stats_interval_set = true;
      continue;
    }
    if (!strcmp(argument, "--status-fd")) {
      if (++index >= argc || options->status_fd_set ||
          parse_fd(argv[index], &options->status_fd) != 0)
        return -1;
      options->status_fd_set = true;
      continue;
    }
    return -1;
  }

  if (options->expected_cgroup_id_set && !options->cgroup_path)
    return -1;
  if (!strcmp(options->command, "run") && !options->cgroup_path)
    return -1;
  if (!strcmp(options->command, "health") &&
      (options->library_count || options->scan_interval_set ||
       options->stats_interval_set || options->status_fd_set))
    return -1;
  return 0;
}

static int cgroup_id_from_fd(int fd, __u64 *id)
{
  size_t allocation = sizeof(struct file_handle) +
    NOSH_URL_FILE_HANDLE_BYTES;
  struct file_handle *handle = calloc(1, allocation);
  int mount_id = 0;
  int result = -1;

  if (!handle)
    return -1;
  handle->handle_bytes = NOSH_URL_FILE_HANDLE_BYTES;
  if (name_to_handle_at(fd, ".", handle, &mount_id, 0) != 0 ||
      handle->handle_bytes < sizeof(*id))
    goto out;
  memcpy(id, handle->f_handle, sizeof(*id));
  if (!*id)
    goto out;
  result = 0;
out:
  free(handle);
  return result;
}

static bool same_directory(int left_fd, int right_fd)
{
  struct stat left = {};
  struct stat right = {};

  return fstat(left_fd, &left) == 0 && fstat(right_fd, &right) == 0 &&
    left.st_dev == right.st_dev && left.st_ino == right.st_ino;
}

static int describe_fd_path(int fd,
                            const char *fallback,
                            char *destination,
                            size_t size)
{
  char proc_path[64];
  ssize_t length;

  snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
  length = readlink(proc_path, destination, size - 1);
  if (length >= 0) {
    if ((size_t)length >= size - 1)
      return -1;
    destination[length] = '\0';
    return 0;
  }
  if (strlen(fallback) >= size)
    return -1;
  strcpy(destination, fallback);
  return 0;
}

static int resolve_cgroup_target(const struct loader_options *options,
                                 struct cgroup_target *target)
{
  struct statfs filesystem = {};
  int root_fd = -1;

  memset(target, 0, sizeof(*target));
  target->fd = -1;
  if (!options->cgroup_path || options->cgroup_path[0] != '/')
    return -1;
  target->fd = open(options->cgroup_path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (target->fd < 0)
    return -1;
  if (fstatfs(target->fd, &filesystem) != 0 ||
      (unsigned long)filesystem.f_type !=
        (unsigned long)CGROUP2_SUPER_MAGIC)
    goto fail;
  root_fd = open("/sys/fs/cgroup",
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root_fd >= 0 && same_directory(target->fd, root_fd))
    goto fail;
  if (cgroup_id_from_fd(target->fd, &target->id) != 0 ||
      (options->expected_cgroup_id_set &&
       target->id != options->expected_cgroup_id) ||
      describe_fd_path(target->fd, options->cgroup_path,
                       target->path, sizeof(target->path)) != 0)
    goto fail;
  if (root_fd >= 0)
    close(root_fd);
  return 0;
fail:
  if (root_fd >= 0)
    close(root_fd);
  close(target->fd);
  target->fd = -1;
  return -1;
}

static bool kernel_at_least_5_8(void)
{
  struct utsname system = {};
  unsigned int major_version = 0;
  unsigned int minor_version = 0;

  if (uname(&system) != 0 ||
      sscanf(system.release, "%u.%u", &major_version,
             &minor_version) != 2)
    return false;
  return major_version > 5 ||
    (major_version == 5 && minor_version >= 8);
}

static void handle_signal(int signal_number)
{
  (void)signal_number;
  stop_requested = 1;
}

static int install_signal_handlers(void)
{
  struct sigaction action = {};

  action.sa_handler = handle_signal;
  sigemptyset(&action.sa_mask);
  return sigaction(SIGINT, &action, NULL) ||
    sigaction(SIGTERM, &action, NULL) ? -1 : 0;
}

static void configure_memlock(void)
{
  struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };

  /* Linux 5.11+ may account BPF memory through memcg instead. */
  (void)setrlimit(RLIMIT_MEMLOCK, &limit);
}

static int add_pid(struct pid_list *list, pid_t pid)
{
  pid_t *replacement;
  size_t capacity;

  if (pid <= 0)
    return 0;
  if (list->count >= NOSH_URL_MAX_PIDS)
    return -1;
  if (list->count < list->capacity) {
    list->values[list->count++] = pid;
    return 0;
  }
  capacity = list->capacity ? list->capacity * 2 : 256;
  if (capacity > NOSH_URL_MAX_PIDS)
    capacity = NOSH_URL_MAX_PIDS;
  replacement = realloc(list->values, capacity * sizeof(*replacement));
  if (!replacement)
    return -1;
  list->values = replacement;
  list->capacity = capacity;
  list->values[list->count++] = pid;
  return 0;
}

static int read_cgroup_processes(int directory_fd,
                                 struct pid_list *list)
{
  FILE *stream;
  int file_fd;
  char *line = NULL;
  size_t capacity = 0;
  int result = 0;

  file_fd = openat(directory_fd, "cgroup.procs", O_RDONLY | O_CLOEXEC);
  if (file_fd < 0)
    return -1;
  stream = fdopen(file_fd, "r");
  if (!stream) {
    close(file_fd);
    return -1;
  }
  while (getline(&line, &capacity, stream) >= 0) {
    char *end = NULL;
    long parsed;

    if (stop_requested)
      break;
    errno = 0;
    parsed = strtol(line, &end, 10);
    while (end && (*end == '\n' || *end == '\r'))
      end++;
    if (errno || !end || *end || parsed <= 0 || parsed > INT_MAX ||
        add_pid(list, (pid_t)parsed) != 0) {
      result = -1;
      break;
    }
  }
  free(line);
  if (ferror(stream))
    result = -1;
  fclose(stream);
  return result;
}

static DIR *open_independent_directory_stream(int directory_fd)
{
  DIR *directory;
  int stream_fd;

  /*
   * dup() would share the persistent cgroup FD's open-file-description
   * offset. A completed readdir() would then leave subsequent discovery
   * scans at end-of-directory and could hide newly created descendants.
   */
  stream_fd = openat(directory_fd, ".",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (stream_fd < 0)
    return NULL;
  directory = fdopendir(stream_fd);
  if (!directory)
    close(stream_fd);
  return directory;
}

static bool scan_child_filesystem_allowed(int child_fd)
{
  struct statfs filesystem = {};

#ifdef NOSH_URL_TESTING
  if (test_allow_non_cgroup_filesystem)
    return true;
#endif
  return fstatfs(child_fd, &filesystem) == 0 &&
    (unsigned long)filesystem.f_type ==
      (unsigned long)CGROUP2_SUPER_MAGIC;
}

static int scan_cgroup_directory(struct loader_context *context,
                                 int directory_fd,
                                 unsigned int depth,
                                 unsigned int *directories,
                                 struct pid_list *pids)
{
  DIR *directory;
  struct dirent *entry;
  int result = 0;

  if (stop_requested)
    return 0;
  if (depth > NOSH_URL_MAX_CGROUP_DEPTH ||
      ++*directories > NOSH_URL_MAX_CGROUP_DIRECTORIES) {
    context->discovery_misses += 1;
    return -1;
  }
  if (read_cgroup_processes(directory_fd, pids) != 0) {
    context->discovery_misses += 1;
    result = -1;
  }
  directory = open_independent_directory_stream(directory_fd);
  if (!directory) {
    context->discovery_misses += 1;
    return -1;
  }
  for (;;) {
    int child_fd;

    errno = 0;
    entry = readdir(directory);
    if (!entry) {
      if (errno) {
        context->discovery_misses += 1;
        result = -1;
      }
      break;
    }
    if (stop_requested)
      break;
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
        (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN))
      continue;
    child_fd = openat(directory_fd, entry->d_name,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (child_fd < 0) {
      if (errno != ENOENT && errno != ENOTDIR) {
        context->discovery_misses += 1;
        result = -1;
      }
      continue;
    }
    if (!scan_child_filesystem_allowed(child_fd)) {
      context->discovery_misses += 1;
      result = -1;
    } else if (scan_cgroup_directory(context, child_fd, depth + 1,
                                     directories, pids) != 0) {
      result = -1;
    }
    close(child_fd);
  }
  closedir(directory);
  return result;
}

static bool libcurl_basename(const char *path)
{
  const char *basename = strrchr(path, '/');

  basename = basename ? basename + 1 : path;
  return !strncmp(basename, "libcurl", 7) && strstr(basename + 7, ".so");
}

static ssize_t find_attachment(const struct loader_context *context,
                               dev_t device,
                               ino_t inode)
{
  size_t index;

  for (index = 0; index < context->attachment_slots; index++) {
    if (context->attachments[index].device == device &&
        context->attachments[index].inode == inode)
      return (ssize_t)index;
  }
  return -1;
}

static int attach_library_fd(struct loader_context *context,
                             int file_fd,
                             const struct stat *metadata,
                             bool late_discovery,
                             bool required)
{
  struct bpf_uprobe_opts options = {};
  struct attachment *attachment;
  struct bpf_link *link;
  char fd_path[64];
  int64_t now = monotonic_ms();
  ssize_t existing = find_attachment(context, metadata->st_dev,
                                     metadata->st_ino);

  if (existing >= 0) {
    attachment = &context->attachments[existing];
    if (attachment->link)
      return 0;
    if (!required && now >= 0 && attachment->last_attempt_ms >= 0 &&
        now - attachment->last_attempt_ms < NOSH_URL_RETRY_INTERVAL_MS)
      return 0;
  } else {
    if (context->attachment_slots >= NOSH_URL_MAX_ATTACHMENTS) {
      context->discovery_misses += 1;
      return required ? -1 : 0;
    }
    attachment = &context->attachments[context->attachment_slots++];
    memset(attachment, 0, sizeof(*attachment));
    attachment->device = metadata->st_dev;
    attachment->inode = metadata->st_ino;
    attachment->last_attempt_ms = -1;
    if (late_discovery)
      context->discovery_misses += 1;
  }

  attachment->last_attempt_ms = now;
  snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", file_fd);
  options.sz = sizeof(options);
  options.retprobe = false;
  options.func_name = "curl_easy_setopt";
  link = bpf_program__attach_uprobe_opts(context->program, -1, fd_path, 0,
                                         &options);
  if (libbpf_get_error(link)) {
    attachment->link = NULL;
    context->discovery_misses += 1;
    return required ? -1 : 0;
  }
  attachment->link = link;
  context->successful_attachments += 1;
  return 0;
}

static int verified_library_fd(const char *path,
                               unsigned int expected_major,
                               unsigned int expected_minor,
                               unsigned long long expected_inode,
                               struct stat *metadata)
{
  int fd = open(path, O_RDONLY | O_CLOEXEC);

  if (fd < 0)
    return -1;
  if (fstat(fd, metadata) != 0 || !S_ISREG(metadata->st_mode) ||
      metadata->st_size <= 0 ||
      (__u64)metadata->st_size > NOSH_URL_MAX_LIBRARY_BYTES ||
      (expected_inode &&
       ((unsigned long long)metadata->st_ino != expected_inode ||
        major(metadata->st_dev) != expected_major ||
        minor(metadata->st_dev) != expected_minor))) {
    close(fd);
    return -1;
  }
  return fd;
}

static int inspect_process_maps(struct loader_context *context, pid_t pid)
{
  char proc_directory[64];
  FILE *stream = NULL;
  char *line = NULL;
  size_t capacity = 0;
  size_t lines = 0;
  int proc_fd = -1;
  int maps_fd = -1;
  int result = 0;

  snprintf(proc_directory, sizeof(proc_directory), "/proc/%ld", (long)pid);
  proc_fd = open(proc_directory,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (proc_fd < 0) {
    context->discovery_misses += 1;
    return -1;
  }
  maps_fd = openat(proc_fd, "maps", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (maps_fd < 0) {
    context->discovery_misses += 1;
    close(proc_fd);
    return -1;
  }
  stream = fdopen(maps_fd, "r");
  if (!stream) {
    context->discovery_misses += 1;
    close(maps_fd);
    close(proc_fd);
    return -1;
  }
  context->processes_inspected += 1;

  while (getline(&line, &capacity, stream) >= 0) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    unsigned long long offset = 0;
    unsigned long long inode = 0;
    unsigned int device_major = 0;
    unsigned int device_minor = 0;
    char permissions[5] = {};
    char object_path[PATH_MAX + 64];
    char *path;
    char *newline;
    struct stat metadata = {};
    int consumed = 0;
    int library_fd;

    if (stop_requested)
      break;
    if (++lines > NOSH_URL_MAX_MAP_LINES ||
        strlen(line) > NOSH_URL_MAX_MAP_LINE_BYTES) {
      context->discovery_misses += 1;
      result = -1;
      break;
    }
    if (sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %n",
               &start, &end, permissions, &offset,
               &device_major, &device_minor, &inode, &consumed) != 7 ||
        !strchr(permissions, 'x') || !inode || consumed <= 0)
      continue;
    path = line + consumed;
    while (*path == ' ' || *path == '\t')
      path++;
    newline = strpbrk(path, "\r\n");
    if (newline)
      *newline = '\0';
    if (path[0] != '/' || !libcurl_basename(path))
      continue;
    context->library_mappings_seen += 1;
    if (strstr(path, " (deleted)")) {
      context->discovery_misses += 1;
      continue;
    }
    if (snprintf(object_path, sizeof(object_path),
                 "/proc/%ld/root%s", (long)pid, path) >=
        (int)sizeof(object_path)) {
      context->discovery_misses += 1;
      continue;
    }
    library_fd = verified_library_fd(object_path, device_major, device_minor,
                                     inode, &metadata);
    if (library_fd < 0) {
      context->discovery_misses += 1;
      continue;
    }
    if (attach_library_fd(context, library_fd, &metadata,
                          context->initial_scan_complete, false) != 0)
      result = -1;
    close(library_fd);
  }
  if (ferror(stream)) {
    context->discovery_misses += 1;
    result = -1;
  }
  free(line);
  fclose(stream);
  close(proc_fd);
  return result;
}

static int discover_libraries(struct loader_context *context,
                              const struct cgroup_target *target)
{
  struct pid_list pids = {};
  unsigned int directories = 0;
  size_t index;
  int result = 0;

  context->discovery_scans += 1;
  if (scan_cgroup_directory(context, target->fd, 0, &directories, &pids) != 0)
    result = -1;
  for (index = 0; index < pids.count; index++) {
    if (stop_requested)
      break;
    if (inspect_process_maps(context, pids.values[index]) != 0)
      result = -1;
  }
  free(pids.values);
  return result;
}

static int attach_explicit_libraries(struct loader_context *context,
                                     const struct loader_options *options)
{
  size_t index;

  for (index = 0; index < options->library_count; index++) {
    struct stat metadata = {};
    int file_fd;

    if (!libcurl_basename(options->libraries[index]))
      return -1;
    file_fd = verified_library_fd(options->libraries[index], 0, 0, 0,
                                  &metadata);
    if (file_fd < 0)
      return -1;
    if (attach_library_fd(context, file_fd, &metadata, false, true) != 0) {
      close(file_fd);
      return -1;
    }
    close(file_fd);
  }
  return 0;
}

static int read_bpf_stats(struct loader_context *context,
                          __u64 counters[NOSH_URL_STAT_MAX])
{
  __u32 key;

  memset(counters, 0, NOSH_URL_STAT_MAX * sizeof(*counters));
  for (key = 0; key < NOSH_URL_STAT_MAX; key++) {
    int cpu;

    memset(context->per_cpu_values, 0,
           (size_t)context->possible_cpus * sizeof(__u64));
    if (bpf_map_lookup_elem(context->stats_map_fd, &key,
                            context->per_cpu_values) != 0)
      return -1;
    for (cpu = 0; cpu < context->possible_cpus; cpu++) {
      if (UINT64_MAX - counters[key] < context->per_cpu_values[cpu])
        return -1;
      counters[key] += context->per_cpu_values[cpu];
    }
  }
  return 0;
}

static int emit_stats(struct loader_context *context, bool final)
{
  __u64 counters[NOSH_URL_STAT_MAX];
  char *line = NULL;
  size_t length = 0;
  FILE *stream;
  int result;

  if (read_bpf_stats(context, counters) != 0)
    return -1;
  stream = open_memstream(&line, &length);
  if (!stream)
    return -1;
  fprintf(stream,
          "{\"schemaVersion\":1,\"recordKind\":\"stats\","
          "\"timestampUnixNs\":\"%" PRIu64 "\",\"cgroupId\":"
          "\"%" PRIu64 "\",\"provider\":\"libcurl\","
          "\"providersAttached\":",
          (uint64_t)realtime_ns(), (uint64_t)context->target_cgroup_id);
  fputs(context->successful_attachments ? "[\"libcurl\"]" : "[]", stream);
  fprintf(stream,
          ",\"final\":%s,\"observationOnly\":true,"
          "\"coverageComplete\":false,"
          "\"coverageLimitation\":"
          "\"Dynamic uprobes cannot cover calls before attachment or clients "
          "that do not use an attached libcurl object.\",\"counters\":{"
          "\"ringbufDrops\":\"%" PRIu64 "\","
          "\"configMissing\":\"%" PRIu64 "\","
          "\"cgroupFilterErrors\":\"%" PRIu64 "\","
          "\"readErrors\":\"%" PRIu64 "\","
          "\"optionCalls\":\"%" PRIu64 "\","
          "\"rawObservations\":\"%" PRIu64 "\","
          "\"discoveryScans\":\"%" PRIu64 "\","
          "\"processesInspected\":\"%" PRIu64 "\","
          "\"libraryMappingsSeen\":\"%" PRIu64 "\","
          "\"attachments\":\"%" PRIu64 "\","
          "\"discoveryMisses\":\"%" PRIu64 "\","
          "\"sanitizerRejects\":\"%" PRIu64 "\","
          "\"pathTruncations\":\"%" PRIu64 "\","
          "\"decoderErrors\":\"%" PRIu64 "\","
          "\"observations\":\"%" PRIu64 "\","
          "\"outputLimitReached\":\"%" PRIu64 "\"}}\n",
          final ? "true" : "false",
          (uint64_t)counters[NOSH_URL_STAT_RINGBUF_DROPS],
          (uint64_t)counters[NOSH_URL_STAT_CONFIG_MISSING],
          (uint64_t)counters[NOSH_URL_STAT_CGROUP_FILTER_ERRORS],
          (uint64_t)counters[NOSH_URL_STAT_READ_ERRORS],
          (uint64_t)counters[NOSH_URL_STAT_OPTION_CALLS],
          (uint64_t)counters[NOSH_URL_STAT_OBSERVATIONS],
          (uint64_t)context->discovery_scans,
          (uint64_t)context->processes_inspected,
          (uint64_t)context->library_mappings_seen,
          (uint64_t)context->successful_attachments,
          (uint64_t)context->discovery_misses,
          (uint64_t)context->sanitizer_rejects,
          (uint64_t)context->path_truncations,
          (uint64_t)context->decoder_errors,
          (uint64_t)context->emitted_observations,
          (uint64_t)context->output_limit_reached);
  if (fclose(stream) != 0) {
    free(line);
    return -1;
  }
  result = evidence_write(context, line, length, final);
  free(line);
  return result;
}

static int emit_observation(struct loader_context *context,
                            const struct nosh_url_event *event,
                            const struct nosh_url_sanitized *url,
                            __u64 timestamp_unix_ns,
                            size_t process_length)
{
  char *line = NULL;
  size_t length = 0;
  FILE *stream = open_memstream(&line, &length);
  int result;

  if (!stream)
    return -1;
  fprintf(stream,
          "{\"schemaVersion\":1,\"recordKind\":\"url-observation\","
          "\"timestampUnixNs\":\"%" PRIu64 "\","
          "\"timestampMonotonicNs\":\"%" PRIu64 "\","
          "\"targetCgroupId\":\"%" PRIu64 "\","
          "\"cgroupId\":\"%" PRIu64 "\",\"pid\":%u,\"tid\":%u,"
          "\"process\":",
          (uint64_t)timestamp_unix_ns, (uint64_t)event->timestamp_ns,
          (uint64_t)event->target_cgroup_id,
          (uint64_t)event->observed_cgroup_id, event->pid, event->tid);
  write_json_string(stream, event->comm, process_length);
  fputs(",\"provider\":\"libcurl\","
        "\"source\":\"libcurl:CURLOPT_URL\",\"scheme\":", stream);
  write_json_string(stream, url->scheme, strlen(url->scheme));
  fputs(",\"host\":", stream);
  write_json_string(stream, url->host, strlen(url->host));
  fprintf(stream, ",\"port\":%u,\"path\":", url->port);
  write_json_string(stream, url->path, strlen(url->path));
  fprintf(stream, ",\"pathTruncated\":%s,\"observationOnly\":true}\n",
          url->path_truncated ? "true" : "false");
  if (fclose(stream) != 0) {
    free(line);
    return -1;
  }
  result = evidence_write(context, line, length, false);
  free(line);
  return result;
}

static int event_callback(void *opaque, void *data, size_t size)
{
  struct loader_context *context = opaque;
  const struct nosh_url_event *event = data;
  struct nosh_url_sanitized url;
  enum nosh_url_sanitize_result sanitize_result;
  const char *process_end;
  __u64 timestamp_unix_ns;

  if (size != sizeof(*event) ||
      event->schema_version != NOSH_URL_SCHEMA_VERSION ||
      event->event_size != sizeof(*event) ||
      event->event_kind != NOSH_URL_EVENT_URL ||
      event->provider != NOSH_URL_PROVIDER_LIBCURL ||
      event->target_cgroup_id != context->target_cgroup_id ||
      !event->observed_cgroup_id || !event->pid ||
      event->raw_length <= 1 || event->raw_length >= NOSH_URL_RAW_MAX ||
      event->raw_url[event->raw_length - 1] != '\0' ||
      memchr(event->raw_url, '\0', event->raw_length - 1) ||
      !unix_timestamp(event->timestamp_ns,
                      context->realtime_minus_monotonic_ns,
                      &timestamp_unix_ns)) {
    context->decoder_errors += 1;
    return 0;
  }
  process_end = memchr(event->comm, '\0', sizeof(event->comm));
  if (!process_end || process_end == event->comm) {
    context->decoder_errors += 1;
    return 0;
  }
  sanitize_result = nosh_url_sanitize(event->raw_url,
                                      event->raw_length - 1, &url);
  if (sanitize_result != NOSH_URL_SANITIZE_OK) {
    context->sanitizer_rejects += 1;
    return 0;
  }
  if (url.path_truncated)
    context->path_truncations += 1;
  if (emit_observation(context, event, &url, timestamp_unix_ns,
                       (size_t)(process_end - event->comm)) != 0)
    return 0;
  context->emitted_observations += 1;
  return 0;
}

static int destroy_attachments(struct loader_context *context)
{
  size_t index;
  int result = 0;

  for (index = 0; index < context->attachment_slots; index++) {
    if (context->attachments[index].link &&
        bpf_link__destroy(context->attachments[index].link) != 0)
      result = -1;
    context->attachments[index].link = NULL;
  }
  return result;
}

static int finalize_collection(struct loader_context *context,
                               struct ring_buffer *ring)
{
  int consume_result;

  /* Freeze the producer set before deciding that the ring is empty. */
  if (destroy_attachments(context) != 0)
    return -1;
  for (;;) {
    consume_result = ring_buffer__consume(ring);
    if (consume_result < 0)
      return -1;
    if (consume_result == 0)
      break;
  }
  return emit_stats(context, true);
}

static void print_usage(FILE *stream)
{
  fputs("usage:\n"
        "  nosh-url-loader run --cgroup ABSOLUTE_PATH "
        "[--cgroup-id ID] [--library ABSOLUTE_ELF]... "
        "[--scan-interval-ms N] [--stats-interval-ms N] "
        "[--status-fd FD]\n"
        "  nosh-url-loader health [--cgroup ABSOLUTE_PATH] "
        "[--cgroup-id ID]\n"
        "  nosh-url-loader --version\n", stream);
}

static int run_health(const struct loader_options *options)
{
  struct cgroup_target target = { .fd = -1 };
  const struct cgroup_target *target_pointer = NULL;
  int result = 1;

  if (!kernel_at_least_5_8() || access("/sys/kernel/btf/vmlinux", R_OK) != 0)
    goto out;
  if (options->cgroup_path) {
    if (resolve_cgroup_target(options, &target) != 0)
      goto out;
    target_pointer = &target;
  }
  if (emit_status(stdout, "healthy", target_pointer, 0,
                  "Kernel prerequisites are available; libcurl objects are "
                  "verified and attached only during run.") != 0)
    goto out;
  result = 0;
out:
  if (target.fd >= 0)
    close(target.fd);
  return result;
}

static int run_collector(const struct loader_options *options)
{
  struct cgroup_target target = { .fd = -1 };
  struct nosh_url_bpf *skeleton = NULL;
  struct ring_buffer *ring = NULL;
  struct nosh_url_config config = {};
  struct loader_context context = {};
  FILE *status = NULL;
  __u32 key = 0;
  __u32 cgroup_fd_value;
  int64_t next_scan;
  int64_t next_stats;
  int result = 1;

  status = fdopen(dup(options->status_fd), "a");
  if (!status)
    return 1;
  context.evidence = stdout;
  context.status = status;
  if (resolve_cgroup_target(options, &target) != 0 ||
      !kernel_at_least_5_8() || access("/sys/kernel/btf/vmlinux", R_OK) != 0 ||
      install_signal_handlers() != 0 ||
      sample_clock_offset(&context.realtime_minus_monotonic_ns) != 0)
    goto fail;
  configure_memlock();

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  skeleton = nosh_url_bpf__open();
  if (!skeleton)
    goto fail;
  context.program = skeleton->progs.nosh_url_curl_easy_setopt;
  if (nosh_url_bpf__load(skeleton) != 0)
    goto fail;

  config.target_cgroup_id = target.id;
  cgroup_fd_value = (__u32)target.fd;
  if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.session_config),
                          &key, &config, BPF_ANY) != 0 ||
      bpf_map_update_elem(bpf_map__fd(skeleton->maps.target_cgroup),
                          &key, &cgroup_fd_value, BPF_ANY) != 0)
    goto fail;
  context.target_cgroup_id = target.id;
  context.stats_map_fd = bpf_map__fd(skeleton->maps.stats);
  context.possible_cpus = libbpf_num_possible_cpus();
  if (context.possible_cpus <= 0)
    goto fail;
  context.per_cpu_values = calloc((size_t)context.possible_cpus,
                                  sizeof(*context.per_cpu_values));
  if (!context.per_cpu_values)
    goto fail;
  ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
                          event_callback, &context, NULL);
  if (!ring)
    goto fail;
  if (attach_explicit_libraries(&context, options) != 0)
    goto fail;
  (void)discover_libraries(&context, &target);
  context.initial_scan_complete = true;
  if (emit_status(status, "ready", &target,
                  context.successful_attachments,
                  "Observational libcurl discovery is active; coverage is "
                  "explicitly incomplete.") != 0)
    goto fail;

  next_scan = monotonic_ms();
  next_stats = next_scan;
  if (next_scan < 0)
    goto fail;
  next_scan += options->scan_interval_ms;
  next_stats += options->stats_interval_ms;
  while (!stop_requested) {
    int poll_result = ring_buffer__poll(ring,
      (int)options->scan_interval_ms);
    int64_t now = monotonic_ms();

    if (poll_result < 0 && poll_result != -EINTR)
      goto fail;
    if (now < 0)
      goto fail;
    if (now >= next_scan) {
      (void)discover_libraries(&context, &target);
      next_scan = now + options->scan_interval_ms;
    }
    if (now >= next_stats) {
      if (emit_stats(&context, false) != 0) {
        if (context.output_limit_reached && !context.output_failed) {
          stop_requested = 1;
          continue;
        }
        goto fail;
      }
      next_stats = now + options->stats_interval_ms;
    }
  }

  if (emit_status(status, "stopping", &target,
                  context.successful_attachments,
                  "Signal received; detaching uprobes before draining "
                  "observations.") != 0)
    goto fail;
  if (finalize_collection(&context, ring) != 0)
    goto fail;
  if (emit_status(status, "complete", &target,
                  context.successful_attachments,
                  "Uprobes detached; buffered observations drained; final "
                  "statistics emitted.") != 0)
    goto fail;
  result = context.output_failed ? 1 : 0;
  goto out;

fail:
  emit_status(status, "error", target.fd >= 0 ? &target : NULL,
              context.successful_attachments,
              "Collector setup or runtime failed; no clean final evidence "
              "record was emitted.");
out:
  (void)destroy_attachments(&context);
  ring_buffer__free(ring);
  free(context.per_cpu_values);
  nosh_url_bpf__destroy(skeleton);
  if (target.fd >= 0)
    close(target.fd);
  fclose(status);
  return result;
}

#ifdef NOSH_URL_TESTING
static int create_test_process_file(int directory_fd, pid_t pid)
{
  int file_fd = openat(directory_fd, "cgroup.procs",
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  int result = 0;

  if (file_fd < 0)
    return -1;
  if (pid > 0 && dprintf(file_fd, "%ld\n", (long)pid) < 0)
    result = -1;
  if (close(file_fd) != 0)
    result = -1;
  return result;
}

static int run_directory_rescan_test(void)
{
  char temporary_path[] = "/tmp/nosh-url-rescan-XXXXXX";
  struct loader_context context = {};
  struct pid_list first_pids = {};
  struct pid_list second_pids = {};
  unsigned int directories = 0;
  int root_fd = -1;
  int child_fd = -1;
  int result = 1;
  size_t index;
  bool found = false;
  pid_t expected_pid = getpid();

  if (!mkdtemp(temporary_path))
    return 1;
  root_fd = open(temporary_path,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root_fd < 0 || create_test_process_file(root_fd, 0) != 0)
    goto out;

  test_allow_non_cgroup_filesystem = true;
  stop_requested = 0;
  if (scan_cgroup_directory(&context, root_fd, 0, &directories,
                            &first_pids) != 0 ||
      first_pids.count != 0 ||
      lseek(root_fd, 0, SEEK_CUR) != 0)
    goto out;

  if (mkdirat(root_fd, "late-descendant", 0700) != 0)
    goto out;
  child_fd = openat(root_fd, "late-descendant",
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (child_fd < 0 ||
      create_test_process_file(child_fd, expected_pid) != 0)
    goto out;

  directories = 0;
  if (scan_cgroup_directory(&context, root_fd, 0, &directories,
                            &second_pids) != 0 ||
      directories != 2 ||
      lseek(root_fd, 0, SEEK_CUR) != 0 ||
      context.discovery_misses != 0)
    goto out;
  for (index = 0; index < second_pids.count; index++) {
    if (second_pids.values[index] == expected_pid) {
      found = true;
      break;
    }
  }
  if (!found)
    goto out;
  result = 0;
out:
  test_allow_non_cgroup_filesystem = false;
  free(first_pids.values);
  free(second_pids.values);
  if (child_fd >= 0) {
    (void)unlinkat(child_fd, "cgroup.procs", 0);
    close(child_fd);
  }
  if (root_fd >= 0) {
    (void)unlinkat(root_fd, "late-descendant", AT_REMOVEDIR);
    (void)unlinkat(root_fd, "cgroup.procs", 0);
    close(root_fd);
  }
  (void)rmdir(temporary_path);
  if (!result)
    puts("nosh-url directory rescan test: ok");
  return result;
}

static int run_shutdown_drain_test(void)
{
  static const int successful_consume[] = { 2, 1, 0 };
  static const int failed_consume[] = { -EIO };
  struct loader_context context = {};
  __u64 per_cpu_value = 0;
  char *evidence = NULL;
  size_t evidence_length = 0;
  FILE *stream = NULL;
  int result = 1;

  stream = open_memstream(&evidence, &evidence_length);
  if (!stream)
    goto out;
  context.evidence = stream;
  context.stats_map_fd = 1;
  context.possible_cpus = 1;
  context.per_cpu_values = &per_cpu_value;
  context.target_cgroup_id = 42;
  context.attachment_slots = 2;
  context.attachments[0].link = (struct bpf_link *)(uintptr_t)1;
  context.attachments[1].link = (struct bpf_link *)(uintptr_t)2;
  nosh_url_test_lifecycle_reset(
    successful_consume,
    sizeof(successful_consume) / sizeof(successful_consume[0]));
  if (finalize_collection(&context, (struct ring_buffer *)(uintptr_t)1) != 0 ||
      context.attachments[0].link || context.attachments[1].link ||
      !nosh_url_test_lifecycle_matches("DDCCC") ||
      !evidence || !strstr(evidence, "\"final\":true"))
    goto out;
  {
    int close_result = fclose(stream);

    stream = NULL;
    if (close_result != 0)
      goto out;
  }
  free(evidence);
  evidence = NULL;
  evidence_length = 0;

  memset(&context, 0, sizeof(context));
  per_cpu_value = 0;
  stream = open_memstream(&evidence, &evidence_length);
  if (!stream)
    goto out;
  context.evidence = stream;
  context.stats_map_fd = 1;
  context.possible_cpus = 1;
  context.per_cpu_values = &per_cpu_value;
  context.target_cgroup_id = 42;
  context.attachment_slots = 1;
  context.attachments[0].link = (struct bpf_link *)(uintptr_t)1;
  nosh_url_test_lifecycle_reset(
    failed_consume,
    sizeof(failed_consume) / sizeof(failed_consume[0]));
  if (finalize_collection(&context, (struct ring_buffer *)(uintptr_t)1) == 0 ||
      context.attachments[0].link ||
      !nosh_url_test_lifecycle_matches("DC") || context.evidence_bytes != 0)
    goto out;
  result = 0;
out:
  if (stream)
    (void)fclose(stream);
  free(evidence);
  if (!result)
    puts("nosh-url shutdown drain test: ok");
  return result;
}
#endif

int main(int argc, char **argv)
{
  struct loader_options options;

#ifdef NOSH_URL_TESTING
  if (argc == 2 && !strcmp(argv[1], "--test-directory-rescan"))
    return run_directory_rescan_test();
  if (argc == 2 && !strcmp(argv[1], "--test-shutdown-drain"))
    return run_shutdown_drain_test();
#endif
  if (parse_options(argc, argv, &options) != 0) {
    print_usage(stderr);
    return 2;
  }
  if (!strcmp(options.command, "help")) {
    print_usage(stdout);
    return 0;
  }
  if (!strcmp(options.command, "version")) {
    puts(NOSH_URL_LOADER_VERSION);
    return 0;
  }
  if (!strcmp(options.command, "health"))
    return run_health(&options);
  return run_collector(&options);
}
