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
#include <linux/types.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "nosh_build.h"
#include "nosh_build.skel.h"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#define NOSH_BUILD_LOADER_VERSION "5"
#define NOSH_BUILD_DEFAULT_STATS_INTERVAL_MS 5000
#define NOSH_BUILD_MIN_STATS_INTERVAL_MS 100
#define NOSH_BUILD_MAX_STATS_INTERVAL_MS 3600000
#define NOSH_BUILD_PROGRAM_COUNT 7
#define NOSH_BUILD_FILE_HANDLE_BYTES 128
#define NOSH_BUILD_EVIDENCE_FILE_LIMIT_BYTES (128ULL * 1024ULL * 1024ULL)
/* The retained head, marker, and tail fit the adapter's 2048-char summary. */
#define NOSH_BUILD_LIBBPF_LOG_HEAD_BYTES 512
#define NOSH_BUILD_LIBBPF_LOG_TAIL_BYTES 1408
#define NOSH_BUILD_LIBBPF_LOG_MARKER_BYTES 128
#define NOSH_BUILD_DNS_HEADER_LEN 12
#define NOSH_BUILD_DNS_RR_TAIL_LEN 10
#define NOSH_BUILD_DNS_POINTER_MASK 0xc0
#define NOSH_BUILD_DNS_POINTER_OFFSET_MASK 0x3fff
#define NOSH_BUILD_DNS_MAX_POINTERS 8
#define NOSH_BUILD_DNS_RESPONSE 0x8000
#define NOSH_BUILD_DNS_TRUNCATED 0x0200
#define NOSH_BUILD_DNS_RCODE_MASK 0x000f

_Static_assert(sizeof(struct nosh_build_syscall_totals) % 8 == 0,
               "per-CPU syscall values require an eight-byte stride");
_Static_assert(sizeof(struct nosh_build_dns_wire_event) <= UINT16_MAX,
               "DNS wire events must fit the raw event-size field");

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t evidence_file_limit_reached;
static FILE *libbpf_status_stream;

struct loader_options {
  const char *command;
  const char *cgroup_path;
  const char *depth;
  __u64 expected_cgroup_id;
  bool expected_cgroup_id_set;
  unsigned int stats_interval_ms;
  bool stats_interval_set;
  int status_fd;
  bool status_fd_set;
};

struct cgroup_target {
  int fd;
  __u64 id;
  char path[PATH_MAX];
};

struct loader_context {
  FILE *event_stream;
  int stats_map_fd;
  int syscall_map_fd;
  int inflight_map_fd;
  int file_map_fd;
  int possible_cpus;
  __u64 *per_cpu_values;
  struct nosh_build_syscall_totals *per_cpu_syscall_values;
  __u64 target_cgroup_id;
  int64_t realtime_minus_monotonic_ns;
  __u64 events_seen;
  __u64 decoder_errors;
  __u64 dns_parse_errors;
  __u64 dns_compressed_names;
  __u64 dns_truncated_names;
  __u64 dns_truncated_responses;
  __u64 dns_answer_limit_reached;
  __u64 dns_unsupported_answers;
  __u64 dns_name_pointers;
  __u64 file_summaries_emitted;
  bool policy_depth;
  bool process_depth;
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

static void write_json_string(FILE *stream, const char *value, size_t length)
{
  size_t index;

  fputc('"', stream);
  for (index = 0; index < length; index++) {
    unsigned char byte = (unsigned char)value[index];

    switch (byte) {
      case '"':
        fputs("\\\"", stream);
        break;
      case '\\':
        fputs("\\\\", stream);
        break;
      case '\b':
        fputs("\\b", stream);
        break;
      case '\f':
        fputs("\\f", stream);
        break;
      case '\n':
        fputs("\\n", stream);
        break;
      case '\r':
        fputs("\\r", stream);
        break;
      case '\t':
        fputs("\\t", stream);
        break;
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

static void write_nullable_json_string(FILE *stream, const char *value)
{
  if (!value) {
    fputs("null", stream);
    return;
  }
  write_json_string(stream, value, strlen(value));
}

static int emit_status(FILE *stream,
                       const char *status,
                       const struct cgroup_target *target,
                       int attached_programs,
                       const char *depth,
                       const char *message)
{
  fprintf(stream,
          "{\"schemaVersion\":2,\"recordKind\":\"status\","
          "\"timestampUnixNs\":\"%" PRIu64 "\",\"status\":",
          (uint64_t)realtime_ns());
  write_json_string(stream, status, strlen(status));
  fprintf(stream, ",\"pid\":%ld,\"cgroupPath\":", (long)getpid());
  write_nullable_json_string(stream, target ? target->path : NULL);
  fputs(",\"cgroupId\":", stream);
  if (target)
    fprintf(stream, "\"%" PRIu64 "\"", (uint64_t)target->id);
  else
    fputs("null", stream);
  fprintf(stream,
          ",\"attachedPrograms\":%d,\"collectionDepth\":",
          attached_programs);
  write_json_string(stream, depth, strlen(depth));
  fprintf(stream,
          ",\"policyCollectionEnabled\":%s,"
          "\"deepCollectionSupported\":false,\"message\":",
          !strcmp(depth, "policy") ? "true" : "false");
  write_nullable_json_string(stream, message);
  fputs("}\n", stream);
  return fflush(stream) == 0 ? 0 : -1;
}

static int emit_diagnostic(FILE *stream,
                           const char *level,
                           const char *component,
                           const char *message)
{
  fprintf(stream,
          "{\"schemaVersion\":2,\"recordKind\":\"diagnostic\","
          "\"timestampUnixNs\":\"%" PRIu64 "\",\"level\":",
          (uint64_t)realtime_ns());
  write_json_string(stream, level, strlen(level));
  fputs(",\"component\":", stream);
  write_json_string(stream, component, strlen(component));
  fputs(",\"message\":", stream);
  write_json_string(stream, message, strlen(message));
  fputs("}\n", stream);
  return fflush(stream) == 0 ? 0 : -1;
}

struct libbpf_log_capture {
  char head[NOSH_BUILD_LIBBPF_LOG_HEAD_BYTES];
  char tail[NOSH_BUILD_LIBBPF_LOG_TAIL_BYTES];
  size_t head_length;
  size_t tail_next;
  size_t tail_bytes;
};

static void add_libbpf_tail_bytes(struct libbpf_log_capture *capture,
                                  size_t length)
{
  if (SIZE_MAX - capture->tail_bytes < length)
    capture->tail_bytes = SIZE_MAX;
  else
    capture->tail_bytes += length;
}

static ssize_t write_libbpf_log_capture(void *cookie,
                                        const char *data,
                                        size_t length)
{
  struct libbpf_log_capture *capture = cookie;
  size_t head_available;
  size_t head_length;
  size_t original_length = length;
  size_t first_length;

  head_available = sizeof(capture->head) - capture->head_length;
  head_length = length < head_available ? length : head_available;
  if (head_length) {
    memcpy(capture->head + capture->head_length, data, head_length);
    capture->head_length += head_length;
    data += head_length;
    length -= head_length;
  }

  if (!length)
    return (ssize_t)original_length;

  add_libbpf_tail_bytes(capture, length);
  if (length >= sizeof(capture->tail)) {
    memcpy(capture->tail,
           data + length - sizeof(capture->tail),
           sizeof(capture->tail));
    capture->tail_next = 0;
    return (ssize_t)original_length;
  }

  first_length = sizeof(capture->tail) - capture->tail_next;
  if (first_length > length)
    first_length = length;
  memcpy(capture->tail + capture->tail_next, data, first_length);
  if (length > first_length)
    memcpy(capture->tail, data + first_length, length - first_length);
  capture->tail_next =
    (capture->tail_next + length) % sizeof(capture->tail);
  return (ssize_t)original_length;
}

static size_t copy_libbpf_log_tail(const struct libbpf_log_capture *capture,
                                   char *destination)
{
  size_t length = capture->tail_bytes < sizeof(capture->tail) ?
    capture->tail_bytes : sizeof(capture->tail);
  size_t start = capture->tail_bytes > sizeof(capture->tail) ?
    capture->tail_next : 0;
  size_t first_length = sizeof(capture->tail) - start;

  if (first_length > length)
    first_length = length;
  memcpy(destination, capture->tail + start, first_length);
  if (length > first_length)
    memcpy(destination + first_length, capture->tail,
           length - first_length);
  return length;
}

static void emit_libbpf_log_prefix(enum libbpf_print_level level,
                                   const char *format,
                                   va_list arguments)
{
  char message[512];
  size_t length;

  vsnprintf(message, sizeof(message), format, arguments);
  length = strlen(message);
  while (length && (message[length - 1] == '\n' ||
                    message[length - 1] == '\r'))
    message[--length] = '\0';
  emit_diagnostic(libbpf_status_stream,
                  level == LIBBPF_WARN ? "warning" : "info",
                  "libbpf", message);
}

static int libbpf_log(enum libbpf_print_level level,
                      const char *format,
                      va_list arguments)
{
  const cookie_io_functions_t capture_functions = {
    .write = write_libbpf_log_capture,
  };
  struct libbpf_log_capture *capture;
  char marker[NOSH_BUILD_LIBBPF_LOG_MARKER_BYTES];
  char *message;
  FILE *capture_stream;
  size_t marker_length = 0;
  size_t length;

  if (!libbpf_status_stream || level == LIBBPF_DEBUG)
    return 0;

  capture = calloc(1, sizeof(*capture));
  if (!capture) {
    emit_libbpf_log_prefix(level, format, arguments);
    return 0;
  }
  capture_stream = fopencookie(capture, "w", capture_functions);
  if (!capture_stream) {
    free(capture);
    emit_libbpf_log_prefix(level, format, arguments);
    return 0;
  }
  setvbuf(capture_stream, NULL, _IONBF, 0);
  vfprintf(capture_stream, format, arguments);
  fclose(capture_stream);

  message = malloc(NOSH_BUILD_LIBBPF_LOG_HEAD_BYTES +
                   NOSH_BUILD_LIBBPF_LOG_TAIL_BYTES +
                   NOSH_BUILD_LIBBPF_LOG_MARKER_BYTES + 1);
  if (!message) {
    free(capture);
    emit_diagnostic(libbpf_status_stream,
                    level == LIBBPF_WARN ? "warning" : "info",
                    "libbpf", "libbpf diagnostic capture unavailable");
    return 0;
  }

  memcpy(message, capture->head, capture->head_length);
  length = capture->head_length;
  if (capture->tail_bytes > sizeof(capture->tail)) {
    int marker_result = snprintf(
      marker, sizeof(marker),
      "\n...[%zu libbpf diagnostic bytes omitted]...\n",
      capture->tail_bytes - sizeof(capture->tail));

    if (marker_result > 0) {
      marker_length = (size_t)marker_result;
      if (marker_length >= sizeof(marker))
        marker_length = sizeof(marker) - 1;
      memcpy(message + length, marker, marker_length);
      length += marker_length;
    }
  }
  length += copy_libbpf_log_tail(capture, message + length);
  message[length] = '\0';
  while (length && (message[length - 1] == '\n' ||
                    message[length - 1] == '\r'))
    message[--length] = '\0';

  emit_diagnostic(libbpf_status_stream,
                  level == LIBBPF_WARN ? "warning" : "info",
                  "libbpf", message);
  free(message);
  free(capture);
  return 0;
}

static void handle_signal(int signal_number)
{
  (void)signal_number;
  stop_requested = 1;
}

static void handle_file_size_signal(int signal_number)
{
  (void)signal_number;
  evidence_file_limit_reached = 1;
  stop_requested = 1;
}

static int install_signal_handlers(void)
{
  struct sigaction stop_action = {};
  struct sigaction file_size_action = {};
  struct sigaction pipe_action = {};

  stop_action.sa_handler = handle_signal;
  sigemptyset(&stop_action.sa_mask);
  if (sigaction(SIGINT, &stop_action, NULL) != 0 ||
      sigaction(SIGTERM, &stop_action, NULL) != 0)
    return -1;
  file_size_action.sa_handler = handle_file_size_signal;
  sigemptyset(&file_size_action.sa_mask);
  if (sigaction(SIGXFSZ, &file_size_action, NULL) != 0)
    return -1;
  pipe_action.sa_handler = SIG_IGN;
  sigemptyset(&pipe_action.sa_mask);
  return sigaction(SIGPIPE, &pipe_action, NULL);
}

static int arm_parent_death_signal(pid_t expected_parent_pid)
{
  if (expected_parent_pid <= 1) {
    errno = ESRCH;
    return -1;
  }
  if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0)
    return -1;
  if (getppid() != expected_parent_pid) {
    errno = ESRCH;
    return -1;
  }
  return 0;
}

static int install_evidence_file_size_limit(void)
{
  const rlim_t cap = (rlim_t)NOSH_BUILD_EVIDENCE_FILE_LIMIT_BYTES;
  struct rlimit current;
  struct rlimit limited;

  if (getrlimit(RLIMIT_FSIZE, &current) != 0)
    return -1;
  limited.rlim_max =
    (current.rlim_max == RLIM_INFINITY || current.rlim_max > cap) ?
      cap : current.rlim_max;
  limited.rlim_cur =
    (current.rlim_cur == RLIM_INFINITY ||
     current.rlim_cur > limited.rlim_max) ?
      limited.rlim_max : current.rlim_cur;
  return setrlimit(RLIMIT_FSIZE, &limited);
}

static void usage(FILE *stream, const char *program)
{
  fprintf(stream,
          "Usage:\n"
          "  %s health [--cgroup ABSOLUTE_PATH] [--cgroup-id UINT64]"
          " [--depth process|balanced|policy|deep]\n"
          "  %s verify [--depth process|balanced|policy|deep]\n"
          "  %s run --cgroup ABSOLUTE_PATH [--cgroup-id UINT64]\\\n"
          "      [--depth process|balanced|policy|deep]"
          " [--stats-interval-ms 0|%d..%d] [--status-fd FD]\n"
          "  %s --version\n\n"
          "Process records successful cgroup-descendant execs only. Policy "
          "adds capability-gated file-open summaries; deep fails preflight.\n",
          program, program, program, NOSH_BUILD_MIN_STATS_INTERVAL_MS,
          NOSH_BUILD_MAX_STATS_INTERVAL_MS, program);
}

static int parse_u64(const char *value, __u64 *result)
{
  char *end = NULL;
  unsigned long long parsed;

  if (!value || !value[0] || value[0] == '-')
    return -1;
  errno = 0;
  parsed = strtoull(value, &end, 10);
  if (errno || !end || *end != '\0')
    return -1;
  *result = (__u64)parsed;
  return 0;
}

static int parse_uint(const char *value, unsigned int *result)
{
  __u64 parsed;

  if (parse_u64(value, &parsed) != 0 || parsed > UINT32_MAX)
    return -1;
  *result = (unsigned int)parsed;
  return 0;
}

static int parse_fd(const char *value, int *result)
{
  __u64 parsed;

  if (parse_u64(value, &parsed) != 0 || parsed > INT32_MAX || parsed < 2)
    return -1;
  if (fcntl((int)parsed, F_GETFD) < 0)
    return -1;
  *result = (int)parsed;
  return 0;
}

static int parse_options(int argc,
                         char **argv,
                         struct loader_options *options)
{
  int index;

  memset(options, 0, sizeof(*options));
  options->depth = "balanced";
  options->stats_interval_ms = NOSH_BUILD_DEFAULT_STATS_INTERVAL_MS;
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
  if (strcmp(argv[1], "run") && strcmp(argv[1], "health") &&
      strcmp(argv[1], "verify"))
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
    if (!strcmp(argument, "--depth")) {
      if (++index >= argc ||
          (strcmp(argv[index], "process") &&
           strcmp(argv[index], "balanced") &&
           strcmp(argv[index], "policy") &&
           strcmp(argv[index], "deep")))
        return -1;
      options->depth = argv[index];
      continue;
    }
    if (!strcmp(argument, "--stats-interval-ms")) {
      if (++index >= argc || options->stats_interval_set ||
          parse_uint(argv[index], &options->stats_interval_ms) != 0 ||
          options->stats_interval_ms > NOSH_BUILD_MAX_STATS_INTERVAL_MS ||
          (options->stats_interval_ms &&
           options->stats_interval_ms < NOSH_BUILD_MIN_STATS_INTERVAL_MS))
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
      (options->stats_interval_set || options->status_fd_set))
    return -1;
  if (!strcmp(options->command, "verify") &&
      (options->cgroup_path || options->expected_cgroup_id_set ||
       options->stats_interval_set || options->status_fd_set))
    return -1;
  return 0;
}

static int cgroup_id_from_fd(int cgroup_fd,
                             __u64 *cgroup_id,
                             char *error,
                             size_t error_size)
{
  struct file_handle *handle;
  size_t allocation_size =
    sizeof(struct file_handle) + NOSH_BUILD_FILE_HANDLE_BYTES;
  int mount_id = 0;
  int result = -1;

  handle = calloc(1, allocation_size);
  if (!handle) {
    snprintf(error, error_size, "cannot allocate cgroup file handle");
    return -1;
  }
  handle->handle_bytes = NOSH_BUILD_FILE_HANDLE_BYTES;
  if (name_to_handle_at(cgroup_fd, ".", handle, &mount_id, 0) != 0) {
    snprintf(error, error_size, "name_to_handle_at(cgroup): %s",
             strerror(errno));
    goto out;
  }
  if (handle->handle_bytes < sizeof(*cgroup_id)) {
    snprintf(error, error_size,
             "cgroup file handle is %u bytes; expected at least %zu",
             handle->handle_bytes, sizeof(*cgroup_id));
    goto out;
  }
  memcpy(cgroup_id, handle->f_handle, sizeof(*cgroup_id));
  if (!*cgroup_id) {
    snprintf(error, error_size, "kernel returned cgroup id 0");
    goto out;
  }
  result = 0;

out:
  free(handle);
  return result;
}

static bool same_directory(int left_fd, int right_fd)
{
  struct stat left = {};
  struct stat right = {};

  return fstat(left_fd, &left) == 0 &&
         fstat(right_fd, &right) == 0 &&
         left.st_dev == right.st_dev &&
         left.st_ino == right.st_ino;
}

static int describe_fd_path(int fd,
                            const char *fallback,
                            char *destination,
                            size_t destination_size)
{
  char proc_path[64];
  ssize_t length;

  snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
  length = readlink(proc_path, destination, destination_size - 1);
  if (length >= 0) {
    if ((size_t)length >= destination_size - 1)
      return -1;
    destination[length] = '\0';
    return 0;
  }
  if (strlen(fallback) >= destination_size)
    return -1;
  strcpy(destination, fallback);
  return 0;
}

static int resolve_cgroup_target(const struct loader_options *options,
                                 struct cgroup_target *target,
                                 char *error,
                                 size_t error_size)
{
  struct statfs filesystem = {};
  int root_fd = -1;

  memset(target, 0, sizeof(*target));
  target->fd = -1;
  if (!options->cgroup_path || options->cgroup_path[0] != '/') {
    snprintf(error, error_size, "an absolute --cgroup path is required");
    return -1;
  }
  target->fd = open(options->cgroup_path,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (target->fd < 0) {
    snprintf(error, error_size, "open cgroup %s: %s",
             options->cgroup_path, strerror(errno));
    return -1;
  }
  if (fstatfs(target->fd, &filesystem) != 0 ||
      (unsigned long)filesystem.f_type !=
        (unsigned long)CGROUP2_SUPER_MAGIC) {
    snprintf(error, error_size, "%s is not a cgroup v2 directory",
             options->cgroup_path);
    goto fail;
  }
  root_fd = open("/sys/fs/cgroup",
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root_fd >= 0 && same_directory(target->fd, root_fd)) {
    snprintf(error, error_size,
             "refusing to attach to the cgroup v2 mount root");
    goto fail;
  }
  if (cgroup_id_from_fd(target->fd, &target->id,
                        error, error_size) != 0)
    goto fail;
  if (options->expected_cgroup_id_set &&
      target->id != options->expected_cgroup_id) {
    snprintf(error, error_size,
             "cgroup id mismatch: resolved %" PRIu64
             " but --cgroup-id requires %" PRIu64,
             (uint64_t)target->id,
             (uint64_t)options->expected_cgroup_id);
    goto fail;
  }
  if (describe_fd_path(target->fd, options->cgroup_path,
                       target->path, sizeof(target->path)) != 0) {
    snprintf(error, error_size, "resolved cgroup path is too long");
    goto fail;
  }
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
  unsigned int major = 0;
  unsigned int minor = 0;

  if (uname(&system) != 0 ||
      sscanf(system.release, "%u.%u", &major, &minor) != 2)
    return false;
  return major > 5 || (major == 5 && minor >= 8);
}

static bool kernel_at_least_5_10(void)
{
  struct utsname system = {};
  unsigned int major = 0;
  unsigned int minor = 0;

  if (uname(&system) != 0 ||
      sscanf(system.release, "%u.%u", &major, &minor) != 2)
    return false;
  return major > 5 || (major == 5 && minor >= 10);
}

static bool bpf_lsm_enabled(void)
{
  char list[1024];
  ssize_t length;
  int fd;
  char *cursor;

  fd = open("/sys/kernel/security/lsm", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return false;
  length = read(fd, list, sizeof(list) - 1);
  close(fd);
  if (length <= 0)
    return false;
  list[length] = '\0';
  cursor = list;
  while (cursor && *cursor) {
    char *separator = strchr(cursor, ',');
    size_t item_length = separator ? (size_t)(separator - cursor) :
      strcspn(cursor, "\r\n");

    if (item_length == 3 && !memcmp(cursor, "bpf", 3))
      return true;
    cursor = separator ? separator + 1 : NULL;
  }
  return false;
}

static bool path_is_cgroup_v2(const char *path)
{
  struct statfs filesystem = {};

  return statfs(path, &filesystem) == 0 &&
         (unsigned long)filesystem.f_type ==
           (unsigned long)CGROUP2_SUPER_MAGIC;
}

static int run_health(const struct loader_options *options)
{
  struct cgroup_target target = {.fd = -1};
  char error[512] = {};
  bool effective_root = geteuid() == 0;
  bool kernel_ok = kernel_at_least_5_8();
  bool policy_kernel_ok = kernel_at_least_5_10();
  bool btf_ok = access("/sys/kernel/btf/vmlinux", R_OK) == 0;
  bool bpf_lsm_ok = bpf_lsm_enabled();
  bool cgroup_v2_ok = path_is_cgroup_v2("/sys/fs/cgroup");
  bool target_ok = true;
  bool policy_requested = !strcmp(options->depth, "policy");
  bool depth_ok = !strcmp(options->depth, "process") ||
    !strcmp(options->depth, "balanced") ||
    (policy_requested && policy_kernel_ok && bpf_lsm_ok);
  bool healthy;

  if (options->cgroup_path)
    target_ok = resolve_cgroup_target(options, &target,
                                      error, sizeof(error)) == 0;
  if (!strcmp(options->depth, "deep"))
    snprintf(error, sizeof(error),
             "deep collection is unavailable: off-CPU and block-latency "
             "collectors are not implemented");
  else if (policy_requested && !policy_kernel_ok)
    snprintf(error, sizeof(error),
             "policy file collection requires Linux 5.10 or newer");
  else if (policy_requested && !bpf_lsm_ok)
    snprintf(error, sizeof(error),
             "policy file collection requires an enabled BPF LSM and "
             "mounted securityfs");
  healthy = effective_root && kernel_ok && btf_ok && cgroup_v2_ok &&
            target_ok && depth_ok;

  fprintf(stdout,
          "{\"schemaVersion\":2,\"recordKind\":\"status\","
          "\"timestampUnixNs\":\"%" PRIu64 "\",\"status\":\"%s\","
          "\"pid\":%ld,\"cgroupPath\":",
          (uint64_t)realtime_ns(), healthy ? "healthy" : "unhealthy",
          (long)getpid());
  write_nullable_json_string(stdout,
                             target.fd >= 0 ? target.path :
                             options->cgroup_path);
  fputs(",\"cgroupId\":", stdout);
  if (target.fd >= 0)
    fprintf(stdout, "\"%" PRIu64 "\"", (uint64_t)target.id);
  else
    fputs("null", stdout);
  fputs(",\"attachedPrograms\":0,\"collectionDepth\":", stdout);
  write_json_string(stdout, options->depth, strlen(options->depth));
  fprintf(stdout,
          ",\"policyCollectionEnabled\":%s,"
          "\"deepCollectionSupported\":false,\"message\":",
          policy_requested ? "true" : "false");
  write_json_string(stdout,
                    healthy ? "host prerequisites satisfied" :
                    (error[0] ? error : "host prerequisites are incomplete"),
                    strlen(healthy ? "host prerequisites satisfied" :
                           (error[0] ? error :
                            "host prerequisites are incomplete")));
  fprintf(stdout,
          ",\"checks\":{\"effectiveRoot\":%s,"
          "\"kernelAtLeast5_8\":%s,\"kernelBtf\":%s,"
          "\"kernelAtLeast5_10\":%s,\"bpfLsm\":%s,"
          "\"cgroupV2\":%s,\"targetCgroup\":%s,"
          "\"requestedDepthSupported\":%s}}\n",
          effective_root ? "true" : "false",
          kernel_ok ? "true" : "false",
          btf_ok ? "true" : "false",
          policy_kernel_ok ? "true" : "false",
          bpf_lsm_ok ? "true" : "false",
          cgroup_v2_ok ? "true" : "false",
          target_ok ? "true" : "false",
          depth_ok ? "true" : "false");
  if (target.fd >= 0)
    close(target.fd);
  if (fflush(stdout) != 0)
    return 1;
  return healthy ? 0 : 1;
}

static int emit_capabilities(struct loader_context *context,
                             const char *depth)
{
  fprintf(context->event_stream,
          "{\"schemaVersion\":2,\"recordKind\":\"capabilities\","
          "\"timestampUnixNs\":\"%" PRIu64 "\","
          "\"collectionDepth\":",
          (uint64_t)realtime_ns());
  write_json_string(context->event_stream, depth, strlen(depth));
  if (context->process_depth) {
    fputs(",\"availableSources\":[\"process-exec\"],"
          "\"unavailableSources\":["
          "{\"name\":\"process-exit\",\"reason\":"
          "\"process depth records successful exec transitions only\"},"
          "{\"name\":\"syscall-summary\",\"reason\":"
          "\"disabled by process-only collection\"},"
          "{\"name\":\"udp-dns-query\",\"reason\":"
          "\"disabled by process-only collection\"},"
          "{\"name\":\"udp-dns-response\",\"reason\":"
          "\"disabled by process-only collection\"},"
          "{\"name\":\"file-operations\",\"reason\":"
          "\"disabled by process-only collection\"},",
          context->event_stream);
  } else {
    fputs(",\"availableSources\":[\"process-exec\",\"process-exit\","
          "\"syscall-summary\",\"udp-dns-query\","
          "\"udp-dns-response\"",
          context->event_stream);
    if (!strcmp(depth, "policy"))
      fputs(",\"file-operations\"", context->event_stream);
    fputs("],\"unavailableSources\":[",
          context->event_stream);
    if (strcmp(depth, "policy"))
      fputs("{\"name\":\"file-operations\",\"reason\":"
            "\"requires --depth policy and an enabled BPF LSM\"},",
            context->event_stream);
  }
  fputs(
          "{\"name\":\"tcp-dns\",\"reason\":"
          "\"DNS-over-TCP reassembly is not implemented\"},"
          "{\"name\":\"encrypted-dns\",\"reason\":"
          "\"DoH and DoT names are opaque; nosh-l4 still records flows\"},"
          "{\"name\":\"ipv6-extension-dns\",\"reason\":"
          "\"UDP DNS behind IPv6 extension headers is not parsed\"},"
          "{\"name\":\"fragmented-dns\",\"reason\":"
          "\"fragmented IPv4 UDP DNS is not reassembled\"},"
          "{\"name\":\"oversized-udp-dns\",\"reason\":"
          "\"UDP DNS messages beyond 1232 bytes are retained only as "
          "explicitly truncated evidence\"},"
          "{\"name\":\"cpu-samples\",\"reason\":"
          "\"cgroup CPU stack sampling is not implemented\"},"
          "{\"name\":\"off-cpu\",\"reason\":"
          "\"deep collection is not implemented\"},"
          "{\"name\":\"block-latency\",\"reason\":"
          "\"deep collection is not implemented\"}]}\n",
          context->event_stream);
  if (fflush(context->event_stream) != 0) {
    context->output_failed = true;
    return -1;
  }
  return 0;
}

static bool event_header_is_valid(const struct nosh_build_event_header *header,
                                  size_t data_size)
{
  if (header->schema_version != NOSH_BUILD_SCHEMA_VERSION ||
      header->event_size != data_size)
    return false;
  if (header->event_kind == NOSH_BUILD_EVENT_PROCESS_EXEC ||
      header->event_kind == NOSH_BUILD_EVENT_PROCESS_EXIT)
    return data_size == sizeof(struct nosh_build_process_event);
  if (header->event_kind == NOSH_BUILD_EVENT_DNS_QUERY)
    return data_size == sizeof(struct nosh_build_dns_wire_event);
  if (header->event_kind == NOSH_BUILD_EVENT_DNS_RESPONSE)
    return data_size == sizeof(struct nosh_build_dns_wire_event);
  return false;
}

static int event_timestamp(const struct loader_context *context,
                           __u64 monotonic_ns,
                           uint64_t *timestamp_ns)
{
  if (context->realtime_minus_monotonic_ns < 0 ||
      (uint64_t)context->realtime_minus_monotonic_ns >
        UINT64_MAX - (uint64_t)monotonic_ns)
    return -1;
  *timestamp_ns = (uint64_t)monotonic_ns +
    (uint64_t)context->realtime_minus_monotonic_ns;
  return 0;
}

static int emit_process_event(struct loader_context *context,
                              const struct nosh_build_process_event *event)
{
  const char *kind =
    event->header.event_kind == NOSH_BUILD_EVENT_PROCESS_EXEC ?
      "process-exec" : "process-exit";
  size_t comm_length = strnlen(event->comm, sizeof(event->comm));
  size_t filename_length = strnlen(event->filename, sizeof(event->filename));
  uint64_t timestamp_ns;

  if (event_timestamp(context, event->header.timestamp_ns,
                      &timestamp_ns) != 0)
    return -1;
  fprintf(context->event_stream,
          "{\"schemaVersion\":2,\"recordKind\":\"event\","
          "\"metadataOnly\":true,\"eventKind\":\"%s\","
          "\"timestampNs\":\"%" PRIu64 "\","
          "\"targetCgroupId\":\"%" PRIu64 "\","
          "\"observedCgroupId\":\"%" PRIu64 "\",\"process\":{"
          "\"pid\":%u,\"tid\":%u,\"ppid\":%u,"
          "\"uid\":%u,\"gid\":%u,\"comm\":",
          kind, timestamp_ns, (uint64_t)context->target_cgroup_id,
          (uint64_t)event->header.cgroup_id, event->pid, event->tid,
          event->ppid, event->uid, event->gid);
  write_json_string(context->event_stream, event->comm, comm_length);
  fputs("},\"executable\":", context->event_stream);
  if (event->header.event_kind == NOSH_BUILD_EVENT_PROCESS_EXEC &&
      filename_length)
    write_json_string(context->event_stream,
                      event->filename, filename_length);
  else
    fputs("null", context->event_stream);
  fputs(",\"rawExitCode\":", context->event_stream);
  if (event->header.event_kind == NOSH_BUILD_EVENT_PROCESS_EXIT)
    fprintf(context->event_stream, "%d", event->exit_code);
  else
    fputs("null", context->event_stream);
  fputs("}\n", context->event_stream);
  return fflush(context->event_stream) == 0 ? 0 : -1;
}

static int prepare_dns_correlation(
    const struct loader_context *context,
    const struct nosh_build_event_header *header,
    const struct nosh_build_dns_correlation *correlation,
    uint64_t *timestamp_ns,
    char address[INET6_ADDRSTRLEN])
{
  int family;

  if (!correlation->qname_length ||
      correlation->qname_length >= sizeof(correlation->qname) ||
      correlation->qname[correlation->qname_length] != '\0' ||
      correlation->server_port != 53 || !correlation->client_port ||
      correlation->complete > 1 ||
      correlation->complete != (correlation->socket_cookie != 0) ||
      event_timestamp(context, header->timestamp_ns, timestamp_ns) != 0)
    return -1;
  if (correlation->family == NOSH_BUILD_FAMILY_IPV4)
    family = AF_INET;
  else if (correlation->family == NOSH_BUILD_FAMILY_IPV6)
    family = AF_INET6;
  else
    return -1;
  if (!inet_ntop(family, correlation->server_address,
                 address, INET6_ADDRSTRLEN))
    return -1;
  return 0;
}

static void emit_dns_common(struct loader_context *context,
                            const struct nosh_build_event_header *header,
                            const struct nosh_build_dns_correlation *correlation,
                            const char *kind,
                            const char *direction,
                            uint64_t timestamp_ns,
                            const char *address)
{
  fprintf(context->event_stream,
          "{\"schemaVersion\":2,\"recordKind\":\"event\","
          "\"metadataOnly\":true,\"eventKind\":\"%s\","
          "\"timestampNs\":\"%" PRIu64 "\","
          "\"targetCgroupId\":\"%" PRIu64 "\","
          "\"observedCgroupId\":\"%" PRIu64 "\",\"process\":null,"
          "\"network\":{\"family\":\"%s\",\"protocol\":\"udp\","
          "\"direction\":\"%s\",\"serverAddress\":",
          kind, timestamp_ns, (uint64_t)context->target_cgroup_id,
          (uint64_t)header->cgroup_id,
          correlation->family == NOSH_BUILD_FAMILY_IPV4 ? "ipv4" : "ipv6",
          direction);
  write_json_string(context->event_stream, address, strlen(address));
  fprintf(context->event_stream,
          ",\"serverPort\":%u,\"clientPort\":%u},\"dns\":{"
          "\"transport\":\"udp\",\"qname\":",
          correlation->server_port, correlation->client_port);
  write_json_string(context->event_stream,
                    correlation->qname, correlation->qname_length);
  fprintf(context->event_stream,
          ",\"queryType\":%u,\"queryClass\":%u,\"correlation\":{"
          "\"keyVersion\":1,\"id\":\"udp53:%" PRIu64 ":%u:%u:%s:53\","
          "\"complete\":%s,\"socketCookie\":\"%" PRIu64 "\","
          "\"transactionId\":%u,\"clientPort\":%u,"
          "\"serverAddress\":",
          correlation->query_type, correlation->query_class,
          (uint64_t)correlation->socket_cookie,
          correlation->transaction_id, correlation->client_port, address,
          correlation->complete ? "true" : "false",
          (uint64_t)correlation->socket_cookie,
          correlation->transaction_id, correlation->client_port);
  write_json_string(context->event_stream, address, strlen(address));
  fprintf(context->event_stream, ",\"serverPort\":%u}",
          correlation->server_port);
}

static int emit_dns_query_event(
    struct loader_context *context,
    const struct nosh_build_dns_query_event *event)
{
  char address[INET6_ADDRSTRLEN];
  uint64_t timestamp_ns;

  if (prepare_dns_correlation(context, &event->header,
                              &event->correlation, &timestamp_ns,
                              address) != 0)
    return -1;
  emit_dns_common(context, &event->header, &event->correlation,
                  "dns-query", "query", timestamp_ns, address);
  fputs("}}\n", context->event_stream);
  return fflush(context->event_stream) == 0 ? 0 : -1;
}

static int emit_dns_answer(struct loader_context *context,
                           const struct nosh_build_dns_answer *answer,
                           unsigned int index)
{
  char address[INET6_ADDRSTRLEN];
  int family;

  if (!answer->owner_name_length ||
      answer->owner_name_length >= sizeof(answer->owner_name) ||
      answer->owner_name[answer->owner_name_length] != '\0' ||
      answer->class != 1)
    return -1;
  fprintf(context->event_stream,
          "{\"index\":%u,\"ownerName\":", index);
  write_json_string(context->event_stream, answer->owner_name,
                    answer->owner_name_length);
  fprintf(context->event_stream,
          ",\"type\":%u,\"class\":%u,\"ttl\":%u,\"data\":{",
          answer->type, answer->class, answer->ttl);
  if (answer->kind == NOSH_BUILD_DNS_ANSWER_CNAME) {
    if (answer->type != 5 || !answer->data_name_length ||
        answer->data_name_length >= sizeof(answer->data_name) ||
        answer->data_name[answer->data_name_length] != '\0')
      return -1;
    fputs("\"kind\":\"cname\",\"name\":", context->event_stream);
    write_json_string(context->event_stream, answer->data_name,
                      answer->data_name_length);
  } else {
    if (answer->kind == NOSH_BUILD_DNS_ANSWER_IPV4 &&
        answer->family == NOSH_BUILD_FAMILY_IPV4 && answer->type == 1)
      family = AF_INET;
    else if (answer->kind == NOSH_BUILD_DNS_ANSWER_IPV6 &&
             answer->family == NOSH_BUILD_FAMILY_IPV6 &&
             answer->type == 28)
      family = AF_INET6;
    else
      return -1;
    if (!inet_ntop(family, answer->address, address, sizeof(address)))
      return -1;
    fputs(family == AF_INET ? "\"kind\":\"ipv4\",\"address\":" :
          "\"kind\":\"ipv6\",\"address\":", context->event_stream);
    write_json_string(context->event_stream, address, strlen(address));
  }
  fputs("}}", context->event_stream);
  return 0;
}

static int emit_dns_response_event(
    struct loader_context *context,
    const struct nosh_build_dns_response_event *event)
{
  char address[INET6_ADDRSTRLEN];
  uint64_t timestamp_ns;
  unsigned int index;

  if (prepare_dns_correlation(context, &event->header,
                              &event->correlation, &timestamp_ns,
                              address) != 0 ||
      !(event->flags & 0x8000) ||
      event->response_code != (event->flags & 0x000f) ||
      event->question_count != 1 ||
      event->answers_visited > event->answers_declared ||
      event->answers_captured > event->answers_visited ||
      event->answers_captured > NOSH_BUILD_DNS_MAX_ANSWERS ||
      event->parse_complete > 1 || event->answer_limit_reached > 1 ||
      (event->parse_complete &&
       ((event->flags & 0x0200) || event->answer_limit_reached ||
        event->answers_visited != event->answers_declared)))
    return -1;
  emit_dns_common(context, &event->header, &event->correlation,
                  "dns-response", "response", timestamp_ns, address);
  fprintf(context->event_stream,
          ",\"response\":{\"flags\":%u,\"responseCode\":%u,"
          "\"truncated\":%s,\"questionCount\":%u,"
          "\"answersDeclared\":%u,\"answersVisited\":%u,"
          "\"answersCaptured\":%u,\"parseComplete\":%s,"
          "\"answerLimitReached\":%s,\"answers\":[",
          event->flags, event->response_code,
          (event->flags & 0x0200) ? "true" : "false",
          event->question_count, event->answers_declared,
          event->answers_visited, event->answers_captured,
          event->parse_complete ? "true" : "false",
          event->answer_limit_reached ? "true" : "false");
  for (index = 0; index < event->answers_captured; index++) {
    if (index)
      fputc(',', context->event_stream);
    if (emit_dns_answer(context, &event->answers[index], index) != 0)
      return -1;
  }
  fputs("]}}}\n", context->event_stream);
  return fflush(context->event_stream) == 0 ? 0 : -1;
}

static int dns_read_u16(const __u8 *wire,
                        size_t length,
                        size_t offset,
                        __u16 *value)
{
  __be16 encoded;

  if (offset > length || sizeof(encoded) > length - offset)
    return -1;
  memcpy(&encoded, wire + offset, sizeof(encoded));
  *value = ntohs(encoded);
  return 0;
}

static int dns_read_u32(const __u8 *wire,
                        size_t length,
                        size_t offset,
                        __u32 *value)
{
  __be32 encoded;

  if (offset > length || sizeof(encoded) > length - offset)
    return -1;
  memcpy(&encoded, wire + offset, sizeof(encoded));
  *value = ntohl(encoded);
  return 0;
}

/* Decode one DNS name without retaining the private wire representation. */
static int decode_dns_name(const __u8 *wire,
                           size_t length,
                           size_t offset,
                           char output[NOSH_BUILD_DNS_QNAME_LEN],
                           __u16 *output_length,
                           size_t *wire_end,
                           __u64 *pointer_count)
{
  size_t cursor = offset;
  size_t next = offset;
  size_t output_index = 0;
  unsigned int pointers = 0;
  unsigned int labels = 0;
  bool jumped = false;

  while (labels++ < NOSH_BUILD_DNS_MAX_LABELS) {
    __u8 label_length;
    size_t index;

    if (cursor >= length)
      return -1;
    label_length = wire[cursor++];
    if (!label_length) {
      if (output_index >= NOSH_BUILD_DNS_QNAME_LEN - 1)
        return -1;
      output[output_index++] = '.';
      output[output_index] = '\0';
      if (!jumped)
        next = cursor;
      *output_length = (__u16)output_index;
      *wire_end = next;
      *pointer_count += pointers;
      return 0;
    }
    if ((label_length & NOSH_BUILD_DNS_POINTER_MASK) ==
        NOSH_BUILD_DNS_POINTER_MASK) {
      size_t pointer_offset;

      if (++pointers > NOSH_BUILD_DNS_MAX_POINTERS || cursor >= length)
        return -1;
      pointer_offset =
        ((size_t)(label_length & 0x3f) << 8) | wire[cursor++];
      if (pointer_offset > NOSH_BUILD_DNS_POINTER_OFFSET_MASK ||
          pointer_offset < NOSH_BUILD_DNS_HEADER_LEN ||
          pointer_offset >= cursor - 2 || pointer_offset >= length)
        return -1;
      if (!jumped)
        next = cursor;
      cursor = pointer_offset;
      jumped = true;
      continue;
    }
    if ((label_length & NOSH_BUILD_DNS_POINTER_MASK) || label_length > 63 ||
        cursor > length || label_length > length - cursor)
      return -1;
    if (output_index) {
      if (output_index >= NOSH_BUILD_DNS_QNAME_LEN - 1)
        return -1;
      output[output_index++] = '.';
    }
    if (label_length > NOSH_BUILD_DNS_QNAME_LEN - 1 - output_index)
      return -1;
    for (index = 0; index < label_length; index++)
      output[output_index++] = (char)wire[cursor + index];
    cursor += label_length;
    if (!jumped)
      next = cursor;
  }
  return -1;
}

static int decode_dns_common(
    struct loader_context *context,
    const struct nosh_build_dns_wire_event *wire_event,
    struct nosh_build_dns_correlation *correlation,
    __u16 *flags,
    __u16 *question_count,
    __u16 *answer_count,
    size_t *question_end)
{
  const __u8 *wire = wire_event->wire;
  size_t length = wire_event->wire_length;
  __u64 pointers = 0;

  if (wire_event->server_port != 53 || !wire_event->client_port ||
      wire_event->wire_length < NOSH_BUILD_DNS_HEADER_LEN ||
      wire_event->wire_length > NOSH_BUILD_DNS_WIRE_LEN ||
      wire_event->original_length < wire_event->wire_length ||
      (wire_event->family != NOSH_BUILD_FAMILY_IPV4 &&
       wire_event->family != NOSH_BUILD_FAMILY_IPV6) ||
      dns_read_u16(wire, length, 0, &correlation->transaction_id) != 0 ||
      dns_read_u16(wire, length, 2, flags) != 0 ||
      dns_read_u16(wire, length, 4, question_count) != 0 ||
      dns_read_u16(wire, length, 6, answer_count) != 0 ||
      *question_count != 1 ||
      (!!(*flags & NOSH_BUILD_DNS_RESPONSE) !=
       (wire_event->header.event_kind == NOSH_BUILD_EVENT_DNS_RESPONSE)) ||
      decode_dns_name(wire, length, NOSH_BUILD_DNS_HEADER_LEN,
                      correlation->qname, &correlation->qname_length,
                      question_end, &pointers) != 0 ||
      dns_read_u16(wire, length, *question_end,
                   &correlation->query_type) != 0 ||
      dns_read_u16(wire, length, *question_end + 2,
                   &correlation->query_class) != 0)
    return -1;
  *question_end += 4;
  correlation->socket_cookie = wire_event->socket_cookie;
  correlation->client_port = wire_event->client_port;
  correlation->server_port = wire_event->server_port;
  correlation->family = wire_event->family;
  correlation->complete = wire_event->socket_cookie != 0;
  memcpy(correlation->server_address, wire_event->server_address,
         sizeof(correlation->server_address));
  context->dns_name_pointers += pointers;
  if (pointers)
    context->dns_compressed_names++;
  return 0;
}

static int decode_and_emit_dns_query(
    struct loader_context *context,
    const struct nosh_build_dns_wire_event *wire_event)
{
  struct nosh_build_dns_query_event event = {};
  __u16 flags = 0;
  __u16 questions = 0;
  __u16 answers = 0;
  size_t question_end = 0;

  event.header = wire_event->header;
  event.header.event_size = sizeof(event);
  if (decode_dns_common(context, wire_event, &event.correlation,
                        &flags, &questions, &answers,
                        &question_end) != 0) {
    context->dns_parse_errors++;
    return 0;
  }
  return emit_dns_query_event(context, &event) == 0 ? 1 : -1;
}

static int decode_and_emit_dns_response(
    struct loader_context *context,
    const struct nosh_build_dns_wire_event *wire_event)
{
  struct nosh_build_dns_response_event *event = calloc(1, sizeof(*event));
  size_t cursor = 0;
  unsigned int index;
  int result = 0;

  if (!event)
    return -1;
  event->header = wire_event->header;
  event->header.event_size = sizeof(*event);
  if (decode_dns_common(context, wire_event, &event->correlation,
                        &event->flags, &event->question_count,
                        &event->answers_declared, &cursor) != 0) {
    context->dns_parse_errors++;
    goto out;
  }
  event->response_code = event->flags & NOSH_BUILD_DNS_RCODE_MASK;
  event->parse_complete =
    !(event->flags & NOSH_BUILD_DNS_TRUNCATED) &&
    wire_event->wire_length == wire_event->original_length;
  if (event->flags & NOSH_BUILD_DNS_TRUNCATED)
    context->dns_truncated_responses++;
  if (event->answers_declared > NOSH_BUILD_DNS_MAX_VISITED_ANSWERS) {
    event->answer_limit_reached = 1;
    event->parse_complete = 0;
    context->dns_answer_limit_reached++;
  }
  for (index = 0;
       index < event->answers_declared &&
       index < NOSH_BUILD_DNS_MAX_VISITED_ANSWERS;
       index++) {
    char owner[NOSH_BUILD_DNS_QNAME_LEN] = {};
    __u16 owner_length = 0;
    size_t owner_end = 0;
    size_t data_offset;
    size_t data_end;
    __u16 type = 0;
    __u16 class = 0;
    __u16 data_length = 0;
    __u32 ttl = 0;
    __u64 pointers = 0;
    bool supported;

    if (decode_dns_name(wire_event->wire, wire_event->wire_length, cursor,
                        owner, &owner_length, &owner_end, &pointers) != 0 ||
        dns_read_u16(wire_event->wire, wire_event->wire_length,
                     owner_end, &type) != 0 ||
        dns_read_u16(wire_event->wire, wire_event->wire_length,
                     owner_end + 2, &class) != 0 ||
        dns_read_u32(wire_event->wire, wire_event->wire_length,
                     owner_end + 4, &ttl) != 0 ||
        dns_read_u16(wire_event->wire, wire_event->wire_length,
                     owner_end + 8, &data_length) != 0) {
      event->parse_complete = 0;
      context->dns_parse_errors++;
      break;
    }
    context->dns_name_pointers += pointers;
    if (pointers)
      context->dns_compressed_names++;
    data_offset = owner_end + NOSH_BUILD_DNS_RR_TAIL_LEN;
    if (data_offset > wire_event->wire_length ||
        data_length > wire_event->wire_length - data_offset) {
      event->parse_complete = 0;
      context->dns_parse_errors++;
      break;
    }
    data_end = data_offset + data_length;
    event->answers_visited++;
    if (class == 1 &&
        ((type == 1 && data_length != 4) ||
         (type == 28 && data_length != 16) ||
         (type == 5 && !data_length))) {
      event->parse_complete = 0;
      context->dns_parse_errors++;
      break;
    }
    supported = class == 1 &&
      ((type == 1 && data_length == 4) ||
       (type == 28 && data_length == 16) ||
       (type == 5 && data_length > 0));
    if (!supported) {
      context->dns_unsupported_answers++;
      cursor = data_end;
      continue;
    }
    if (event->answers_captured >= NOSH_BUILD_DNS_MAX_ANSWERS) {
      if (!event->answer_limit_reached)
        context->dns_answer_limit_reached++;
      event->answer_limit_reached = 1;
      event->parse_complete = 0;
      cursor = data_end;
      continue;
    }
    {
      struct nosh_build_dns_answer *answer =
        &event->answers[event->answers_captured];

      answer->ttl = ttl;
      answer->type = type;
      answer->class = class;
      answer->owner_name_length = owner_length;
      memcpy(answer->owner_name, owner, owner_length + 1);
      if (type == 1) {
        answer->kind = NOSH_BUILD_DNS_ANSWER_IPV4;
        answer->family = NOSH_BUILD_FAMILY_IPV4;
        memcpy(answer->address, wire_event->wire + data_offset, 4);
      } else if (type == 28) {
        answer->kind = NOSH_BUILD_DNS_ANSWER_IPV6;
        answer->family = NOSH_BUILD_FAMILY_IPV6;
        memcpy(answer->address, wire_event->wire + data_offset, 16);
      } else {
        size_t cname_end = 0;
        __u64 cname_pointers = 0;

        answer->kind = NOSH_BUILD_DNS_ANSWER_CNAME;
        if (decode_dns_name(wire_event->wire, wire_event->wire_length,
                            data_offset, answer->data_name,
                            &answer->data_name_length, &cname_end,
                            &cname_pointers) != 0 || cname_end != data_end) {
          event->parse_complete = 0;
          context->dns_parse_errors++;
          break;
        }
        context->dns_name_pointers += cname_pointers;
        if (cname_pointers)
          context->dns_compressed_names++;
      }
    }
    event->answers_captured++;
    cursor = data_end;
  }
  if (event->answers_visited != event->answers_declared)
    event->parse_complete = 0;
  result = emit_dns_response_event(context, event) == 0 ? 1 : -1;
out:
  free(event);
  return result;
}

static int decode_and_emit_dns_wire(
    struct loader_context *context,
    const struct nosh_build_dns_wire_event *event)
{
  if (event->header.event_kind == NOSH_BUILD_EVENT_DNS_QUERY)
    return decode_and_emit_dns_query(context, event);
  return decode_and_emit_dns_response(context, event);
}

static int handle_ring_event(void *opaque, void *data, size_t data_size)
{
  struct loader_context *context = opaque;
  const struct nosh_build_event_header *header = data;
  int result;

  if (data_size < sizeof(*header) ||
      !event_header_is_valid(header, data_size)) {
    context->decoder_errors++;
    return 0;
  }
  if (header->event_kind == NOSH_BUILD_EVENT_DNS_QUERY ||
      header->event_kind == NOSH_BUILD_EVENT_DNS_RESPONSE)
    result = decode_and_emit_dns_wire(context, data);
  else
    result = emit_process_event(context, data);
  if (result < 0) {
    context->output_failed = true;
    return -EIO;
  }
  context->events_seen++;
  return 0;
}

static __u64 sum_per_cpu_values(const __u64 *values, int possible_cpus)
{
  __u64 total = 0;
  int cpu;

  for (cpu = 0; cpu < possible_cpus; cpu++) {
    if (UINT64_MAX - total < values[cpu])
      return UINT64_MAX;
    total += values[cpu];
  }
  return total;
}

static __u64 saturating_add_u64(__u64 left, __u64 right)
{
  return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static int read_syscall_totals(
    struct loader_context *context,
    const struct nosh_build_syscall_key *key,
    struct nosh_build_syscall_totals *totals)
{
  size_t bytes = (size_t)context->possible_cpus *
    sizeof(*context->per_cpu_syscall_values);
  int cpu;

  memset(context->per_cpu_syscall_values, 0, bytes);
  if (bpf_map_lookup_elem(context->syscall_map_fd, key,
                          context->per_cpu_syscall_values) != 0)
    return -1;
  memset(totals, 0, sizeof(*totals));
  for (cpu = 0; cpu < context->possible_cpus; cpu++) {
    const struct nosh_build_syscall_totals *slot =
      &context->per_cpu_syscall_values[cpu];

    totals->calls = saturating_add_u64(totals->calls, slot->calls);
    totals->completions = saturating_add_u64(totals->completions,
                                             slot->completions);
    totals->errors = saturating_add_u64(totals->errors, slot->errors);
    totals->total_duration_ns = saturating_add_u64(
      totals->total_duration_ns, slot->total_duration_ns);
    if (slot->max_duration_ns > totals->max_duration_ns)
      totals->max_duration_ns = slot->max_duration_ns;
  }
  return 0;
}

static int read_stat(struct loader_context *context,
                     enum nosh_build_stat stat,
                     __u64 *value)
{
  __u32 key = stat;
  size_t bytes =
    (size_t)context->possible_cpus * sizeof(*context->per_cpu_values);

  memset(context->per_cpu_values, 0, bytes);
  if (bpf_map_lookup_elem(context->stats_map_fd, &key,
                          context->per_cpu_values) != 0)
    return -1;
  *value = sum_per_cpu_values(context->per_cpu_values,
                              context->possible_cpus);
  return 0;
}

static int count_inflight_syscalls(struct loader_context *context,
                                   __u64 *count)
{
  __u64 current;
  __u64 next;
  __u64 scanned = 0;
  bool have_current = false;

  *count = 0;
  while (scanned < NOSH_BUILD_INFLIGHT_MAX_ENTRIES &&
         bpf_map_get_next_key(context->inflight_map_fd,
                              have_current ? &current : NULL,
                              &next) == 0) {
    if (*count == UINT64_MAX)
      return -1;
    (*count)++;
    scanned++;
    current = next;
    have_current = true;
  }
  if (scanned == NOSH_BUILD_INFLIGHT_MAX_ENTRIES)
    return 0;
  return errno == ENOENT ? 0 : -1;
}

static int emit_stats_json(struct loader_context *context, bool final)
{
  __u64 counters[NOSH_BUILD_STAT_MAX] = {};
  __u64 inflight = 0;
  int stat;

  for (stat = 0; stat < NOSH_BUILD_STAT_MAX; stat++) {
    if (read_stat(context, stat, &counters[stat]) != 0)
      return -1;
  }
  counters[NOSH_BUILD_STAT_DNS_PARSE_ERRORS] = saturating_add_u64(
    counters[NOSH_BUILD_STAT_DNS_PARSE_ERRORS], context->dns_parse_errors);
  counters[NOSH_BUILD_STAT_DNS_COMPRESSED_NAMES] = saturating_add_u64(
    counters[NOSH_BUILD_STAT_DNS_COMPRESSED_NAMES],
    context->dns_compressed_names);
  counters[NOSH_BUILD_STAT_DNS_TRUNCATED_NAMES] = saturating_add_u64(
    counters[NOSH_BUILD_STAT_DNS_TRUNCATED_NAMES],
    context->dns_truncated_names);
  counters[NOSH_BUILD_STAT_DNS_TRUNCATED_RESPONSES] = saturating_add_u64(
    counters[NOSH_BUILD_STAT_DNS_TRUNCATED_RESPONSES],
    context->dns_truncated_responses);
  counters[NOSH_BUILD_STAT_DNS_ANSWER_LIMIT_REACHED] = saturating_add_u64(
    counters[NOSH_BUILD_STAT_DNS_ANSWER_LIMIT_REACHED],
    context->dns_answer_limit_reached);
  counters[NOSH_BUILD_STAT_DNS_UNSUPPORTED_ANSWERS] = saturating_add_u64(
    counters[NOSH_BUILD_STAT_DNS_UNSUPPORTED_ANSWERS],
    context->dns_unsupported_answers);
  counters[NOSH_BUILD_STAT_DNS_NAME_POINTERS] = saturating_add_u64(
    counters[NOSH_BUILD_STAT_DNS_NAME_POINTERS], context->dns_name_pointers);
  if (count_inflight_syscalls(context, &inflight) != 0)
    return -1;

  fprintf(context->event_stream,
          "{\"schemaVersion\":2,\"recordKind\":\"stats\","
          "\"timestampUnixNs\":\"%" PRIu64 "\","
          "\"targetCgroupId\":\"%" PRIu64 "\",\"final\":%s,"
          "\"eventsSeen\":\"%" PRIu64 "\","
          "\"decoderErrors\":\"%" PRIu64 "\","
          "\"inflightSyscalls\":\"%" PRIu64 "\",\"counters\":{"
          "\"ringbufDrops\":\"%" PRIu64 "\","
          "\"syscallMapFull\":\"%" PRIu64 "\","
          "\"inflightMapFull\":\"%" PRIu64 "\","
          "\"configMissing\":\"%" PRIu64 "\","
          "\"cgroupFilterErrors\":\"%" PRIu64 "\","
          "\"dnsParseErrors\":\"%" PRIu64 "\","
          "\"dnsCompressedNames\":\"%" PRIu64 "\","
          "\"dnsTruncatedNames\":\"%" PRIu64 "\","
          "\"dnsTruncatedResponses\":\"%" PRIu64 "\","
          "\"dnsAnswerLimitReached\":\"%" PRIu64 "\","
          "\"dnsUnsupportedAnswers\":\"%" PRIu64 "\","
          "\"dnsCorrelationMissing\":\"%" PRIu64 "\","
          "\"dnsQueryObservations\":\"%" PRIu64 "\","
          "\"dnsResponseObservations\":\"%" PRIu64 "\","
          "\"dnsNamePointers\":\"%" PRIu64 "\","
          "\"fileMapFull\":\"%" PRIu64 "\","
          "\"filePathErrors\":\"%" PRIu64 "\","
          "\"fileOpenObservations\":\"%" PRIu64 "\"},"
          "\"fileSummaryRecords\":\"%" PRIu64 "\"}\n",
          (uint64_t)realtime_ns(),
          (uint64_t)context->target_cgroup_id,
          final ? "true" : "false",
          (uint64_t)context->events_seen,
          (uint64_t)context->decoder_errors,
          (uint64_t)inflight,
          (uint64_t)counters[NOSH_BUILD_STAT_RINGBUF_DROPS],
          (uint64_t)counters[NOSH_BUILD_STAT_SYSCALL_MAP_FULL],
          (uint64_t)counters[NOSH_BUILD_STAT_INFLIGHT_MAP_FULL],
          (uint64_t)counters[NOSH_BUILD_STAT_CONFIG_MISSING],
          (uint64_t)counters[NOSH_BUILD_STAT_CGROUP_FILTER_ERRORS],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_PARSE_ERRORS],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_COMPRESSED_NAMES],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_TRUNCATED_NAMES],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_TRUNCATED_RESPONSES],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_ANSWER_LIMIT_REACHED],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_UNSUPPORTED_ANSWERS],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_CORRELATION_MISSING],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_QUERY_OBSERVATIONS],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_RESPONSE_OBSERVATIONS],
          (uint64_t)counters[NOSH_BUILD_STAT_DNS_NAME_POINTERS],
          (uint64_t)counters[NOSH_BUILD_STAT_FILE_MAP_FULL],
          (uint64_t)counters[NOSH_BUILD_STAT_FILE_PATH_ERRORS],
          (uint64_t)counters[NOSH_BUILD_STAT_FILE_OPEN_OBSERVATIONS],
          (uint64_t)context->file_summaries_emitted);
  if (fflush(context->event_stream) != 0) {
    context->output_failed = true;
    return -1;
  }
  return 0;
}

static int emit_syscall_summaries(struct loader_context *context)
{
  struct nosh_build_syscall_key current;
  struct nosh_build_syscall_key next;
  bool have_current = false;

  while (bpf_map_get_next_key(context->syscall_map_fd,
                              have_current ? &current : NULL,
                              &next) == 0) {
    struct nosh_build_syscall_totals totals = {};

    if (read_syscall_totals(context, &next, &totals) != 0)
      return -1;
    fprintf(context->event_stream,
            "{\"schemaVersion\":2,"
            "\"recordKind\":\"syscall-summary\","
            "\"timestampUnixNs\":\"%" PRIu64 "\","
            "\"targetCgroupId\":\"%" PRIu64 "\","
            "\"syscallNumber\":%" PRId64 ","
            "\"calls\":\"%" PRIu64 "\","
            "\"completions\":\"%" PRIu64 "\","
            "\"errors\":\"%" PRIu64 "\","
            "\"totalDurationNs\":\"%" PRIu64 "\","
            "\"maxDurationNs\":\"%" PRIu64 "\"}\n",
            (uint64_t)realtime_ns(),
            (uint64_t)context->target_cgroup_id,
            (int64_t)next.syscall_number,
            (uint64_t)totals.calls,
            (uint64_t)totals.completions,
            (uint64_t)totals.errors,
            (uint64_t)totals.total_duration_ns,
            (uint64_t)totals.max_duration_ns);
    if (fflush(context->event_stream) != 0) {
      context->output_failed = true;
      return -1;
    }
    current = next;
    have_current = true;
  }
  return errno == ENOENT ? 0 : -1;
}

static int emit_file_summaries(struct loader_context *context)
{
  struct nosh_build_file_key current;
  struct nosh_build_file_key next;
  bool have_current = false;
  __u64 scanned = 0;

  if (!context->policy_depth)
    return 0;
  while (scanned < NOSH_BUILD_FILE_MAX_ENTRIES &&
         bpf_map_get_next_key(context->file_map_fd,
                              have_current ? &current : NULL,
                              &next) == 0) {
    struct nosh_build_file_totals totals = {};
    size_t path_length = strnlen(next.path, sizeof(next.path));
    uint64_t first_observed_ns;
    uint64_t last_observed_ns;

    if (!path_length || path_length == sizeof(next.path) ||
        bpf_map_lookup_elem(context->file_map_fd, &next, &totals) != 0 ||
        !totals.opens || !totals.first_seen_ns || !totals.last_seen_ns ||
        totals.first_seen_ns > totals.last_seen_ns ||
        event_timestamp(context, totals.first_seen_ns,
                        &first_observed_ns) != 0 ||
        event_timestamp(context, totals.last_seen_ns,
                        &last_observed_ns) != 0)
      return -1;
    fprintf(context->event_stream,
            "{\"schemaVersion\":2,\"recordKind\":\"file-summary\","
            "\"metadataOnly\":true,"
            "\"timestampUnixNs\":\"%" PRIu64 "\","
            "\"targetCgroupId\":\"%" PRIu64 "\",\"path\":",
            (uint64_t)realtime_ns(),
            (uint64_t)context->target_cgroup_id);
    write_json_string(context->event_stream, next.path, path_length);
    fprintf(context->event_stream,
            ",\"aggregationKey\":\"resolved-path\","
            "\"firstObservedNs\":\"%" PRIu64 "\","
            "\"lastObservedNs\":\"%" PRIu64 "\","
            "\"opens\":\"%" PRIu64 "\",\"accessCounts\":{"
            "\"read\":\"%" PRIu64 "\","
            "\"write\":\"%" PRIu64 "\","
            "\"execute\":\"%" PRIu64 "\","
            "\"create\":\"%" PRIu64 "\"}}\n",
            first_observed_ns, last_observed_ns,
            (uint64_t)totals.opens,
            (uint64_t)totals.read_opens,
            (uint64_t)totals.write_opens,
            (uint64_t)totals.execute_opens,
            (uint64_t)totals.create_opens);
    if (fflush(context->event_stream) != 0) {
      context->output_failed = true;
      return -1;
    }
    context->file_summaries_emitted++;
    scanned++;
    current = next;
    have_current = true;
  }
  if (scanned == NOSH_BUILD_FILE_MAX_ENTRIES)
    return 0;
  return errno == ENOENT ? 0 : -1;
}

static int destroy_links(struct bpf_link *links[NOSH_BUILD_PROGRAM_COUNT])
{
  const int detach_order[NOSH_BUILD_PROGRAM_COUNT] = {
    6, /* stop policy file opens before taking the final map snapshot */
    2, /* stop new syscall entries first */
    4, /* then stop DNS query observations */
    5, /* then stop DNS response observations */
    0, /* then process exec */
    3, /* allow already-entered syscalls a chance to complete */
    1, /* process exit remains last so it can clear exit syscalls */
  };
  int index;
  int result = 0;

  for (index = 0; index < NOSH_BUILD_PROGRAM_COUNT; index++) {
    int selected = detach_order[index];

    if (links[selected]) {
      if (bpf_link__destroy(links[selected]) != 0)
        result = -1;
      links[selected] = NULL;
    }
  }
  return result;
}

static void set_memlock_limit(FILE *status_stream)
{
  struct rlimit limit = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0)
    emit_diagnostic(status_stream, "warning", "loader",
                    "cannot raise RLIMIT_MEMLOCK; continuing for kernels "
                    "with memcg-based BPF accounting");
}

static int configure_program_autoload(struct nosh_build_bpf *skeleton,
                                      const char *depth)
{
  bool process_requested = !strcmp(depth, "process");
  bool policy_requested = !strcmp(depth, "policy");

  if (!policy_requested &&
      bpf_program__set_autoload(
        skeleton->progs.nosh_build_file_open, false) != 0)
    return -1;
  if (!process_requested)
    return 0;
  if (bpf_program__set_autoload(
        skeleton->progs.nosh_build_process_exit, false) != 0 ||
      bpf_program__set_autoload(
        skeleton->progs.nosh_build_sys_enter, false) != 0 ||
      bpf_program__set_autoload(
        skeleton->progs.nosh_build_sys_exit, false) != 0 ||
      bpf_program__set_autoload(
        skeleton->progs.nosh_build_dns_egress, false) != 0 ||
      bpf_program__set_autoload(
        skeleton->progs.nosh_build_dns_ingress, false) != 0)
    return -1;
  return 0;
}

/*
 * Exercise the real kernel verifier without attaching any program. `health`
 * intentionally remains a read-only prerequisite probe; this command closes
 * the gap between a successful package/install check and the first live run.
 */
static int run_verifier_probe(const struct loader_options *options)
{
  struct nosh_build_bpf *skeleton = NULL;
  char error_message[512] = {};
  bool policy_requested = !strcmp(options->depth, "policy");
  int exit_status = 1;

  setvbuf(stdout, NULL, _IOLBF, 0);
  libbpf_status_stream = stdout;
  libbpf_set_print(libbpf_log);

  if (geteuid() != 0) {
    emit_status(stdout, "error", NULL, 0, options->depth,
                "kernel verifier probe requires root");
    goto cleanup;
  }
  if (!kernel_at_least_5_8() ||
      access("/sys/kernel/btf/vmlinux", R_OK) != 0 ||
      !path_is_cgroup_v2("/sys/fs/cgroup")) {
    emit_status(stdout, "error", NULL, 0, options->depth,
                "kernel verifier prerequisites are incomplete");
    goto cleanup;
  }
  if (!strcmp(options->depth, "deep")) {
    emit_status(stdout, "error", NULL, 0, options->depth,
                "deep collection is unavailable: off-CPU and block-latency "
                "collectors are not implemented");
    goto cleanup;
  }
  if (policy_requested &&
      (!kernel_at_least_5_10() || !bpf_lsm_enabled())) {
    emit_status(stdout, "error", NULL, 0, options->depth,
                "policy file collection requires Linux 5.10+, an enabled "
                "BPF LSM, and mounted securityfs");
    goto cleanup;
  }

  set_memlock_limit(stdout);
  skeleton = nosh_build_bpf__open();
  if (!skeleton) {
    snprintf(error_message, sizeof(error_message),
             "cannot open embedded BPF skeleton: %s", strerror(errno));
    emit_status(stdout, "error", NULL, 0, options->depth, error_message);
    goto cleanup;
  }
  if (configure_program_autoload(skeleton, options->depth) != 0) {
    emit_status(stdout, "error", NULL, 0, options->depth,
                "cannot configure programs for the requested depth");
    goto cleanup;
  }
  {
    int load_result = nosh_build_bpf__load(skeleton);

    if (load_result != 0) {
      int load_error = load_result < 0 ? -load_result : load_result;

      snprintf(error_message, sizeof(error_message),
               "kernel verifier rejected BPF object: %s",
               strerror(load_error));
      emit_status(stdout, "error", NULL, 0, options->depth, error_message);
      goto cleanup;
    }
  }
  if (emit_status(stdout, "healthy", NULL, 0, options->depth,
                  "kernel verifier accepted BPF object; no programs attached")
      != 0)
    goto cleanup;
  exit_status = 0;

cleanup:
  if (skeleton)
    nosh_build_bpf__destroy(skeleton);
  libbpf_status_stream = NULL;
  return exit_status;
}

static int attach_program(struct bpf_program *program,
                          struct bpf_link **link,
                          const char *name,
                          FILE *status_stream,
                          const struct cgroup_target *target,
                          int attached_programs,
                          const char *depth)
{
  long link_error;
  char error_message[256];

  *link = bpf_program__attach(program);
  link_error = *link ? libbpf_get_error(*link) : -(errno ? errno : EINVAL);
  if (!link_error)
    return 0;
  *link = NULL;
  snprintf(error_message, sizeof(error_message),
           "cannot attach %s program: %s",
           name, strerror((int)-link_error));
  emit_status(status_stream, "error", target, attached_programs,
              depth, error_message);
  return -1;
}

static int run_loader(const struct loader_options *options,
                      pid_t expected_parent_pid)
{
  struct cgroup_target target = {.fd = -1};
  struct nosh_build_bpf *skeleton = NULL;
  struct ring_buffer *ring = NULL;
  struct bpf_link *links[NOSH_BUILD_PROGRAM_COUNT] = {};
  struct loader_context context = {.event_stream = stdout};
  struct nosh_build_config config = {};
  __u32 cgroup_fd_value;
  FILE *status_stream = NULL;
  char error_message[512] = {};
  int status_dup = -1;
  int attached_programs = 0;
  int exit_status = 1;
  int runtime_error = 0;
  int64_t next_stats_ms = 0;
  __u32 config_key = 0;
  long link_error;

  status_dup = dup(options->status_fd);
  if (status_dup < 0)
    return 1;
  status_stream = fdopen(status_dup, "a");
  if (!status_stream) {
    close(status_dup);
    return 1;
  }
  setvbuf(status_stream, NULL, _IOLBF, 0);
  setvbuf(stdout, NULL, _IOLBF, 0);
  libbpf_status_stream = status_stream;
  libbpf_set_print(libbpf_log);

  if (install_signal_handlers() != 0) {
    emit_status(status_stream, "error", NULL, 0, options->depth,
                "cannot install signal handlers");
    goto cleanup;
  }
  if (install_evidence_file_size_limit() != 0) {
    snprintf(error_message, sizeof(error_message),
             "cannot install 128 MiB evidence file-size limit: %s",
             strerror(errno));
    emit_status(status_stream, "error", NULL, 0, options->depth,
                error_message);
    goto cleanup;
  }
  if (arm_parent_death_signal(expected_parent_pid) != 0) {
    snprintf(error_message, sizeof(error_message),
             "cannot arm supervisor death signal: %s", strerror(errno));
    emit_status(status_stream, "error", NULL, 0, options->depth,
                error_message);
    goto cleanup;
  }
  if (!strcmp(options->depth, "deep")) {
    emit_status(status_stream, "error", NULL, 0, options->depth,
                "deep collection is unavailable: off-CPU and block-latency "
                "collectors are not implemented");
    goto cleanup;
  }
  if (!strcmp(options->depth, "policy") &&
      (!kernel_at_least_5_10() || !bpf_lsm_enabled())) {
    emit_status(status_stream, "error", NULL, 0, options->depth,
                "policy file collection requires Linux 5.10+, an enabled "
                "BPF LSM, and mounted securityfs");
    goto cleanup;
  }
  if (resolve_cgroup_target(options, &target,
                            error_message, sizeof(error_message)) != 0) {
    emit_status(status_stream, "error", NULL, 0, options->depth,
                error_message);
    goto cleanup;
  }
  if (emit_status(status_stream, "starting", &target, 0, options->depth,
                  "loading CO-RE programs") != 0)
    goto cleanup;

  set_memlock_limit(status_stream);
  skeleton = nosh_build_bpf__open();
  if (!skeleton) {
    snprintf(error_message, sizeof(error_message),
             "cannot open embedded BPF skeleton: %s", strerror(errno));
    emit_status(status_stream, "error", &target, 0, options->depth,
                error_message);
    goto cleanup;
  }
  if (configure_program_autoload(skeleton, options->depth) != 0) {
    emit_status(status_stream, "error", &target, 0, options->depth,
                "cannot configure programs for the requested depth");
    goto cleanup;
  }
  {
    int load_result = nosh_build_bpf__load(skeleton);

    if (load_result != 0) {
      int load_error = load_result < 0 ? -load_result : load_result;

      snprintf(error_message, sizeof(error_message),
               "cannot load BPF object: %s", strerror(load_error));
      emit_status(status_stream, "error", &target, 0, options->depth,
                  error_message);
      goto cleanup;
    }
  }

  config.target_cgroup_id = target.id;
  config.collection_depth = !strcmp(options->depth, "policy") ?
    NOSH_BUILD_DEPTH_POLICY : NOSH_BUILD_DEPTH_BALANCED;
  cgroup_fd_value = (__u32)target.fd;
  if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.session_config),
                          &config_key, &config, BPF_ANY) != 0) {
    snprintf(error_message, sizeof(error_message),
             "cannot initialize target cgroup config: %s", strerror(errno));
    emit_status(status_stream, "error", &target, 0, options->depth,
                error_message);
    goto cleanup;
  }
  if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.target_cgroup),
                          &config_key, &cgroup_fd_value, BPF_ANY) != 0) {
    snprintf(error_message, sizeof(error_message),
             "cannot initialize descendant cgroup filter: %s",
             strerror(errno));
    emit_status(status_stream, "error", &target, 0, options->depth,
                error_message);
    goto cleanup;
  }

  context.stats_map_fd = bpf_map__fd(skeleton->maps.stats);
  context.syscall_map_fd = bpf_map__fd(skeleton->maps.syscall_totals);
  context.inflight_map_fd = bpf_map__fd(skeleton->maps.inflight_syscalls);
  context.file_map_fd = bpf_map__fd(skeleton->maps.file_totals);
  context.possible_cpus = libbpf_num_possible_cpus();
  context.target_cgroup_id = target.id;
  context.policy_depth = !strcmp(options->depth, "policy");
  context.process_depth = !strcmp(options->depth, "process");
  if (context.stats_map_fd < 0 || context.syscall_map_fd < 0 ||
      context.inflight_map_fd < 0 || context.file_map_fd < 0 ||
      context.possible_cpus <= 0 ||
      sample_clock_offset(&context.realtime_minus_monotonic_ns) != 0) {
    emit_status(status_stream, "error", &target, 0, options->depth,
                "cannot initialize collector map readers");
    goto cleanup;
  }
  context.per_cpu_values = calloc((size_t)context.possible_cpus,
                                  sizeof(*context.per_cpu_values));
  context.per_cpu_syscall_values = calloc(
    (size_t)context.possible_cpus,
    sizeof(*context.per_cpu_syscall_values));
  if (!context.per_cpu_values || !context.per_cpu_syscall_values) {
    emit_status(status_stream, "error", &target, 0, options->depth,
                "cannot allocate per-CPU collector buffers");
    goto cleanup;
  }
  ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
                          handle_ring_event, &context, NULL);
  if (!ring) {
    snprintf(error_message, sizeof(error_message),
             "cannot open event ring buffer: %s", strerror(errno));
    emit_status(status_stream, "error", &target, 0, options->depth,
                error_message);
    goto cleanup;
  }

  if (attach_program(skeleton->progs.nosh_build_process_exec, &links[0],
                     "process-exec", status_stream, &target,
                     attached_programs, options->depth) != 0)
    goto cleanup;
  attached_programs++;
  if (!context.process_depth) {
    if (attach_program(skeleton->progs.nosh_build_process_exit, &links[1],
                       "process-exit", status_stream, &target,
                       attached_programs, options->depth) != 0)
      goto cleanup;
    attached_programs++;
    if (attach_program(skeleton->progs.nosh_build_sys_enter, &links[2],
                       "sys-enter", status_stream, &target,
                       attached_programs, options->depth) != 0)
      goto cleanup;
    attached_programs++;
    if (attach_program(skeleton->progs.nosh_build_sys_exit, &links[3],
                       "sys-exit", status_stream, &target,
                       attached_programs, options->depth) != 0)
      goto cleanup;
    attached_programs++;

    links[4] = bpf_program__attach_cgroup(
      skeleton->progs.nosh_build_dns_egress, target.fd);
    link_error = links[4] ? libbpf_get_error(links[4]) :
      -(errno ? errno : EINVAL);
    if (link_error) {
      links[4] = NULL;
      snprintf(error_message, sizeof(error_message),
               "cannot attach UDP DNS program: %s",
               strerror((int)-link_error));
      emit_status(status_stream, "error", &target, attached_programs,
                  options->depth, error_message);
      goto cleanup;
    }
    attached_programs++;

    links[5] = bpf_program__attach_cgroup(
      skeleton->progs.nosh_build_dns_ingress, target.fd);
    link_error = links[5] ? libbpf_get_error(links[5]) :
      -(errno ? errno : EINVAL);
    if (link_error) {
      links[5] = NULL;
      snprintf(error_message, sizeof(error_message),
               "cannot attach UDP DNS response program: %s",
               strerror((int)-link_error));
      emit_status(status_stream, "error", &target, attached_programs,
                  options->depth, error_message);
      goto cleanup;
    }
    attached_programs++;
  }

  if (context.policy_depth) {
    if (attach_program(skeleton->progs.nosh_build_file_open, &links[6],
                       "file-open", status_stream, &target,
                       attached_programs, options->depth) != 0)
      goto cleanup;
    attached_programs++;
  }

  if (emit_capabilities(&context, options->depth) != 0 ||
      emit_stats_json(&context, false) != 0 ||
      emit_status(status_stream, "ready", &target, attached_programs,
                  options->depth,
                  context.process_depth ?
                    "process observer attached; successful execs are recorded without argv" :
                  context.policy_depth ?
                    "policy process, syscall, UDP DNS query/response, and file programs attached" :
                    "balanced process, syscall, and UDP DNS query/response programs attached")
        != 0)
    goto cleanup;

  if (options->stats_interval_ms) {
    next_stats_ms = monotonic_ms();
    if (next_stats_ms < 0)
      runtime_error = EIO;
    else
      next_stats_ms += options->stats_interval_ms;
  }

  while (!stop_requested && !runtime_error) {
    int poll_timeout_ms = 1000;
    int poll_result;

    if (options->stats_interval_ms) {
      int64_t now_ms = monotonic_ms();
      int64_t remaining_ms;

      if (now_ms < 0) {
        runtime_error = EIO;
        break;
      }
      if (now_ms >= next_stats_ms) {
        if (sample_clock_offset(&context.realtime_minus_monotonic_ns) != 0 ||
            emit_stats_json(&context, false) != 0) {
          runtime_error = EIO;
          break;
        }
        next_stats_ms = now_ms + options->stats_interval_ms;
      }
      remaining_ms = next_stats_ms - now_ms;
      if (remaining_ms < poll_timeout_ms)
        poll_timeout_ms = remaining_ms > 0 ? (int)remaining_ms : 0;
    }

    poll_result = ring_buffer__poll(ring, poll_timeout_ms);
    if (poll_result < 0 && poll_result != -EINTR) {
      runtime_error = -poll_result;
      break;
    }
    if (context.output_failed) {
      runtime_error = EIO;
      break;
    }
  }

  if (evidence_file_limit_reached)
    runtime_error = EFBIG;

  emit_status(status_stream, "stopping", &target, attached_programs,
              options->depth,
              evidence_file_limit_reached ?
              "evidence file-size limit reached; detaching" :
              runtime_error ? "collector error; detaching" :
              "termination requested; detaching");
  if (evidence_file_limit_reached)
    runtime_error = EFBIG;
  if (destroy_links(links) != 0 && !runtime_error)
    runtime_error = EIO;
  attached_programs = 0;

  if (!context.output_failed && !runtime_error) {
    int consume_result;

    do {
      consume_result = ring_buffer__consume(ring);
    } while (consume_result > 0 && !context.output_failed);
    if (consume_result < 0 && consume_result != -EINTR)
      runtime_error = -consume_result;
    if (!runtime_error) {
      if ((!context.process_depth &&
           (emit_syscall_summaries(&context) != 0 ||
            emit_file_summaries(&context) != 0)) ||
          emit_stats_json(&context, true) != 0)
        runtime_error = EIO;
    }
  } else if (context.output_failed && !runtime_error) {
    runtime_error = EIO;
  }
  if (evidence_file_limit_reached)
    runtime_error = EFBIG;

  if (runtime_error) {
    snprintf(error_message, sizeof(error_message),
             "collector stopped with error: %s", strerror(runtime_error));
    emit_status(status_stream, "error", &target, 0, options->depth,
                error_message);
  } else {
    int status_result = emit_status(
      status_stream, "stopped", &target, 0, options->depth,
      context.process_depth ?
        "final process-observer stats emitted; link detached" :
      context.policy_depth ?
        "syscall and file summaries plus final stats emitted; links detached" :
        "syscall summaries and final stats emitted; links detached");

    if (status_result == 0 && !evidence_file_limit_reached)
      exit_status = 0;
  }

cleanup:
  (void)destroy_links(links);
  if (ring)
    ring_buffer__free(ring);
  free(context.per_cpu_values);
  free(context.per_cpu_syscall_values);
  if (skeleton)
    nosh_build_bpf__destroy(skeleton);
  if (target.fd >= 0)
    close(target.fd);
  libbpf_status_stream = NULL;
  fclose(status_stream);
  return exit_status;
}

int main(int argc, char **argv)
{
  struct loader_options options;
  pid_t expected_parent_pid = getppid();

  if (parse_options(argc, argv, &options) != 0) {
    usage(stderr, argv[0]);
    return 2;
  }
  if (!strcmp(options.command, "help")) {
    usage(stdout, argv[0]);
    return 0;
  }
  if (!strcmp(options.command, "version")) {
    printf("nosh-build-loader %s schema %d process balanced policy udp-dns file-open\n",
           NOSH_BUILD_LOADER_VERSION, NOSH_BUILD_SCHEMA_VERSION);
    return 0;
  }
  if (!strcmp(options.command, "health"))
    return run_health(&options);
  if (!strcmp(options.command, "verify"))
    return run_verifier_probe(&options);
  return run_loader(&options, expected_parent_pid);
}
