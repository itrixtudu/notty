// SPDX-License-Identifier: 0BSD OR GPL-2.0-only

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
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

#include "nosh_l4.h"
#include "nosh_l4.skel.h"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#define NOSH_L4_LOADER_VERSION "1"
#define NOSH_L4_DEFAULT_STATS_INTERVAL_MS 5000
#define NOSH_L4_MIN_STATS_INTERVAL_MS 100
#define NOSH_L4_MAX_STATS_INTERVAL_MS 3600000
#define NOSH_L4_PROGRAM_COUNT 6
#define NOSH_L4_FILE_HANDLE_BYTES 128
#define NOSH_L4_EVIDENCE_FILE_LIMIT_BYTES (128ULL * 1024ULL * 1024ULL)
/* The retained head, marker, and tail fit the adapter's 2048-char summary. */
#define NOSH_L4_LIBBPF_LOG_HEAD_BYTES 512
#define NOSH_L4_LIBBPF_LOG_TAIL_BYTES 1408
#define NOSH_L4_LIBBPF_LOG_MARKER_BYTES 128

static volatile sig_atomic_t stop_requested;
static volatile sig_atomic_t evidence_file_limit_reached;
static FILE *libbpf_status_stream;
static const char *loader_output_mode = "events";

struct loader_options {
  const char *command;
  const char *cgroup_path;
  const char *output_mode;
  __u64 expected_cgroup_id;
  bool expected_cgroup_id_set;
  unsigned int stats_interval_ms;
  bool stats_interval_set;
  int status_fd;
  bool status_fd_set;
  bool output_mode_set;
};

struct cgroup_target {
  int fd;
  __u64 id;
  char path[PATH_MAX];
};

struct loader_context {
  FILE *event_stream;
  int stats_map_fd;
  int flow_map_fd;
  int owner_map_fd;
  int possible_cpus;
  __u64 *per_cpu_values;
  __u64 cgroup_id;
  int64_t realtime_minus_monotonic_ns;
  __u64 events_seen;
  __u64 decoder_errors;
  __u64 flow_summaries_emitted;
  bool flow_summary_mode;
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
                       const char *message)
{
  fprintf(stream,
          "{\"schemaVersion\":1,\"recordKind\":\"status\","
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
  fprintf(stream, ",\"attachedPrograms\":%d,\"outputMode\":",
          attached_programs);
  write_json_string(stream, loader_output_mode, strlen(loader_output_mode));
  fputs(",\"message\":", stream);
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
          "{\"schemaVersion\":1,\"recordKind\":\"diagnostic\","
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
  char head[NOSH_L4_LIBBPF_LOG_HEAD_BYTES];
  char tail[NOSH_L4_LIBBPF_LOG_TAIL_BYTES];
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
  char marker[NOSH_L4_LIBBPF_LOG_MARKER_BYTES];
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

  message = malloc(NOSH_L4_LIBBPF_LOG_HEAD_BYTES +
                   NOSH_L4_LIBBPF_LOG_TAIL_BYTES +
                   NOSH_L4_LIBBPF_LOG_MARKER_BYTES + 1);
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
  const rlim_t cap = (rlim_t)NOSH_L4_EVIDENCE_FILE_LIMIT_BYTES;
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
          " [--output-mode events|flow-summary]\n"
          "  %s run --cgroup ABSOLUTE_PATH [--cgroup-id UINT64]\\\n"
          "      [--output-mode events|flow-summary]"
          " [--stats-interval-ms 0|%d..%d] [--status-fd FD]\n"
          "  %s --version\n"
          "\n"
          "events is the runtime default; flow-summary emits attempts live "
          "and bounded flow totals at shutdown.\n"
          "run writes only evidence and cumulative stats JSONL to stdout.\n"
          "Readiness and diagnostics use stderr unless --status-fd is set.\n",
          program, program, NOSH_L4_MIN_STATS_INTERVAL_MS,
          NOSH_L4_MAX_STATS_INTERVAL_MS, program);
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
  options->output_mode = "events";
  options->stats_interval_ms = NOSH_L4_DEFAULT_STATS_INTERVAL_MS;
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
    if (!strcmp(argument, "--output-mode")) {
      if (++index >= argc || options->output_mode_set ||
          (strcmp(argv[index], "events") &&
           strcmp(argv[index], "flow-summary")))
        return -1;
      options->output_mode = argv[index];
      options->output_mode_set = true;
      continue;
    }
    if (!strcmp(argument, "--stats-interval-ms")) {
      if (++index >= argc || options->stats_interval_set ||
          parse_uint(argv[index], &options->stats_interval_ms) != 0 ||
          options->stats_interval_ms > NOSH_L4_MAX_STATS_INTERVAL_MS ||
          (options->stats_interval_ms &&
           options->stats_interval_ms < NOSH_L4_MIN_STATS_INTERVAL_MS))
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
  return 0;
}

static int cgroup_id_from_fd(int cgroup_fd,
                             __u64 *cgroup_id,
                             char *error,
                             size_t error_size)
{
  struct file_handle *handle;
  size_t allocation_size =
    sizeof(struct file_handle) + NOSH_L4_FILE_HANDLE_BYTES;
  int mount_id = 0;
  int result = -1;

  handle = calloc(1, allocation_size);
  if (!handle) {
    snprintf(error, error_size, "cannot allocate cgroup file handle");
    return -1;
  }
  handle->handle_bytes = NOSH_L4_FILE_HANDLE_BYTES;

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
    snprintf(error, error_size,
             "an absolute --cgroup path is required");
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
    snprintf(error, error_size,
             "%s is not a cgroup v2 directory", options->cgroup_path);
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
  bool btf_ok = access("/sys/kernel/btf/vmlinux", R_OK) == 0;
  bool cgroup_v2_ok = path_is_cgroup_v2("/sys/fs/cgroup");
  bool target_ok = true;
  bool healthy;

  if (options->cgroup_path)
    target_ok = resolve_cgroup_target(options, &target,
                                      error, sizeof(error)) == 0;
  healthy = effective_root && kernel_ok && btf_ok &&
            cgroup_v2_ok && target_ok;

  fprintf(stdout,
          "{\"schemaVersion\":1,\"recordKind\":\"status\","
          "\"timestampUnixNs\":\"%" PRIu64 "\",\"status\":\"%s\","
          "\"pid\":%ld,\"cgroupPath\":",
          (uint64_t)realtime_ns(),
          healthy ? "healthy" : "unhealthy", (long)getpid());
  write_nullable_json_string(stdout,
                             target.fd >= 0 ? target.path :
                             options->cgroup_path);
  fputs(",\"cgroupId\":", stdout);
  if (target.fd >= 0)
    fprintf(stdout, "\"%" PRIu64 "\"", (uint64_t)target.id);
  else
    fputs("null", stdout);
  fputs(",\"attachedPrograms\":0,\"outputMode\":", stdout);
  write_json_string(stdout, options->output_mode,
                    strlen(options->output_mode));
  fputs(",\"message\":", stdout);
  write_json_string(stdout,
                    healthy ? "host prerequisites satisfied" :
                    (error[0] ? error : "host prerequisites are incomplete"),
                    strlen(healthy ? "host prerequisites satisfied" :
                           (error[0] ? error :
                            "host prerequisites are incomplete")));
  fprintf(stdout,
          ",\"checks\":{\"effectiveRoot\":%s,"
          "\"kernelAtLeast5_8\":%s,\"kernelBtf\":%s,"
          "\"cgroupV2\":%s,\"targetCgroup\":%s}}\n",
          effective_root ? "true" : "false",
          kernel_ok ? "true" : "false",
          btf_ok ? "true" : "false",
          cgroup_v2_ok ? "true" : "false",
          target_ok ? "true" : "false");

  if (target.fd >= 0)
    close(target.fd);
  if (fflush(stdout) != 0)
    return 1;
  return healthy ? 0 : 1;
}

static const char *event_kind_name(__u8 event_kind)
{
  switch (event_kind) {
    case NOSH_L4_EVENT_ATTEMPT:
      return "attempt";
    case NOSH_L4_EVENT_PACKET:
      return "packet";
    default:
      return NULL;
  }
}

static const char *hook_name(__u8 hook)
{
  switch (hook) {
    case NOSH_L4_HOOK_CONNECT4:
      return "connect4";
    case NOSH_L4_HOOK_CONNECT6:
      return "connect6";
    case NOSH_L4_HOOK_SENDMSG4:
      return "sendmsg4";
    case NOSH_L4_HOOK_SENDMSG6:
      return "sendmsg6";
    case NOSH_L4_HOOK_INGRESS:
      return "ingress";
    case NOSH_L4_HOOK_EGRESS:
      return "egress";
    default:
      return NULL;
  }
}

static const char *operation_name(__u8 operation)
{
  switch (operation) {
    case NOSH_L4_OPERATION_CONNECT:
      return "connect";
    case NOSH_L4_OPERATION_SENDMSG:
      return "sendmsg";
    case NOSH_L4_OPERATION_PACKET:
      return "packet";
    default:
      return NULL;
  }
}

static const char *direction_name(const struct nosh_l4_event *event)
{
  if (event->direction == NOSH_L4_DIRECTION_INGRESS)
    return "ingress";
  if (event->direction == NOSH_L4_DIRECTION_EGRESS)
    return "egress";
  if (event->event_kind == NOSH_L4_EVENT_ATTEMPT)
    return "egress";
  return NULL;
}

static const char *family_name(__u8 family)
{
  if (family == NOSH_L4_FAMILY_IPV4)
    return "ipv4";
  if (family == NOSH_L4_FAMILY_IPV6)
    return "ipv6";
  return NULL;
}

static const char *protocol_name(__u8 protocol)
{
  switch (protocol) {
    case NOSH_L4_PROTOCOL_TCP:
      return "tcp";
    case NOSH_L4_PROTOCOL_UDP:
      return "udp";
    case NOSH_L4_PROTOCOL_ICMP:
      return "icmp";
    case NOSH_L4_PROTOCOL_ICMPV6:
      return "icmpv6";
    default:
      return NULL;
  }
}

static const char *owner_source_name(__u8 owner_source)
{
  if (owner_source == NOSH_L4_OWNER_CURRENT_TASK)
    return "current-task";
  if (owner_source == NOSH_L4_OWNER_SOCKET_COOKIE_CACHE)
    return "socket-cookie-cache";
  return NULL;
}

static bool bytes_are_zero(const __u8 *bytes, size_t length)
{
  size_t index;

  for (index = 0; index < length; index++) {
    if (bytes[index])
      return false;
  }
  return true;
}

static int write_address(FILE *stream,
                         __u8 family,
                         const __u8 address[NOSH_L4_ADDRESS_LEN],
                         bool null_when_zero)
{
  char text[INET6_ADDRSTRLEN];
  int address_family =
    family == NOSH_L4_FAMILY_IPV4 ? AF_INET : AF_INET6;
  size_t address_length =
    family == NOSH_L4_FAMILY_IPV4 ? 4 : NOSH_L4_ADDRESS_LEN;

  if (null_when_zero && bytes_are_zero(address, address_length)) {
    fputs("null", stream);
    return 0;
  }
  if (!inet_ntop(address_family, address, text, sizeof(text)))
    return -1;
  write_json_string(stream, text, strlen(text));
  return 0;
}

static void write_nullable_port(FILE *stream,
                                const struct nosh_l4_event *event,
                                __u16 port)
{
  if ((event->protocol != NOSH_L4_PROTOCOL_TCP &&
       event->protocol != NOSH_L4_PROTOCOL_UDP) ||
      (event->flags & NOSH_L4_F_L4_UNAVAILABLE) || !port) {
    fputs("null", stream);
    return;
  }
  fprintf(stream, "%u", port);
}

static void write_nullable_icmp(FILE *stream,
                                const struct nosh_l4_event *event,
                                __u8 value)
{
  if ((event->protocol != NOSH_L4_PROTOCOL_ICMP &&
       event->protocol != NOSH_L4_PROTOCOL_ICMPV6) ||
      (event->flags & NOSH_L4_F_L4_UNAVAILABLE)) {
    fputs("null", stream);
    return;
  }
  fprintf(stream, "%u", value);
}

static void write_flags(FILE *stream, __u16 flags)
{
  bool first = true;

  fputc('[', stream);
#define WRITE_FLAG(flag, name)                       \
  do {                                               \
    if (flags & (flag)) {                            \
      if (!first)                                    \
        fputc(',', stream);                          \
      write_json_string(stream, (name), strlen(name)); \
      first = false;                                 \
    }                                                \
  } while (0)
  WRITE_FLAG(NOSH_L4_F_OBSERVED_ONLY, "observed-only");
  WRITE_FLAG(NOSH_L4_F_COMPLETION_UNKNOWN, "completion-unknown");
  WRITE_FLAG(NOSH_L4_F_FRAGMENT, "fragment");
  WRITE_FLAG(NOSH_L4_F_L4_UNAVAILABLE, "l4-unavailable");
#undef WRITE_FLAG
  fputc(']', stream);
}

static int observed_timestamp(const struct loader_context *context,
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

static bool event_is_valid(const struct nosh_l4_event *event,
                           size_t data_size)
{
  const __u16 known_flags =
    NOSH_L4_F_OBSERVED_ONLY |
    NOSH_L4_F_COMPLETION_UNKNOWN |
    NOSH_L4_F_L4_UNAVAILABLE |
    NOSH_L4_F_FRAGMENT;

  if (data_size != sizeof(*event) ||
      event->schema_version != NOSH_L4_SCHEMA_VERSION ||
      event->event_size != sizeof(*event) ||
      !event_kind_name(event->event_kind) ||
      !hook_name(event->hook) ||
      !operation_name(event->operation) ||
      !direction_name(event) ||
      !family_name(event->family) ||
      !protocol_name(event->protocol) ||
      event->verdict != NOSH_L4_VERDICT_ALLOW ||
      event->hook_return != NOSH_L4_ALLOW ||
      !(event->flags & NOSH_L4_F_OBSERVED_ONLY) ||
      (event->flags & ~known_flags))
    return false;

  if (event->event_kind == NOSH_L4_EVENT_ATTEMPT) {
    if (event->hook < NOSH_L4_HOOK_CONNECT4 ||
        event->hook > NOSH_L4_HOOK_SENDMSG6 ||
        (event->operation != NOSH_L4_OPERATION_CONNECT &&
         event->operation != NOSH_L4_OPERATION_SENDMSG) ||
        (event->protocol != NOSH_L4_PROTOCOL_TCP &&
         event->protocol != NOSH_L4_PROTOCOL_UDP) ||
        event->direction != NOSH_L4_DIRECTION_EGRESS ||
        event->owner_source != NOSH_L4_OWNER_CURRENT_TASK ||
        !(event->flags & NOSH_L4_F_COMPLETION_UNKNOWN))
      return false;
    if ((event->hook == NOSH_L4_HOOK_CONNECT4 &&
         event->operation != NOSH_L4_OPERATION_CONNECT) ||
        (event->hook == NOSH_L4_HOOK_CONNECT6 &&
         event->operation != NOSH_L4_OPERATION_CONNECT) ||
        (event->hook == NOSH_L4_HOOK_SENDMSG4 &&
         event->operation != NOSH_L4_OPERATION_SENDMSG) ||
        (event->hook == NOSH_L4_HOOK_SENDMSG6 &&
         event->operation != NOSH_L4_OPERATION_SENDMSG))
      return false;
  } else if (event->hook != NOSH_L4_HOOK_INGRESS &&
             event->hook != NOSH_L4_HOOK_EGRESS) {
    return false;
  } else if (event->operation != NOSH_L4_OPERATION_PACKET ||
             event->owner_source == NOSH_L4_OWNER_CURRENT_TASK ||
             (event->owner_source != NOSH_L4_OWNER_UNKNOWN &&
              event->owner_source !=
                NOSH_L4_OWNER_SOCKET_COOKIE_CACHE) ||
             (event->flags & NOSH_L4_F_COMPLETION_UNKNOWN) ||
             (event->hook == NOSH_L4_HOOK_INGRESS &&
              event->direction != NOSH_L4_DIRECTION_INGRESS) ||
             (event->hook == NOSH_L4_HOOK_EGRESS &&
              event->direction != NOSH_L4_DIRECTION_EGRESS)) {
    return false;
  }

  if ((event->family == NOSH_L4_FAMILY_IPV4 &&
       (event->hook == NOSH_L4_HOOK_CONNECT6 ||
        event->hook == NOSH_L4_HOOK_SENDMSG6 ||
        event->protocol == NOSH_L4_PROTOCOL_ICMPV6)) ||
      (event->family == NOSH_L4_FAMILY_IPV6 &&
       (event->hook == NOSH_L4_HOOK_CONNECT4 ||
        event->hook == NOSH_L4_HOOK_SENDMSG4 ||
        event->protocol == NOSH_L4_PROTOCOL_ICMP)))
    return false;
  return true;
}

static int emit_event_json(struct loader_context *context,
                           const struct nosh_l4_event *event)
{
  FILE *stream = context->event_stream;
  const char *kind = event_kind_name(event->event_kind);
  const char *hook = hook_name(event->hook);
  const char *direction = direction_name(event);
  const char *family = family_name(event->family);
  const char *protocol = protocol_name(event->protocol);
  const char *owner_source = owner_source_name(event->owner_source);
  const char *operation = operation_name(event->operation);
  size_t comm_length = strnlen(event->comm, sizeof(event->comm));
  uint64_t timestamp_ns;

  if (observed_timestamp(context, event->timestamp_ns,
                         &timestamp_ns) != 0)
    return -1;

  fprintf(stream,
          "{\"schemaVersion\":1,\"metadataOnly\":true,"
          "\"eventKind\":\"%s\",\"hook\":\"%s\","
          "\"timestampNs\":\"%" PRIu64 "\","
          "\"cgroupId\":\"%" PRIu64 "\","
          "\"socketCookie\":\"%" PRIu64 "\",\"network\":{"
          "\"direction\":\"%s\",\"family\":\"%s\","
          "\"protocol\":\"%s\",\"sourceAddress\":",
          kind, hook, timestamp_ns,
          (uint64_t)event->cgroup_id, (uint64_t)event->socket_cookie,
          direction, family, protocol);
  if (write_address(stream, event->family, event->source_address,
                    event->event_kind == NOSH_L4_EVENT_ATTEMPT) != 0)
    return -1;
  fputs(",\"destinationAddress\":", stream);
  if (write_address(stream, event->family, event->destination_address,
                    false) != 0)
    return -1;
  fputs(",\"sourcePort\":", stream);
  write_nullable_port(stream, event, event->source_port);
  fputs(",\"destinationPort\":", stream);
  write_nullable_port(stream, event, event->destination_port);
  fputs(",\"icmpType\":", stream);
  write_nullable_icmp(stream, event, event->icmp_type);
  fputs(",\"icmpCode\":", stream);
  write_nullable_icmp(stream, event, event->icmp_code);
  fprintf(stream, ",\"ifindex\":%u},\"process\":", event->ifindex);

  if (!owner_source) {
    fputs("null", stream);
  } else {
    fprintf(stream,
            "{\"attribution\":\"%s\",\"pid\":%u,\"tid\":%u,"
            "\"uid\":%u,\"gid\":%u,\"comm\":",
            owner_source, event->pid, event->tid, event->uid, event->gid);
    write_json_string(stream, event->comm, comm_length);
    fputc('}', stream);
  }

  fputs(",\"sensorDecision\":{\"verdict\":\"allow\","
        "\"observedOnly\":true,\"hookReturn\":1},\"attempt\":", stream);
  if (event->event_kind == NOSH_L4_EVENT_ATTEMPT) {
    fprintf(stream,
            "{\"operation\":\"%s\",\"completionKnown\":false}",
            operation);
  } else {
    fputs("null", stream);
  }
  fputs(",\"accounting\":", stream);
  if (event->event_kind == NOSH_L4_EVENT_PACKET) {
    fprintf(stream,
            "{\"scope\":\"running-flow-total\",\"packetBytes\":%u,"
            "\"packets\":\"%" PRIu64 "\",\"bytes\":\"%" PRIu64 "\"}",
            event->packet_len, (uint64_t)event->packets,
            (uint64_t)event->bytes);
  } else {
    fputs("null", stream);
  }
  fputs(",\"flags\":", stream);
  write_flags(stream, event->flags);
  fputs("}\n", stream);
  return fflush(stream) == 0 ? 0 : -1;
}

static int handle_ring_event(void *opaque, void *data, size_t data_size)
{
  struct loader_context *context = opaque;
  const struct nosh_l4_event *event = data;

  if (!event_is_valid(event, data_size) ||
      event->cgroup_id != context->cgroup_id) {
    context->decoder_errors++;
    return 0;
  }
  if (context->flow_summary_mode &&
      event->event_kind == NOSH_L4_EVENT_PACKET) {
    context->decoder_errors++;
    return 0;
  }
  if (emit_event_json(context, event) != 0) {
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

static int read_stat(struct loader_context *context,
                     enum nosh_l4_stat stat,
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

static int emit_stats_json(struct loader_context *context, bool final)
{
  __u64 counters[NOSH_L4_STAT_MAX] = {};
  int stat;

  for (stat = 0; stat < NOSH_L4_STAT_MAX; stat++) {
    if (read_stat(context, stat, &counters[stat]) != 0)
      return -1;
  }

  fprintf(context->event_stream,
          "{\"schemaVersion\":1,\"recordKind\":\"stats\","
          "\"timestampUnixNs\":\"%" PRIu64 "\","
          "\"cgroupId\":\"%" PRIu64 "\",\"final\":%s,"
          "\"outputMode\":\"%s\","
          "\"eventsSeen\":\"%" PRIu64 "\","
          "\"decoderErrors\":\"%" PRIu64 "\","
          "\"flowSummaryRecords\":\"%" PRIu64 "\",\"counters\":{"
          "\"ringbufDrops\":\"%" PRIu64 "\","
          "\"parseErrors\":\"%" PRIu64 "\","
          "\"unsupportedProtocol\":\"%" PRIu64 "\","
          "\"flowMapFull\":\"%" PRIu64 "\","
          "\"configMissing\":\"%" PRIu64 "\"}}\n",
          (uint64_t)realtime_ns(), (uint64_t)context->cgroup_id,
          final ? "true" : "false",
          context->flow_summary_mode ? "flow-summary" : "events",
          (uint64_t)context->events_seen,
          (uint64_t)context->decoder_errors,
          (uint64_t)context->flow_summaries_emitted,
          (uint64_t)counters[NOSH_L4_STAT_RINGBUF_DROPS],
          (uint64_t)counters[NOSH_L4_STAT_PARSE_ERRORS],
          (uint64_t)counters[NOSH_L4_STAT_UNSUPPORTED_PROTOCOL],
          (uint64_t)counters[NOSH_L4_STAT_FLOW_MAP_FULL],
          (uint64_t)counters[NOSH_L4_STAT_CONFIG_MISSING]);
  if (fflush(context->event_stream) != 0) {
    context->output_failed = true;
    return -1;
  }
  return 0;
}

static bool flow_key_is_valid(const struct loader_context *context,
                              const struct nosh_l4_flow_key *key)
{
  const __u8 known_flags = NOSH_L4_F_L4_UNAVAILABLE |
    NOSH_L4_F_FRAGMENT;

  return key->cgroup_id == context->cgroup_id &&
    (key->direction == NOSH_L4_DIRECTION_INGRESS ||
     key->direction == NOSH_L4_DIRECTION_EGRESS) &&
    family_name(key->family) && protocol_name(key->protocol) &&
    !(key->flags & ~known_flags);
}

static int emit_flow_summary(struct loader_context *context,
                             const struct nosh_l4_flow_key *key,
                             const struct nosh_l4_flow_totals *totals)
{
  struct nosh_l4_process owner = {};
  struct nosh_l4_event descriptor = {};
  bool have_owner = false;
  size_t comm_length = 0;
  uint64_t first_observed_ns;
  uint64_t last_observed_ns;
  FILE *stream = context->event_stream;

  if (!flow_key_is_valid(context, key) || !totals->packets ||
      !totals->first_seen_ns || !totals->last_seen_ns ||
      totals->first_seen_ns > totals->last_seen_ns ||
      observed_timestamp(context, totals->first_seen_ns,
                         &first_observed_ns) != 0 ||
      observed_timestamp(context, totals->last_seen_ns,
                         &last_observed_ns) != 0)
    return -1;
  if (key->socket_cookie &&
      bpf_map_lookup_elem(context->owner_map_fd,
                          &key->socket_cookie, &owner) == 0) {
    comm_length = strnlen(owner.comm, sizeof(owner.comm));
    if (comm_length == sizeof(owner.comm))
      return -1;
    have_owner = true;
  }

  descriptor.family = key->family;
  descriptor.protocol = key->protocol;
  descriptor.flags = NOSH_L4_F_OBSERVED_ONLY | key->flags;
  descriptor.event_kind = NOSH_L4_EVENT_PACKET;
  fprintf(stream,
          "{\"schemaVersion\":1,\"recordKind\":\"flow-summary\","
          "\"metadataOnly\":true,"
          "\"timestampUnixNs\":\"%" PRIu64 "\","
          "\"firstObservedNs\":\"%" PRIu64 "\","
          "\"lastObservedNs\":\"%" PRIu64 "\","
          "\"cgroupId\":\"%" PRIu64 "\","
          "\"socketCookie\":\"%" PRIu64 "\",\"network\":{"
          "\"direction\":\"%s\",\"family\":\"%s\","
          "\"protocol\":\"%s\",\"sourceAddress\":",
          (uint64_t)realtime_ns(), first_observed_ns, last_observed_ns,
          (uint64_t)key->cgroup_id, (uint64_t)key->socket_cookie,
          key->direction == NOSH_L4_DIRECTION_INGRESS ? "ingress" : "egress",
          family_name(key->family), protocol_name(key->protocol));
  if (write_address(stream, key->family, key->source_address, false) != 0)
    return -1;
  fputs(",\"destinationAddress\":", stream);
  if (write_address(stream, key->family,
                    key->destination_address, false) != 0)
    return -1;
  fputs(",\"sourcePort\":", stream);
  write_nullable_port(stream, &descriptor, key->source_port);
  fputs(",\"destinationPort\":", stream);
  write_nullable_port(stream, &descriptor, key->destination_port);
  fputs(",\"icmpType\":", stream);
  write_nullable_icmp(stream, &descriptor, key->icmp_type);
  fputs(",\"icmpCode\":", stream);
  write_nullable_icmp(stream, &descriptor, key->icmp_code);
  fprintf(stream, ",\"ifindex\":%u},\"process\":", key->ifindex);
  if (!have_owner) {
    fputs("null", stream);
  } else {
    fprintf(stream,
            "{\"attribution\":\"socket-cookie-cache\","
            "\"pid\":%u,\"tid\":%u,\"uid\":%u,\"gid\":%u,\"comm\":",
            owner.pid, owner.tid, owner.uid, owner.gid);
    write_json_string(stream, owner.comm, comm_length);
    fputc('}', stream);
  }
  fprintf(stream,
          ",\"accounting\":{\"scope\":\"capture-flow-total\","
          "\"packets\":\"%" PRIu64 "\",\"bytes\":\"%" PRIu64 "\"},"
          "\"flags\":",
          (uint64_t)totals->packets, (uint64_t)totals->bytes);
  write_flags(stream, descriptor.flags);
  fputs("}\n", stream);
  return fflush(stream) == 0 ? 0 : -1;
}

static int emit_flow_summaries(struct loader_context *context)
{
  struct nosh_l4_flow_key current;
  struct nosh_l4_flow_key next;
  bool have_current = false;
  __u64 scanned = 0;

  if (!context->flow_summary_mode)
    return 0;
  while (scanned < NOSH_L4_FLOW_MAX_ENTRIES &&
         bpf_map_get_next_key(context->flow_map_fd,
                              have_current ? &current : NULL,
                              &next) == 0) {
    struct nosh_l4_flow_totals totals = {};

    if (bpf_map_lookup_elem(context->flow_map_fd, &next, &totals) != 0 ||
        emit_flow_summary(context, &next, &totals) != 0)
      return -1;
    context->flow_summaries_emitted++;
    scanned++;
    current = next;
    have_current = true;
  }
  if (scanned == NOSH_L4_FLOW_MAX_ENTRIES)
    return 0;
  return errno == ENOENT ? 0 : -1;
}

static int destroy_links(struct bpf_link *links[NOSH_L4_PROGRAM_COUNT])
{
  int index;
  int result = 0;

  for (index = NOSH_L4_PROGRAM_COUNT - 1; index >= 0; index--) {
    if (links[index]) {
      if (bpf_link__destroy(links[index]) != 0)
        result = -1;
      links[index] = NULL;
    }
  }
  return result;
}

static int set_memlock_limit(FILE *status_stream)
{
  struct rlimit limit = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &limit) == 0)
    return 0;
  emit_diagnostic(status_stream, "warning", "loader",
                  "cannot raise RLIMIT_MEMLOCK; continuing for kernels "
                  "with memcg-based BPF accounting");
  return -1;
}

static int run_loader(const struct loader_options *options,
                      pid_t expected_parent_pid)
{
  struct cgroup_target target = {.fd = -1};
  struct nosh_l4_bpf *skeleton = NULL;
  struct ring_buffer *ring = NULL;
  struct bpf_link *links[NOSH_L4_PROGRAM_COUNT] = {};
  struct bpf_program *programs[NOSH_L4_PROGRAM_COUNT];
  const char *program_names[NOSH_L4_PROGRAM_COUNT] = {
    "connect4", "connect6", "sendmsg4", "sendmsg6", "ingress", "egress",
  };
  struct loader_context context = {
    .event_stream = stdout,
  };
  struct nosh_l4_config config = {};
  FILE *status_stream = NULL;
  char error_message[512] = {};
  int status_dup = -1;
  int attached_programs = 0;
  int exit_status = 1;
  int runtime_error = 0;
  int load_result;
  int64_t next_stats_ms = 0;
  __u32 config_key = 0;
  int index;

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
    emit_status(status_stream, "error", NULL, 0,
                "cannot install signal handlers");
    goto cleanup;
  }
  if (install_evidence_file_size_limit() != 0) {
    snprintf(error_message, sizeof(error_message),
             "cannot install 128 MiB evidence file-size limit: %s",
             strerror(errno));
    emit_status(status_stream, "error", NULL, 0, error_message);
    goto cleanup;
  }
  if (arm_parent_death_signal(expected_parent_pid) != 0) {
    snprintf(error_message, sizeof(error_message),
             "cannot arm supervisor death signal: %s", strerror(errno));
    emit_status(status_stream, "error", NULL, 0, error_message);
    goto cleanup;
  }
  if (resolve_cgroup_target(options, &target,
                            error_message, sizeof(error_message)) != 0) {
    emit_status(status_stream, "error", NULL, 0, error_message);
    goto cleanup;
  }
  if (emit_status(status_stream, "starting", &target, 0,
                  "loading CO-RE programs") != 0)
    goto cleanup;

  set_memlock_limit(status_stream);
  skeleton = nosh_l4_bpf__open();
  if (!skeleton) {
    snprintf(error_message, sizeof(error_message),
             "cannot open embedded BPF skeleton: %s", strerror(errno));
    emit_status(status_stream, "error", &target, 0, error_message);
    goto cleanup;
  }
  load_result = nosh_l4_bpf__load(skeleton);
  if (load_result != 0) {
    int load_error = load_result < 0 ? -load_result : load_result;

    snprintf(error_message, sizeof(error_message),
             "cannot load BPF object: %s", strerror(load_error));
    emit_status(status_stream, "error", &target, 0, error_message);
    goto cleanup;
  }

  config.target_cgroup_id = target.id;
  config.output_mode = !strcmp(options->output_mode, "flow-summary") ?
    NOSH_L4_OUTPUT_FLOW_SUMMARY : NOSH_L4_OUTPUT_EVENTS;
  if (bpf_map_update_elem(bpf_map__fd(skeleton->maps.session_config),
                          &config_key, &config, BPF_ANY) != 0) {
    snprintf(error_message, sizeof(error_message),
             "cannot initialize target cgroup config: %s", strerror(errno));
    emit_status(status_stream, "error", &target, 0, error_message);
    goto cleanup;
  }

  context.stats_map_fd = bpf_map__fd(skeleton->maps.stats);
  context.flow_map_fd = bpf_map__fd(skeleton->maps.flow_totals);
  context.owner_map_fd = bpf_map__fd(skeleton->maps.socket_owners);
  context.possible_cpus = libbpf_num_possible_cpus();
  context.cgroup_id = target.id;
  context.flow_summary_mode =
    !strcmp(options->output_mode, "flow-summary");
  if (context.stats_map_fd < 0 || context.flow_map_fd < 0 ||
      context.owner_map_fd < 0 || context.possible_cpus <= 0 ||
      sample_clock_offset(&context.realtime_minus_monotonic_ns) != 0) {
    emit_status(status_stream, "error", &target, 0,
                "cannot initialize stats map reader");
    goto cleanup;
  }
  context.per_cpu_values = calloc((size_t)context.possible_cpus,
                                  sizeof(*context.per_cpu_values));
  if (!context.per_cpu_values) {
    emit_status(status_stream, "error", &target, 0,
                "cannot allocate per-CPU stats buffer");
    goto cleanup;
  }

  ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
                          handle_ring_event, &context, NULL);
  if (!ring) {
    snprintf(error_message, sizeof(error_message),
             "cannot open event ring buffer: %s", strerror(errno));
    emit_status(status_stream, "error", &target, 0, error_message);
    goto cleanup;
  }

  programs[0] = skeleton->progs.nosh_l4_connect4;
  programs[1] = skeleton->progs.nosh_l4_connect6;
  programs[2] = skeleton->progs.nosh_l4_sendmsg4;
  programs[3] = skeleton->progs.nosh_l4_sendmsg6;
  programs[4] = skeleton->progs.nosh_l4_ingress;
  programs[5] = skeleton->progs.nosh_l4_egress;

  for (index = 0; index < NOSH_L4_PROGRAM_COUNT; index++) {
    long link_error;

    links[index] = bpf_program__attach_cgroup(programs[index], target.fd);
    link_error = links[index] ? libbpf_get_error(links[index]) :
      -(errno ? errno : EINVAL);
    if (link_error) {
      links[index] = NULL;
      snprintf(error_message, sizeof(error_message),
               "cannot attach %s program: %s",
               program_names[index], strerror((int)-link_error));
      emit_status(status_stream, "error", &target,
                  attached_programs, error_message);
      goto cleanup;
    }
    attached_programs++;
  }

  if (emit_status(status_stream, "ready", &target, attached_programs,
                  context.flow_summary_mode ?
                    "all cgroup programs attached; attempts plus flow summaries enabled" :
                    "all cgroup programs attached; event output enabled") != 0)
    goto cleanup;
  if (emit_stats_json(&context, false) != 0) {
    emit_status(status_stream, "error", &target, attached_programs,
                "cannot emit initial loss stats");
    goto cleanup;
  }

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
        if (sample_clock_offset(
              &context.realtime_minus_monotonic_ns) != 0 ||
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
    if (emit_flow_summaries(&context) != 0 ||
        emit_stats_json(&context, true) != 0)
      runtime_error = EIO;
  } else if (context.output_failed && !runtime_error) {
    runtime_error = EIO;
  }
  if (evidence_file_limit_reached)
    runtime_error = EFBIG;

  if (runtime_error) {
    snprintf(error_message, sizeof(error_message),
             "collector stopped with error: %s", strerror(runtime_error));
    emit_status(status_stream, "error", &target, 0, error_message);
  } else {
    int status_result = emit_status(
      status_stream, "stopped", &target, 0,
      context.flow_summary_mode ?
        "flow summaries and final stats emitted; links detached" :
        "final stats emitted and links detached");

    if (status_result == 0 && !evidence_file_limit_reached)
      exit_status = 0;
  }

cleanup:
  (void)destroy_links(links);
  if (ring)
    ring_buffer__free(ring);
  free(context.per_cpu_values);
  if (skeleton)
    nosh_l4_bpf__destroy(skeleton);
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
  loader_output_mode = options.output_mode;
  if (!strcmp(options.command, "help")) {
    usage(stdout, argv[0]);
    return 0;
  }
  if (!strcmp(options.command, "version")) {
    printf("nosh-l4-loader %s schema %d\n",
           NOSH_L4_LOADER_VERSION, NOSH_L4_SCHEMA_VERSION);
    return 0;
  }
  if (!strcmp(options.command, "health"))
    return run_health(&options);
  return run_loader(&options, expected_parent_pid);
}
