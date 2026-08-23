// SPDX-License-Identifier: 0BSD

#ifndef NOSH_URL_SANITIZER_H
#define NOSH_URL_SANITIZER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nosh_url.h"

#define NOSH_URL_SCHEME_MAX 32
#define NOSH_URL_HOST_MAX 253
#define NOSH_URL_SANITIZED_PATH_MAX NOSH_URL_PATH_MAX

struct nosh_url_sanitized {
  char scheme[NOSH_URL_SCHEME_MAX + 1];
  char host[NOSH_URL_HOST_MAX + 1];
  char path[NOSH_URL_SANITIZED_PATH_MAX + 1];
  uint16_t port;
  bool path_truncated;
};

enum nosh_url_sanitize_result {
  NOSH_URL_SANITIZE_OK = 0,
  NOSH_URL_SANITIZE_INVALID = 1,
  NOSH_URL_SANITIZE_NO_EFFECTIVE_PORT = 2,
};

enum nosh_url_sanitize_result
nosh_url_sanitize(const char *raw,
                  size_t raw_length,
                  struct nosh_url_sanitized *result);

#endif
