// SPDX-License-Identifier: 0BSD

#include "url_sanitizer.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct nosh_url_sanitized sanitize(const char *value)
{
  struct nosh_url_sanitized result;

  assert(nosh_url_sanitize(value, strlen(value), &result) ==
         NOSH_URL_SANITIZE_OK);
  return result;
}

int main(void)
{
  struct nosh_url_sanitized result;
  char long_url[700];

  result = sanitize(
    "HTTPS://User:Secret@GitHub.COM:8443/org/repo?token=secret#fragment");
  assert(!strcmp(result.scheme, "https"));
  assert(!strcmp(result.host, "github.com"));
  assert(result.port == 8443);
  assert(!strcmp(result.path, "/org/repo"));
  assert(!result.path_truncated);
  assert(!strstr(result.path, "token"));
  assert(!strstr(result.host, "User"));

  result = sanitize("http://EXAMPLE.com?secret=yes");
  assert(!strcmp(result.scheme, "http"));
  assert(!strcmp(result.host, "example.com"));
  assert(result.port == 80);
  assert(!strcmp(result.path, "/"));

  result = sanitize("https://[2001:0DB8:0:0::1]/index.html#private");
  assert(!strcmp(result.host, "[2001:db8::1]"));
  assert(result.port == 443);
  assert(!strcmp(result.path, "/index.html"));

  result = sanitize("custom+tls://Service.INTERNAL:9443/api/v1");
  assert(!strcmp(result.scheme, "custom+tls"));
  assert(!strcmp(result.host, "service.internal"));
  assert(result.port == 9443);
  assert(!strcmp(result.path, "/api/v1"));

  memset(long_url, 'a', sizeof(long_url));
  memcpy(long_url, "https://example.com/", strlen("https://example.com/"));
  long_url[sizeof(long_url) - 1] = '\0';
  result = sanitize(long_url);
  assert(strlen(result.path) == NOSH_URL_SANITIZED_PATH_MAX);
  assert(result.path_truncated);

  assert(nosh_url_sanitize("file:///etc/passwd", 18, &result) ==
         NOSH_URL_SANITIZE_INVALID);
  assert(nosh_url_sanitize("example.com/path", 16, &result) ==
         NOSH_URL_SANITIZE_INVALID);
  assert(nosh_url_sanitize("unknown://example.com/path", 26, &result) ==
         NOSH_URL_SANITIZE_NO_EFFECTIVE_PORT);
  assert(nosh_url_sanitize("https://example.com:0/", 22, &result) ==
         NOSH_URL_SANITIZE_INVALID);
  assert(nosh_url_sanitize("https://exa%mple.com/", 22, &result) ==
         NOSH_URL_SANITIZE_INVALID);

  puts("nosh-url sanitizer tests: ok");
  return 0;
}
