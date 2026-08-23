// SPDX-License-Identifier: 0BSD

#include "url_sanitizer.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct default_port {
  const char *scheme;
  uint16_t port;
};

static const struct default_port default_ports[] = {
  { "dict", 2628 },
  { "ftp", 21 },
  { "ftps", 990 },
  { "gopher", 70 },
  { "gophers", 70 },
  { "http", 80 },
  { "https", 443 },
  { "imap", 143 },
  { "imaps", 993 },
  { "ldap", 389 },
  { "ldaps", 636 },
  { "mqtt", 1883 },
  { "pop3", 110 },
  { "pop3s", 995 },
  { "rtmp", 1935 },
  { "rtmps", 443 },
  { "rtsp", 554 },
  { "scp", 22 },
  { "sftp", 22 },
  { "smb", 445 },
  { "smbs", 445 },
  { "smtp", 25 },
  { "smtps", 465 },
  { "telnet", 23 },
  { "tftp", 69 },
  { "ws", 80 },
  { "wss", 443 },
};

static bool visible_ascii(unsigned char byte)
{
  return byte >= 0x21 && byte <= 0x7e;
}

static bool ascii_alpha(unsigned char byte)
{
  return (byte >= 'a' && byte <= 'z') ||
    (byte >= 'A' && byte <= 'Z');
}

static bool ascii_digit(unsigned char byte)
{
  return byte >= '0' && byte <= '9';
}

static unsigned char ascii_lower(unsigned char byte)
{
  return byte >= 'A' && byte <= 'Z' ? byte + ('a' - 'A') : byte;
}

static uint16_t default_port_for(const char *scheme)
{
  size_t index;

  for (index = 0; index < sizeof(default_ports) / sizeof(default_ports[0]);
       index++) {
    if (!strcmp(scheme, default_ports[index].scheme))
      return default_ports[index].port;
  }
  return 0;
}

static bool valid_scheme(const char *raw, size_t length, char *destination)
{
  size_t index;

  if (!length || length > NOSH_URL_SCHEME_MAX ||
      !ascii_alpha((unsigned char)raw[0]))
    return false;
  for (index = 0; index < length; index++) {
    unsigned char byte = (unsigned char)raw[index];

    if (!ascii_alpha(byte) && !ascii_digit(byte) &&
        byte != '+' && byte != '-' && byte != '.')
      return false;
    destination[index] = (char)ascii_lower(byte);
  }
  destination[length] = '\0';
  return strcmp(destination, "file") != 0;
}

static bool parse_port(const char *value, size_t length, uint16_t *port)
{
  unsigned long parsed = 0;
  size_t index;

  if (!length || length > 5)
    return false;
  for (index = 0; index < length; index++) {
    if (!ascii_digit((unsigned char)value[index]))
      return false;
    parsed = parsed * 10 + (unsigned long)(value[index] - '0');
    if (parsed > UINT16_MAX)
      return false;
  }
  if (!parsed)
    return false;
  *port = (uint16_t)parsed;
  return true;
}

static bool normalize_ipv6_host(const char *value,
                                size_t length,
                                char *destination)
{
  unsigned char address[16];
  char input[INET6_ADDRSTRLEN];
  char output[INET6_ADDRSTRLEN];
  size_t output_length;

  if (!length || length >= sizeof(input))
    return false;
  memcpy(input, value, length);
  input[length] = '\0';
  if (inet_pton(AF_INET6, input, address) != 1 ||
      !inet_ntop(AF_INET6, address, output, sizeof(output)))
    return false;
  output_length = strlen(output);
  if (output_length + 2 > NOSH_URL_HOST_MAX)
    return false;
  destination[0] = '[';
  memcpy(destination + 1, output, output_length);
  destination[output_length + 1] = ']';
  destination[output_length + 2] = '\0';
  return true;
}

static bool normalize_host(const char *value,
                           size_t length,
                           char *destination)
{
  size_t index;

  while (length && value[length - 1] == '.')
    length--;
  if (!length || length > NOSH_URL_HOST_MAX)
    return false;
  for (index = 0; index < length; index++) {
    unsigned char byte = (unsigned char)value[index];

    if (!visible_ascii(byte) || byte == '/' || byte == '@' || byte == '?' ||
        byte == '#' || byte == ':' || byte == '%' || byte == '[' ||
        byte == ']' || byte == '\\')
      return false;
    destination[index] = (char)ascii_lower(byte);
  }
  destination[length] = '\0';
  if (destination[0] == '.' || strstr(destination, ".."))
    return false;
  return true;
}

enum nosh_url_sanitize_result
nosh_url_sanitize(const char *raw,
                  size_t raw_length,
                  struct nosh_url_sanitized *result)
{
  const char *scheme_end;
  const char *authority_start;
  const char *authority_end;
  const char *resource_end;
  const char *host_start;
  const char *host_end;
  const char *path_start;
  const char *at = NULL;
  const char *cursor;
  const char *port_start = NULL;
  size_t path_length;

  if (!raw || !raw_length || !result || memchr(raw, '\0', raw_length))
    return NOSH_URL_SANITIZE_INVALID;
  memset(result, 0, sizeof(*result));

  scheme_end = memchr(raw, ':', raw_length);
  if (!scheme_end || scheme_end + 2 >= raw + raw_length ||
      scheme_end[1] != '/' || scheme_end[2] != '/' ||
      !valid_scheme(raw, (size_t)(scheme_end - raw), result->scheme))
    return NOSH_URL_SANITIZE_INVALID;

  authority_start = scheme_end + 3;
  resource_end = raw + raw_length;
  for (cursor = authority_start; cursor < resource_end; cursor++) {
    if (*cursor == '?' || *cursor == '#') {
      resource_end = cursor;
      break;
    }
  }
  authority_end = resource_end;
  for (cursor = authority_start; cursor < resource_end; cursor++) {
    if (*cursor == '/') {
      authority_end = cursor;
      break;
    }
  }
  if (authority_start == authority_end)
    return NOSH_URL_SANITIZE_INVALID;

  for (cursor = authority_start; cursor < authority_end; cursor++) {
    if (*cursor == '@')
      at = cursor;
  }
  host_start = at ? at + 1 : authority_start;
  host_end = authority_end;
  if (host_start == host_end)
    return NOSH_URL_SANITIZE_INVALID;

  if (*host_start == '[') {
    const char *closing = memchr(host_start + 1, ']',
                                 (size_t)(host_end - host_start - 1));

    if (!closing ||
        !normalize_ipv6_host(host_start + 1,
                             (size_t)(closing - host_start - 1),
                             result->host))
      return NOSH_URL_SANITIZE_INVALID;
    if (closing + 1 < host_end) {
      if (closing[1] != ':')
        return NOSH_URL_SANITIZE_INVALID;
      port_start = closing + 2;
    }
  } else {
    const char *colon = NULL;

    for (cursor = host_start; cursor < host_end; cursor++) {
      if (*cursor == ':') {
        if (colon)
          return NOSH_URL_SANITIZE_INVALID;
        colon = cursor;
      }
    }
    if (colon) {
      port_start = colon + 1;
      host_end = colon;
    }
    if (!normalize_host(host_start, (size_t)(host_end - host_start),
                        result->host))
      return NOSH_URL_SANITIZE_INVALID;
  }

  if (port_start) {
    if (!parse_port(port_start, (size_t)(authority_end - port_start),
                    &result->port))
      return NOSH_URL_SANITIZE_INVALID;
  } else {
    result->port = default_port_for(result->scheme);
    if (!result->port)
      return NOSH_URL_SANITIZE_NO_EFFECTIVE_PORT;
  }

  path_start = authority_end;
  if (path_start == resource_end) {
    result->path[0] = '/';
    result->path[1] = '\0';
    return NOSH_URL_SANITIZE_OK;
  }
  if (*path_start != '/')
    return NOSH_URL_SANITIZE_INVALID;
  path_length = (size_t)(resource_end - path_start);
  for (cursor = path_start; cursor < resource_end; cursor++) {
    unsigned char byte = (unsigned char)*cursor;

    if (!visible_ascii(byte) || byte == '?' || byte == '#' || byte == '\\')
      return NOSH_URL_SANITIZE_INVALID;
  }
  if (path_length > NOSH_URL_SANITIZED_PATH_MAX) {
    path_length = NOSH_URL_SANITIZED_PATH_MAX;
    result->path_truncated = true;
  }
  memcpy(result->path, path_start, path_length);
  result->path[path_length] = '\0';
  return NOSH_URL_SANITIZE_OK;
}
