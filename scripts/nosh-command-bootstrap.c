/* Trusted worker bootstrap for the host AppArmor acceptance probe.
 * Its image and argv are supplied by the operator; never installed setuid. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2 || strncmp(argv[1], "/usr/bin/", 9) || strchr(argv[1] + 9, '/')) {
    fputs("invalid executable\n", stderr);
    return 125;
  }
  struct rlimit core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
      || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("worker confinement");
    return 125;
  }
  char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
  execve(argv[1], argv + 1, environment);
  perror("worker exec");
  return 126;
}
