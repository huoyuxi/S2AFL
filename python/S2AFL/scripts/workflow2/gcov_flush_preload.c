#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void (*gcov_flush_fn)(void);

static gcov_flush_fn resolve_dynamic_symbol(const char *name) {
  void *sym = dlsym(RTLD_DEFAULT, name);
  return (gcov_flush_fn)sym;
}

static uintptr_t parse_hex_env(const char *name) {
  const char *value = getenv(name);
  if (!value || !*value) return 0;
  return (uintptr_t)strtoull(value, 0, 16);
}

static uintptr_t executable_load_base(void) {
  char exe_path[4096];
  ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (exe_len <= 0) return 0;
  exe_path[exe_len] = '\0';

  FILE *fp = fopen("/proc/self/maps", "r");
  if (!fp) return 0;
  char line[8192];
  uintptr_t best = 0;
  while (fgets(line, sizeof(line), fp)) {
    unsigned long start = 0, end = 0, offset = 0;
    char perms[8] = {0};
    char path[4096] = {0};
    int fields = sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095s", &start, &end, perms, &offset, path);
    if (fields >= 5 && strstr(perms, "x") && strcmp(path, exe_path) == 0) {
      best = (uintptr_t)start - (uintptr_t)offset;
      break;
    }
  }
  fclose(fp);
  return best;
}

static gcov_flush_fn resolve_static_offset(void) {
  uintptr_t symbol = parse_hex_env("S2AFL_GCOV_DUMP_ADDR");
  if (!symbol) return 0;
  const char *mode = getenv("S2AFL_GCOV_DUMP_MODE");
  if (mode && strcmp(mode, "abs") == 0) {
    return (gcov_flush_fn)symbol;
  }
  uintptr_t base = executable_load_base();
  if (!base) return 0;
  return (gcov_flush_fn)(base + symbol);
}

static void s2afl_gcov_flush_handler(int signo) {
  (void)signo;
  gcov_flush_fn dump_fn = resolve_dynamic_symbol("__gcov_dump");
  if (!dump_fn) dump_fn = resolve_static_offset();
  if (dump_fn) {
    dump_fn();
    return;
  }
  gcov_flush_fn flush_fn = resolve_dynamic_symbol("__gcov_flush");
  if (flush_fn) flush_fn();
}

__attribute__((constructor))
static void s2afl_install_gcov_flush_handler(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = s2afl_gcov_flush_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR2, &sa, 0);
}
