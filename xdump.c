/*
 *  Brendon Tiszka
 *  Simple tool for dumping a executables memory
 */

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define MAXBUF    8192

/* User defined values */
#define DEBUG     0
#define PAGE_SIZE 4096
#define MAPPREFIX "map-"
#define MEMPREFIX "mem-"
#define BINSUFFIX ".bin"

#define LOW_ADDR  PAGE_SIZE
#define HIGH_ADDR 0xffffffff

#define USE_PROC_DIR 1
/* End user defined values */

#define debug(x...) { \
fprintf(stderr, x); \
fflush(stderr); \
}\

#define fatal(x...) { \
fprintf(stderr, "[-] ERROR: " x); \
exit(1); \
}\


void usage(char *myname) {
  debug("Usage: %s filename\n", myname);
  exit(3);
}

int dump_with_proc(FILE *mapfile, pid_t child) {
  int i;
  char tmp[MAXBUF];
  int *writeptr;
  char *filepath;

  while (fgets(tmp, MAXBUF, mapfile)) {
    int dumpfile, dumpcnt;
    char small[MAXBUF];
    unsigned int st, en, len;

    if (sscanf(tmp, "%x-%x", &st, &en) != 2) {
      debug("[!] Parse error in /proc/%d/maps: %s", child, tmp);
      continue;
    }

    len = en - st;

    if (DEBUG) debug("%x %x\n", st, en);

    if ((filepath=strchr(tmp,'/'))) {
      *(filepath-1)=0;
      sprintf(small, MAPPREFIX "%x-%x" BINSUFFIX, st, en);
    } else {
      if (strchr(tmp, '\n')) *strchr(tmp,'\n')=0;
      sprintf(small, MEMPREFIX "%x-%x" BINSUFFIX, st, en);
    }

    if (DEBUG) debug("%s\n", small);

    writeptr = calloc(len, 1);

    for (i = 0; i < len/4; i++)
      writeptr[i] = ptrace(PTRACE_PEEKDATA, child, i*4+st, 0);

    dumpfile = open(small, O_WRONLY | O_TRUNC | O_CREAT | O_EXCL, 0600);
    if (dumpfile < 0) fatal("Cannot open output file %s.\n", small);

    if (write(dumpfile, writeptr, len) != len)
      fatal("Short write to %s.\n", small);

    dumpcnt++;
    close(dumpfile);
  }

  return 1;
}

int dump_segment(pid_t child, size_t addr) {
  char small[MAXBUF];
  int *writeptr;
  int i, dumpfile;

  memset(small, 0, MAXBUF);
  writeptr = calloc(PAGE_SIZE, 1);
  for (i = 0; i < PAGE_SIZE/4; i++)
    writeptr[i] = ptrace(PTRACE_PEEKDATA, child, i*4+addr, 0);

  sprintf(small, MEMPREFIX "%zx-%zx" BINSUFFIX, addr, addr+PAGE_SIZE);

  dumpfile = open(small, O_WRONLY | O_TRUNC | O_CREAT | O_EXCL, 0600);
  if (dumpfile < 0) fatal("Cannot open output file %s.\n", small);

  if (write(dumpfile, writeptr, PAGE_SIZE) != PAGE_SIZE)
    fatal("Short write to %s.\n", small);

  return 1;
}

int do_memsearch(pid_t child) {
  size_t lo_addr, hi_addr, addr;

  lo_addr = LOW_ADDR;
  hi_addr = HIGH_ADDR;

  for (addr = lo_addr; addr < hi_addr; addr += PAGE_SIZE) {
    errno = 0;
    int q = ptrace(PTRACE_PEEKDATA, child, addr, 0);
    if (errno == 0) {
      if (DEBUG) debug("found: %zx %x\n", addr, q);
      dump_segment(child, addr);
    }
  }

  return 1;
}

int do_trace(pid_t child) {
  FILE *mapfile;
  int status, canproc;
  char tmp[MAXBUF];


  waitpid(child, &status, 0);
  assert(WIFSTOPPED(status));

  sprintf(tmp, "/proc/%d/maps", child);
  mapfile=fopen(tmp, "r");

  canproc = USE_PROC_DIR;
  if (!mapfile) {
    canproc = 0;
  }

  if (canproc)  dump_with_proc(mapfile, child);
  else          do_memsearch(child);


  ptrace(PTRACE_DETACH);
  return 0;
}

int do_child(int argc, char **argv) {
  char *args [argc+1];
  int i;

  for (i = 0; i < argc; i++)
    args[i] = argv[i];

  args[argc] = NULL;
  debug("argc %d execvp(%s, args) \n", argc, args[0]);

  if (ptrace(PTRACE_TRACEME) == 0) {
    return execvp(args[0], args);
  }

  fatal("Couldn't attach to process");
}

int main(int argc, char *argv[]) {
  pid_t child;

  if (DEBUG) debug("version 0.1 brendon tiszka\n\n");

  if (argc<2) usage(argv[0]);

  child = fork();
  if (child == 0) {
    return do_child(argc - 1, argv + 1);
  } else {
    return do_trace(child);
  }
}
