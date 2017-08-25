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

#define MAXBUF    8096

/* User defined values */
#define DEBUG     0
#define PAGE_SIZE 4096
#define MAPPREFIX "map-"
#define MEMPREFIX "mem-"
#define BINSUFFIX ".bin"
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

int do_trace(pid_t child) {
  FILE *mapfile;
  int status, memfile, i;
  char tmp[MAXBUF];
  int *writeptr;
  char *filepath;

  waitpid(child, &status, 0);
  assert(WIFSTOPPED(status));

  sprintf(tmp, "/proc/%d/maps", child);
  mapfile=fopen(tmp, "r");

  if (!mapfile) fatal("Cannot open %s for reading.\n", tmp);

  sprintf(tmp, "/proc/%d/mem", child);
  memfile = open(tmp, O_RDONLY);
  if (memfile < 0) fatal("Cannot open %s for reading.\n", tmp);

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

  ptrace(PTRACE_DETACH);
  return 0;
}

int do_child(int argc, char **argv) {
  char *args [argc+1];
  int i;
  debug("execvp(%s, args) \n", args[0]);

  for (i = 0; i < argc; i++)
    args[i] = argv[i];
  args[argc] = NULL;

  ptrace(PTRACE_TRACEME);
  return execvp(args[0], args);
}

int main(int argc, char *argv[]) {
  pid_t child;

  if (DEBUG) debug("version 0.1 brendon tiszka");

  if (argc<2) usage(argv[0]);

  child = fork();
  if (child == 0) {
    return do_child(argc - 1, argv + 1);
  } else {
    return do_trace(child);
  }
}
