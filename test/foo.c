#include <stdio.h>
#include <unistd.h>

char *flag = "REDTEAM{100_beanie_dream}";

int main(void) {
  printf("uid: %d; euid: %d\n", getuid(), geteuid());
  return 0;
}
