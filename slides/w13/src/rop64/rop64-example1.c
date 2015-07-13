#include <stdio.h>

int main() {
  char buf[8];
  puts("pwn this!");
  fflush(stdout);
  read(0, buf, 1024);
  return 0;
}
