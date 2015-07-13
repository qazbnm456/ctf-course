#include <stdio.h>
#include <sys/mman.h>

void destroy_main() {
  char *start = (char*)0x8048517;
  char *end = (char*)0x8048569;
  mprotect((void*)(((int)start)&(-0x1000)), 0x1000, 
      PROT_READ | PROT_WRITE | PROT_EXEC);
  while (start!=end) {
    *start = '\xff';
    start++;
  }
  mprotect((void*)(((int)start)&(-0x1000)), 0x1000, PROT_READ | PROT_EXEC);
}

int main() {
  char str[16];
  alarm(10);
  write(1, "Example2:\n", 10);
  read(0, str, 256);
  destroy_main();
  return 0;
}
