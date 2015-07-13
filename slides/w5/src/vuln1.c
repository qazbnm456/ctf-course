#include <unistd.h>

int main() {
  char str[16];
  alarm(10);
  write(1, "Pwn me if you can:\n", 19);
  read(0, str, 256);
  return 0;
}
