#include <stdio.h>

int main() {
  char buf[80];
  read(0, buf, 256);
  puts(buf);
}
