#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  char *p, *q;
  p = malloc(256);
  q = malloc(256);
  gets(p);
  free(q);
  free(p);
  return 0;
}
