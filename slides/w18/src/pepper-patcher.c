#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void add_range_checking_in_show();

__attribute__ ((constructor)) void init(void) {
  add_range_checking_in_show();
}


int input_with_range_checking() {
  int (*orig_input)() = (int (*)())0x080487B9;
  int ret = orig_input();
  if (ret<0 || ret>=100) return 0;
  return ret;
}

void add_range_checking_in_show() {
  // hijack input function call
  // 08048930: call    sub_80487B9    | E8 84 FE FF FF

  const int addr = 0x08048930;

  mprotect((void*)0x08048000, 0x1000, PROT_READ | PROT_WRITE);

  *(int*)(addr+1) = (int)input_with_range_checking - (addr+5);

  mprotect((void*)0x08048000, 0x1000, PROT_READ | PROT_EXEC);
}

