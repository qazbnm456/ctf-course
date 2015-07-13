section .text
global _start
_start:
  mov rax, 1
  mov rdi, 1
  mov rsi, str
  mov rdx, 6
  syscall

  mov rax, 60
  syscall 
str:
  db 'hello',0xA
