
---
title: Start Pwning
---

# About

## About Me
+ 吳哲仰 (Sean)
+ winesap.tw@gmail.com
+ 台大資工所 ing
+ 參加過「百度杯」和「DEFCON」
+ 興趣使然

## About My Teams
+ 217
    + 百度杯
    + 不定時參加一些比賽
    + 成員是台大 & 台科大學生
    + http://217.logdown.com/

+ HITCON
    + DEFCON
    + 舉辦 CTF

## About CTF
+ Capture The Flag
+ Hacker, geek 們太無聊想出來的玩法
+ 比 everything

## Jeopardy

+ 解題比賽
+ 24 ~ 48 小時，比時限內得分
+ 帶有漏洞的 service；可破解的 encryption
+ 入侵或破解後就有辦法拿到 flag

## Attack-defense

+ 每隊會拿到帶有漏洞的 service
+ 除了互相攻擊外，也可以修補自己的 service
+ Flag 每回合更新
+ 攻擊成功則得分，被攻擊方會失分

## About Lesson
+ 資安有很多層面，我善長的是 Software Security
    + Software 也有很多種
    + We focus on Unix-like OS
    + 嚴格來說，我是危害資安的那方


# Pwn, Pwning, Pwnable

## Exploit & Vulnerability
+ 一個軟體、一個服務有個 bug
+ 當這個 bug 可以被利用 (Expolit) 時，bug 就成為漏洞 (Vulnerability)
+ 學習如何將 bug 升級為漏洞，也就是 exploit 的技術

## Pwn
+ 及物動詞 
    + 「我今天 pwn 了一個 remote service」
+ 通常有著權限提升的意思在
+ Jailbreak: 利用 iOS 裡的漏泂拿到 admin 權限
+ 本地提權: 利用 kernel 裡的洞漏把自己升級成 root
+ 不知道為啥，一般來說講 pwn 會比較容易覺得是 binary 類的東西

## 基本流程
+ 尋找漏洞
+ 奪取程式控制權 (Control-flow Hijack)
+ 執行攻擊目的 (Execute Payload)

## Step 1: 尋找漏洞
+ 用力看 code (代碼審計，code audit)
+ Fuzz testing
    - Crash
    - 非預期行為

## Step 2: Control-flow Hijack
+ 試著控制程式的流程，例如
    - 改掉 return address
    - 改掉函式指標，使得呼叫函式時的行為改變
    - 改掉變數值，使得程行的行為改變 (e.g. uid = 0)

## Step 3: Execute Payload
+ 執行攻擊的目標
    - remote shell
    - Dump database
    - Install backdoor

# Setup

## 基礎建設
+ Programming & debuging on Linux
+ X86 assembly language

## Tools
+ gdb, gdbserver
+ nc, ncat
+ readelf 
+ objdump
+ IDA Pro
+ qemu, gdb-multiarch

## Scripting
+ I use Python2 with [pwntools](https://github.com/Gallopsled/pwntools)

# Buffer Overflow

## 定義
+ 寫到不該寫的地方
    + Crash
    + Control-flow hijack
+ 讀到不該讀的地方
    + Information leaking

## Vulnerable Function
+ `gets`
+ `scanf`
+ `strcpy`
+ `memcpy`
+ `sprintf`

## Stack Buffer Overflow
+ Stack 上的區域變數存在**溢出** (overflow) 漏洞
+ 可以覆蓋掉返回地址 (return address)
+ 又稱 stack smashing

## Example: gets()
``` cpp
#include <stdio.h>

void hacked() {
  puts("Hacked!!");
}

int main() {
  char str[10];
  gets(str);
}
```

## Compile it with gcc

``` no-highlight
gcc -o gets gets.c -m32 -fno-stack-protector -zexecstack
gets.c: In function ‘main’:
gets.c:9:3: warning: ‘gets’ is deprecated (declared at /usr/include/stdio.h:638) [-Wdeprecated-declarations]
   gets(str);
   ^
/tmp/cc4cukNn.o: In function `main':
gets.c:(.text+0x25): warning: the `gets' function is dangerous and should not be used.
```

## Return Hijack
+ 返回地址會在呼叫函式時，會被堆到 stack 上
+ 這個函式內的區域變數，會存放在比較低的位址
+ 如果這個變數是個陣列，寫入過多資料時就會覆蓋到在比較高位的返回地址

## Stack Buffer Overflow

![](images/stack-overflow.png)

## From Crash to Hack
+ 如果只是輸入的資料太多，程式通常就只會 crash
+ 必須構造特定的資料，才能利用這個漏洞
+ 在輸入中放上要 hijack 跳過去的 address

## Tips
+ 先跳到已知的函式上，檢查有沒有成功控制程式流程
    - 有沒有如預期的輸出
    - 跳到輸入函式上，應該要停住等待輸入 (但如果再輸入一些內容又會 crash)

## Shellcode
+ 現在主流的計算機架構中，data 和 code 都是混在一起的
+ 正確的 data 就可以當 code 跑
+ 基本上就是 assembler 生成的 binary code

## Jump to Shellcode
+ Input 時就可以把 shellcode 上去了，但還是要想辦法跳到 shellcode 所在的地方才有辦法執行
+ 想辦法找到 shellcode 的位址
+ 有 ASLR 的情況下，stack base 會隨機化，每次 shellcode 的位址會不同

## NOP slide
`\x90\x90\x90\x90\x90\x90\x90\x90\x90`<br>`\x90\x90\x90\x90\x90\x90\x90\x90\x90`<br>`\x90\x90\x90\x90\x90\x90\x90\x90\x90`

+ 記憶體中塞滿 `nop` 指令，最後面接上 shellcode
+ 跳到其中任何地方最後都會執行到 shellcode

## Jump to Shellcode
+ NOP slide 基本上不會成功，因為 ASLR 的範圍太大了
+ 利用暫存器或 stack 上殘留的值做精確的跳轉

## Gadget
+ KK <span style="font-family:'Sans-serif'">\[\`g&#230;d&#658;&#618;t\]</span> 
  小機件；（小巧的）器具；小玩意兒\[C\]
+ 一小段有用的 code
+ 即使不是原本就有指令，也有可能恰好構成有用的 gadget

## Call/Jump Reg
+ gcc 生成的執行檔中 `call eax` 很常見
+ 另外如果有 `jmp esp` 這樣的指令也可以利用，因為 stack 上的內容是可以被 overflow 控制的

## Return by Value on Stack
+ x86 的參數會用 stack 傳遞，可能有 buffer pointer
+ 區域變數的值也有可能留在 stack 上
+ 如果能將 esp 調整到正確的位置再 return，就可以利用

## Example

``` cpp
#include <stdio.h>
int input(int len, char *str) {
  char buf[80];
  while (len--) {
    buf[len] = str[len];
    if (buf[len]==' ') buf[len] = '_';
  }
  return 0;
}
int main() {
  char str[0x80];
  fgets(str, sizeof(str), stdin);
  input(strlen(str)-1, str);
}
```

# Shellcode

## 特性
+ 不可以有當做字串結尾的 `'\0'` 字元，或其它會被函數截斷的字元
+ Position independent，在位址不確定的情況下也要可以正常執行

## Null-free

+ 常見的緩衝區溢出是對字串操作時發生，這樣我們要送的  code 中就不可以有代表字串結束的`'\0'`
+ 例如 `strcpy` 複製字串到 stack buffer 上，如果其中有 `'\0'` 就不會產生溢出

## Position Independent Code

+ 沒有辦法確定 shellcode 被放在哪裡的情況，不可以指定絕對位址
+ 一般 `jmp` 和 `call` 都是用相對位址，但拿 .data 裡的內容時會是絕對位址

## Launch a shell

``` avrasm
section .text
global _start
_start:
    mov eax, 0x0b
    mov ebx, sh
    mov ecx, argv
    mov edx, envp
    int 0x80

section .data
argv:
    dd sh, 0
envp:
    dd 0
sh:
    db "/bin/sh", 0
```

## How to set eax to 0?
+ `mov eax, 0x0` &#8594; `b8 00 00 00 00`

## How to set eax to 1?
+ `mov eax, 0x1` &#8594; `b8 01 00 00 00`

## Get offset of the buffer (.data)?
+ `mov ebx, sh` &#8594; `bb a4 90 04 08`

## Embed a null-terminated string 
+ `sh: db "/bin/sh", 0`

## Build arrays or structures
+ `argv: dd sh, 0`
+ `envp: 0`

## General Solution
+ Escape
+ Read and jump

## Auto Escaping
``` avrasm
_start:
  jmp shellcode
escape:
  xor eax, eax
  mov esi, [esp]
  mov edi, esi
.L1:
  mov dl, [esi]
  inc esi
  cmp dl, 0xff  ; escape charater - 0xff
  je .B1
  mov [edi], dl
  inc edi
  jmp .L1
.B1:            ; escape
  mov dl, [esi]
  inc esi
  cmp dl, 0xff  ; 0xff 0xff - shellcode end
  jne .B2
  ret
.B2:            ; 0xff {others} - replace to '\0'
  mov [edi], al
  inc edi
  jmp .L1
shellcode:
  call escape
```

## Read and Jump
+ 如果 I/O 能繼續進行，就可以使用
+ 寫一段 null-free 的 `read(0, esp, length) + jmp esp` 就行

# Buffer Overflow Examples

## gets, scanf, strcpy, sprintf

``` cpp
int main(int argc, char **argv) {
  char str[10];
  gets(str);
  scanf("%s", str);
  strcpy(str, argv[1]);
  sprintf(str, "%s", argv[1]);
  memcpy(str, argv[1], strlen(argv[1]));
}
```

## readline

``` cpp
void readline(char *buf, int size) {
  int i = 0;
  while (1) {
    buf[i] = getchar();
    if (buf[i]=='\n' || i==size) {
      buf[i] = 0;
      break;
    }
    i++;
  }
}
int main() {
  char buf[16];
  readline(buf, 16);
}
```

## stat + open file

``` cpp
int readfile(char *filename) {
  char buf[1024];
  struct stat st;
  FILE *f;
  int ch;
  char *p = buf;
  stat(filename, &st);
  if (st.st_size < 1024) {
    f = fopen(filename, "rb");
    while ((ch=fgetc(f))!=EOF) {
      *p++ = ch;
    }
  } else puts("File too large");
}
```

## htop


Process_writeField() in Process.c
``` cpp
    char buffer[128];
    char* buf = buffer;
    int n = sizeof(buffer) - 1;
    for (int i = 0; i < maxIndent - 1; i++) { // maxIndent < 32
      int written;
      if (indent & (1 << i))
         written = snprintf(buf, n, "%s  ", 
                            treeStr[TREE_STR_VERT]); // = 5
      else
         written = snprintf(buf, n, "   "); // = 3
      buf += written;
      n -= written;
    }
```

# Protection & Bypass

## Prevent Buffer Overflow & Exploit

+ StackGuard
+ Data Execution Prevention

## gcc parameters
+ 關閉 StackGuard `-fno-stack-protector`
+ 關閉 DEP `-zexecstack` 

## StackGuard

+ 在函式被呼叫時，先在 stack 上放 **canary**
+ 函式返回前先檢查這個值有沒有被修改

## StackGuard

![](images/stack-overflow2.png)

## Data Execution Prevention

+ Shellcode 不能執行，因為是 data 
+ NX bit
+ Writable 和 executable 是互斥的
    + 可以改的不能跑，可以跑的不能改


## Stack Reading

+ 適用於 service fork() 後不會重新執行 exec() 的情況
  + `fork()` 後 canary 的值不會改變
  + 任何 address 也會相同，即 ASLR 不會重新作用 
+ 每次多 overflow 一個 byte，測試可能的值
+ 如果沒有 crash 就表示猜對了
+ crash 就表示猜錯了，但重新連上 service 又會重新啟動


## Overwrite Local Variable

+ 如果只是 Overflow 到區域變數，不會蓋到 StackGuard canary
+ 利用程式本身對區域變數的操作，做出進一步的任意記憶體寫入

# Case Study

## Compiled with StackGuard
``` cpp
#include <stdio.h>
char str[256];
int main() {
  int i, j;
  char buf[16];
  fgets(str, sizeof(str), stdin);
  for (i=0, j=0; str[i]; ++i) {
    if (str[i]!=' ') {
      buf[j++] = str[i];
    }
  }
  buf[j] = 0;
  puts(buf);
}
```

