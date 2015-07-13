
---
title: Exploit Writing
---

# Source Code

## Source Code

[Examples](https://csie.ctf.tw/slides/w5/w5.tar.gz)

# Exploit Writing

## 目標
+ 從頭到尾寫一次，確保每個人都會寫 exploit
+ 確保作業 0x03

## 例題

[Example1](https://csie.ctf.tw/problems/14)


## Setup
+ IDA - 靜態分析
+ gdb - 動態調試
+ ncat - 在本地開啟服務
+ [ht](http://sourceforge.net/projects/hte/files/ht-source/ht-2.0.22.tar.gz) - 修改 binary

## 在本地開服務

`ncat -vc ./vuln1 -kl 8888`

+ `-v` debug info
+ `-c` 要執行的 command
+ `-l` 指定服務所在的 port
+ `-k` keep alive

## 尋找漏洞
+ Static analysis
+ Fuzz

## Binary Patching
+ 修改 binary 讓 debug 方便一點

## Function Hooking
+ `gcc alarm_hook.c -o alarm_hook.so \ `<br>`-m32 -fPIC -shared`
+ `LD_PRELOAD=./alarm_hook ./vuln1`

## 指令 library
+ `LD_LIBRARY_PATH=. ./vuln1`

``` cpp
unsigned int alarm(unsigned int x) {
  return 0;
}
```


## gdb attach
+ service 啟動後再 attach
+ `pidof vuln1`
+ `attach <pid>`

## gdbserver
+ `gdbserver localhost:4444 ./vuln1`
+ `gdbserver --wrapper env LD_LIBRARY_PATH=. \ `<br>`LD_PRELOAD=./alarm_hook.so -- \ `<br>`localhost:4444 ./vuln1`
+ gdb 裡使用 `target remote localhost:4444` 連線到 gdbserver

## ncat + gdbserver
+ `ncat -vc 'gdbserver --wrapper env \ `<br>
`LD_LIBRARY_PATH=. LD_PRELOAD=./alarm_hook.so \ `<br>`-- localhost:4444 ./vuln1' -kl 8888`

## qemu
+ `qemu-i386 -g 4444 ./vuln1` 
+ `qemu-i386 -strace ./vuln1` 
+ `qemu-i386 -d cpu ./vuln1` 

## Fetch information
+ 利用 output function 
+ libc base address, stack address

## Return to Function
+ 在 stack 上構造參數
+ pop 掉參數後，可以再串連下一個 function

## gets - system Combo
+ 取得 libc base 後執行 `gets(cmd); system(cmd)`
+ cmd 可以隨便找一個已知 address 的可寫位址

## Exploit & Trace
+ [Exploit](src/exp1.py)
+ [Trace](src/log-dump/log1.html)

# Tricks

## FreeBuf
+ global variable
+ .data, .bss
+ ~~.rodata~~ readonly
+ got 所在的 page

## Keep alive
+ leak + ret2lib 需要兩步，而且 ret2lib 的 address 一開始 hijack 時還未知
+ ret2main

## 無法 ret2main
[Example2](https://csie.ctf.tw/problems/15)

## Exploit & Trace
+ [Exploit](src/exp2.py)
+ [Trace](src/log-dump/log2.html)

# Olympic CTF 2014 - Echof

## Echof
[Echof](https://csie.ctf.tw/problems/16)
