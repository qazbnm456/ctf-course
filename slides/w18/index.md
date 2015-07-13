
---
title: Final Attack & Defense
---

# Final Exam

## Attack & Defense
[2015 CTCTF](http://ct.ctf.tw)

## Date
+ 時間: 1/17 9:00~17:00 & 1/18 9:00~15:00 
+ 測試時間: 1/16 20:00~22:00

## Type
+ 本次比賽類型為 Attack & Defense
+ 每支隊伍負責維護一台 server (gamebox) 上的數個 service
+ 比賽中攻擊其它隊伍的 service，並且修補自己 service 的漏洞

## Access
+ 每支隊伍會收到一組 OpenVPN key & config
+ 一個 token 用來在上傳 flag 時識別上傳的隊伍
+ 一組 ssh key 用來登入 gamebox

## Network
+ 用 OpenVPN 連入
+ 各隊 subnet: 10.217.x.0/24

## Gamebox
+ 10.217.x.201
+ Ubuntu 12.04(?) 64bit 
+ ssh -i key.pem ctf\@10.217.x.201 
+ chown, su for each services
+ No root

## Forbidden
+ 禁止以大量的連線、流量或 fork bomb 等資源消耗型攻擊進行 DOS 或 DDOS，允許利用 service 本身漏洞造成 service crash 或結果不正確
+ Service 本身必需在裁判方提供的 server 上運行

## Protection
+ 原則上任何對 service 加固的方式都是允許的，但當裁判認定加固方式過於白爛時，會要求參賽隊伍移除 
    + 將服務用 qemu 包起來
    + 原則上 service 的設計會儘量讓這類防禦方式無效
+ 裁判方不提供備份及救援，請自行做好備分及權限控管

## Service Check
+ 主辦方會對各隊 service 進行測試，在修補漏洞或加固時要注意避免影響 service 的「預期行為」
    + 一個 buffer overflow 的漏洞顯然不是設計者預期該有的行為可以修掉
    + 加大 buffer 或是限制 input 長度
+ 裁判方不會試圖觸發漏洞或讓 service crash。

## TCP Packets
+ 所有進出 gamebox 的流量由裁判方紀錄，參賽隊伍並可以利用 sftp 從 10.217.x.1 下載
+ 每個回合為一個 pcap 單檔，每個單檔延遲3回合開放，保留 30 分鐘

## Scoring
+ 假設隊伍 A 利用 service 的漏洞入侵後取得 B 隊的 flag 並在該回合內上傳至評分系統，視為 A 對 B 入侵成功，B 為「被入侵」
+ 如果 service 沒有通過裁判方的檢查，視為 service down
+ 「被入侵」以及「service down」皆扣 15 分
+ 「被入侵」隊伍所失的 15 分，由入侵該隊的隊伍平分
+ 「service down」隊伍所失的 15 分，由其它該 service 正常的隊伍平分

## Scoring Example
+ 各隊失分 (被入侵 + service down):
    + A = -0 -0
    + B = -15 -15
    + C = -15 -15
    + D = -15 -0
+ 各隊得分 
    + A(入侵 B + 入侵 C + 入侵 D + service 正常) = 15 + 15/2 + 15 + 30/2 
    + B(入侵 C) =15/2 C = 0 
    + D(service 正常) = 30/2
+ 總分變化: A = 52.5, B = 22.5, C = -30, D = 0

## NPC
+ 10.217.1.201 為 NPC 隊伍之 gamebox
    + service 不會做加固
    + flag 會更新，分數計算視為一般隊伍
+ 裁判會用這隊放 hint 或調整分數

## IRC
+ chat.freenode.net #ctctf

# OpenVPN

## Test Client Config
+ 本日測試用
+ [config.tar.gz](http://judge.csie.ctf.tw/client.tar.gz)
    + ca.crt
    + client.crt
    + client.key
    + client.conf

## Windows
+ [Downloads](https://openvpn.net/index.php/open-source/downloads.html)
+ [OpenVPN GUI](http://swupdate.openvpn.org/community/releases/openvpn-install-2.3.6-I601-x86_64.exe)
+ config 解到 `C:\Program Files\OpenVPN\config`，把 client.conf 改成 client.ovpn
+ admin 執行 OpenVPN GUI -> connect

``` no-highlight
 C:\Program Files\OpenVPN\config 的目錄

 2015/01/08  上午 11:48    <DIR>          .
 2015/01/08  上午 11:48    <DIR>          ..
 2015/01/07  下午 05:20             1,464 ca.crt
 2015/01/07  下午 05:20             4,228 client.crt
 2015/01/07  下午 05:20               916 client.key
 2015/01/07  下午 05:20               182 client.ovpn
 2015/01/07  上午 11:46               213 README.txt
```

## Ubuntu / Debian
+ `tar zxvf client.tar.gz`
+ `apt-get install openvpn`
+ `sudo openvpn client.conf`

## Mac OSX
+ [Tunnelblick](https://esystem.csie.ntu.edu.tw/nalab/vpn/doc)
+ 解開 client.tar.gz，點兩下 client.conf (或改 client.ovpn)

## Check
+ 會得到一個 tun device 和 IP = 10.88.219.x
+ `ping 10.88.219.1`

# Try ATK & DEF

## Teams
+ 請各隊派一人來拿 ssh 密碼

``` no-highlight
<(_ _)> shik @10.88.219.101 
YSTP @10.88.219.102
wolfcat @10.88.219.103
WTFTJ @10.88.219.104
aaaay @10.88.219.105
IlIIIllIIlll @10.88.219.106
TeamSoloMid @10.88.219.107
HackStuff @10.88.219.108
i11usi0n @10.88.219.109
WEEEEEEEEE @10.88.219.110
happy CTF @10.88.219.111
AuditorTrollTeam @10.88.219.112
```

## Submit Flag

``` no-highlight
$ nc judge.csie.ctf.tw 1337
Your team ID (1~12): 1
> 08ae6a23db8318a02cf68e396652cb5f
Round: 4735651
Nope
> 94c21bb4acd850625d08563a6ba4f14b
Ok (2)
>
```

## Pwning Matrix
+ [Matrix](http://judge.csie.ctf.tw) <br>
![](p.png)

