# noob-s-socks5

中文看下边

An it-just-work bare SOCKS5 server in c++. Supports CONNECT and UDP_ASSOC.

Meant to work with `badvpn-tun2socks` and some game accelerator, to seperate game environment from accelerators.

The code itself is poorly written. No warranty.

Based on `socks_proxy` by fgssfgss. https://github.com/fgssfgss/socks_proxy

## Example

- Install `TAP-win32` on the game machine.
- Compile `badvpn-tun2socks` from master (prebuilt binariess has no support for --socks5-udp)

- Run on game machine:

```cmd
"C:\Program Files\TAP-Windows\bin\addtap.bat"
REM Rename the new TAP interface to "tun2socks"
netsh in ipv4 set addr tun2socks static address=172.17.3.1/28
ping eu.wargaming.net
route add -p 92.223.19.61/20 172.17.3.5
badvpn-tun2socks.exe --tundev tap0901:tun2socks:172.17.3.1:172.17.3.0:255.255.255.0 --netif-ipaddr 172.17.3.5 --netif-netmask 255.255.255.0 --socks-server-addr 192.168.22.128:1080 --socks5-udp
```

- Run on game accelerator machine:

```cmd
REM Start your accelerator
ren MySocks5.exe WorldOfWarships64.exe
WorldOfWarships64.exe
```

## 中文说明

- 凑齐 `badvpn-tun2socks` `TAP-win32` 还有本程序，就可以在虚拟机里跑网游加速器了。下面是无脑配置步骤。
- 先在主机上添加一个TAP适配器(`"C:\Program Files\TAP-Windows\bin\addtap.bat"`），改名为`tun2socks`
- 配置IP为`172.17.3.1/28`
```netsh in ipv4 set addr tun2socks static address=172.17.3.1/28```
- 找到游戏服务器的IP，加一个路由
```cmd
ping eu.wargaming.net
route add -p 92.223.19.61/20 172.17.3.5
```
- 运行 `badvpn-tun2socks`
```cmd
badvpn-tun2socks.exe --tundev tap0901:tun2socks:172.17.3.1:172.17.3.0:255.255.255.0 --netif-ipaddr 172.17.3.5 --netif-netmask 255.255.255.0 --socks-server-addr 192.168.22.128:1080 --socks5-udp
```
- 虚拟机里配置好加速器，把本项目找个地方扔进去，伪装成游戏
```cmd
ren MySocks5.exe WorldOfWarships64.exe
```
- 开启加速，再运行本程序
```
WorldOfWarships64.exe
```
- 回到主机运行游戏

重启后，只需要从“运行 `badvpn-tun2socks`”继续即可。
如果加速器对直接IP访问443端口有限制，而游戏本身是通过域名访问服务器的，可以参考`socks_server.cpp`开头的`IP_REVERSE_MAP_TEXT`数组，做IP到域名的反向映射。

<div style="opacity: 10%;">写这个主要是现有的成熟的SOCKS5代理，带UDP的，要不就是改名之后运行不了，要不就是一开加速之后UDP哑火，表现都比较奇怪，所以只好自己糊了一个凑合用的。也许某天会重构一下吧，嗯。</div>



