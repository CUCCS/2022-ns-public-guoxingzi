# 基于 Scapy 编写端口扫描器

## 实验目的

- 掌握网络扫描之端口状态探测的基本原理

## 实验要求

- 禁止探测互联网上的 IP ，严格遵守网络安全相关法律法规
- 完成以下扫描技术的编程实现
  -  `TCP connect scan`/ `TCP stealth scan`
  -  `TCP Xmas scan` / `TCP fin scan`/ `TCP null scan`
  -  `UDP scan`
- 上述每种扫描技术的实现测试均需要测试端口状态为：开放、关闭 和 过滤 状态时的程序执行结果
- 提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
- 在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟

## 实验环境

- Visual Studio Code

- Scapy 2.4.4

- Kali Rolling (Linux kali 5.18.0-kali5-amd64)


## 实验步骤

### 网络拓扑

Attacker作为扫描端，Victim作为被扫描的靶机，Gateway作为网关，起到联通作用。

![tuopu.png](tuopu.png)

### 端口状态模拟

查看当前防火墙的状态和现有规则

```bash
sudo ufw status
```

有以下三种状态

- 关闭状态：对应端口没有开启监听, 防火墙没有开启。

  ```shell
  sudo ufw disable
  ```

- 开启状态：对应端口开启监听: apache2基于TCP, 在80端口提供服务; DNS服务基于UDP,在53端口提供服务。防火墙处于关闭状态。

  ```shell
  systemctl start apache2 # port 80
  systemctl start dnsmasq # port 53
  ```

- 过滤状态：对应端口开启监听, 防火墙开启。

  ```bash
  ufw enable && ufw deny 80/tcp
  ufw enable && ufw deny 53/udp
  ```



### TCP connect scan

TCP connect Scan(TCP连接扫描) 这种方法也称之为“TCP全连接扫描”。它是最简单的一种扫描技术,所利用的是TCP协议的3次握手过程。它直接连到目标端口并完成一个完整的3次握手过 程(SYN、SYN/ACK和ACK)。操作系统提供的“connect()”函数完成系统调用,用来与目标计算机的端口进行连接。如果端口处于侦听状 态,那么“connect()”函数就能成功。否则,这个端口是不能用的,即没有提供服务。先发送一个S，然后等待回应。如果有回应且标识为RA，说明目标端口处于关闭状态；如果有回应且标识为SA，说明目标端口处于开放状态。这时TCP connect scan会回复一个RA，在完成三次握手的同时断开连接。

**CODE**

```python
from scapy.all import *


def tcpconnect(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=timeout)
    if pkts is None:
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x12):  #Flags: 0x012 (SYN, ACK)
            send_rst = sr(IP(dst=dst_ip)/TCP(dport=dst_port,flags="AR"),timeout=timeout)
            print("Open")
        elif (pkts.getlayer(TCP).flags == 0x14):   #Flags: 0x014 (RST, ACK)
            print("Closed")

tcpconnect('10.0.2.6', 80)
```

#### 端口关闭

attacker端代码

```shell
sudo python tcp_connect_scan.py #运行python文件
```

![tcpconnectscancloseattacker.png](tcpconnectscancloseattacker.png)

victim代码

```shell
sudo ufw status #检查防火墙状态，此处需要关闭
sudo netstat -anop | grep LISTEN | grep -v unix #查看TCP端口是否开启，此处需要关闭
sudo tcpdump -i eth3 -w tcp-cnt-3.pcap && date -R #开启抓包
sudo tshark -r tcp-cnt-3.pcap -Y "tcp or udp or icmp" #进行抓包分析
```

![tcpconnectscanclosevictim.png](tcpconnectscanclosevictim.png)

#### 端口开放

attacker端代码

```shell
sudo python tcp_connect_scan.py #运行python文件
```

![tcpconnectscan&openattacker.png](tcpconnectscanopenattacker.png)

victim代码

```shell
systemctl start apache2 #打开TCP80监听端口
sudo ufw status #查看防火墙状态，此处状态需要关闭
sudo netstat -anop | grep LISTEN | grep -v unix #查看TCP端口是否开启，此处需要关闭
sudo tcpdump -i eth3 -w tcp-cnt-3.pcap && date -R #开启抓包
sudo tshark -r tcp-cnt-2.pcap -Y "tcp or udp or icmp" #进行抓包分析
```

![tcpconnectscanopenvictim.png](tcpconnectscanopenvictim.png)

#### 端口过滤

attacker端代码

```shell
sudo python tcp_connect_scan.py #运行python文件
```

![tcpconnectscanfilterattacker.png](tcpconnectscanfilterattacker.png)

victim代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status #打开防火墙并且查看其状态
systemctl start apache2 # port 80，打开80端口
sudo netstat -anop | grep LISTEN | grep -v unix #查看TCP端口是否开启，此处需要关闭
sudo tcpdump -i eth3 -w tcp-cnt-3.pcap && date -R #开启抓包
sudo tshark -r tcp-cnt-3.pcap -Y "tcp or udp or icmp" #进行抓包分析
```

![tcpconnectscanfiltervictim.png](tcpconnectscanfiltervictim.png)

### TCP stealth scan

首先发送一个S，然后等待回应。如果有回应且标识为RA，则说明目标端口处于关闭状态；如果有回应且标识为SA，说明目标端口处于开放状态。这时TCP stealth scan只回复一个R，不完成三次握手，直接取消建立连接。

**CODE**

```python
#! /usr/bin/python

from scapy.all import *


def tcpstealthscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=10)
    if (pkts is None):
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip) /
                          TCP(dport=dst_port, flags="R"), timeout=10)
            print("Open")
        elif (pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
        elif(pkts.haslayer(ICMP)):
            if(int(pkts.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print("Filtered")


tcpstealthscan('10.0.2.6', 80)
```

#### 端口关闭

attacker端

![TCPstealthscanA1](TCPstealthscanA1.png)

victim代码

```shell
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-n-1.pcap && date -R
sudo tshark -r tcp-cnt-n-1.pcap -Y "tcp or udp or icmp"
```

![TCPstealthscanV1](TCPstealthscanV1.png)

#### 端口开放

attacker端

![TCPstealthscanA2](TCPstealthscanA2.png)

victim代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tshark -r tcp-stl-n-1.pcap -Y "tcp or udp or icmp"
```

![TCPstealthscanV2](TCPstealthscanV2.png)

#### 端口过滤

attacker

![TCP stealth scan A3](TCPstealthscanA3.png)

victim代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-stl-3.pcap && date -R
sudo tshark -r tcp-stl-3.pcap -Y "tcp or udp or icmp"
```

![TCP stealth scan V3](TCPstealthscanV3.png)

### TCP Xmas scan

其原理在于TCP连接结束时,会向TCP端口发送一个设置了FIN 位的连接终止数据报,关闭的端口会回应一个设置了RST的连接复位数据报;而开放的端口则会对这种可疑的数据报不加理睬,将它丢弃。一种隐蔽性扫描，当处于端口处于关闭状态时，会回复一个RST包；其余所有状态都将不回复。

**CODE**

```python
#! /usr/bin/python
from scapy.all import *


def Xmasscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="FPU"), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


Xmasscan('10.0.2.6', 80)
```

#### 端口关闭

attacker端

![TCP Xmas scan A1](TCPXmasscanA1.png)

victim代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-3.pcap && date -R
sudo tshark -r tcp-cnt-3.pcap -Y "tcp or udp or icmp"
```

![TCP Xmas scanV1](TCPXmasscanV1.png)

#### 端口开放

attacker端

![TCP Xmas scan A2](TCPXmasscanA2.png)

victim代码

```shell
systemctl start apache2
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-2.pcap && date -R
sudo tshark -r tcp-cnt-2.pcap -Y "tcp or udp or icmp"
```

![TCP Xmas scan V2](TCPXmasscanV2.png)

#### 端口过滤

attacker端

![TCP Xmas scan A3](TCPXmasscanA3 .png)

victim代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-stl-3.pcap && date -R
sudo tshark -r tcp-stl-3.pcap -Y "tcp or udp or icmp"
```

![TCP Xmas scan V3](TCPXmasscanV3.png)

### TCP FIN scan

TCP FIN扫描也和TCP SYN扫描原理差不多，当申请方主机向目标主机一个端口发送的TCP标志位FIN置位的数据包，如果目标主机该端口是“关”状态，则返回一个TCP RST数据包；否则不回复。根据这一原理可以判断对方端口是处于“开”还是“关”状态。这种方法的缺点是，该原理不是协议规定，因而与具体的协议系统实现有一定的关系，因为有些系统在实现的时候，不管端口是处于“开”还是“关”状态，都会回复RST数据包，从而导致此方法失效。只发送FIN包，FIN数据包能够通过只监测SYN包的包过滤器，隐蔽性较SYN扫描更⾼，此扫描与Xmas扫描也较为相似，只是发送的包未FIN包，同理，收到RST包说明端口处于关闭状态；反之说明为开启/过滤状态。

**CODE**

```python
#! /usr/bin/python
from scapy.all import *


def finscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="F"), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


finscan('10.0.2.6', 80)
```

#### 端口关闭

attacker端

![TCP FIN scan A1](TCPFINscanA1.png)

victim代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-3.pcap && date -R
sudo tshark -r tcp-cnt-3.pcap -Y "tcp or udp or icmp"
```

![TCP FIN scan V1](TCPFINscanV1.png)

#### 端口开放

attacker端

![TCP FIN scan A2](TCPFINscanA2.png)

victim代码

```shell
systemctl start apache2
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-2.pcap && date -R
sudo tshark -r tcp-cnt-2.pcap -Y "tcp or udp or icmp"
```

![TCP FIN scan V2](TCPFINscanV2.png)

#### 端口过滤

attacker端

![TCP FIN scan A3](TCPFINscanA3.png)

victim代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-stl-3.pcap && date -R
sudo tshark -r tcp-stl-3.pcap -Y "tcp or udp or icmp"
```

![TCP FIN scan V3](TCPFINscanV3.png)

### TCP NULL scan

其原理是扫描主机向目标主机某端口发送一个带有FIN标志的数据包,如果目标主机端口未开,则会回应一个RST的连接复位数据报;而开放的端口则会对这种可疑的数据报不加理睬,将它丢弃。因此可以根据是否收到RST数据报来判断对方的端口是否开放。发送的包中关闭所有TCP报⽂头标记，实验结果预期还是同理：收到RST包说明端口为关闭状态，未收到包即为开启/过滤状态.

**CODE**

```python
#! /usr/bin/python
from scapy.all import *


def nullscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags=""), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


nullscan('10.0.2.6', 80)
```

#### 端口关闭

attacker端

![TCP NULL scan A1](TCPNULLscanA1.png)

victim代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-3.pcap && date -R
sudo tshark -r tcp-cnt-3.pcap -Y "tcp or udp or icmp"
```

![TCP NULL scan V1](TCPNULLscanV1.png)

#### 端口开放

attacker端

![TCP NULL scan A2](TCPNULLscanA2.png)

victim代码

```shell
systemctl start apache2
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-2.pcap && date -R
sudo tshark -r tcp-cnt-2.pcap -Y "tcp or udp or icmp"
```

![TCP NULL scan V2](TCPNULLscanV2.png)

#### 端口过滤

attacker端

![TCP NULL scan A3](TCPNULLscanA3.png)

victim代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-stl-3.pcap && date -R
sudo tshark -r tcp-stl-3.pcap -Y "tcp or udp or icmp"
```

![TCP NULL scan V3](TCPNULLscanV3.png)

### UDP scan

udp端口扫描原理 由于UDP协议是非面向连接的,对UDP端口的探测也就不可能像TCP端口的探测那样依赖于连接建立过程(不能使用telnet这种tcp协议类型命令),这也使得UDP端口扫描的可靠性不高。这是一种开放式扫描，通过发送UDP包进行扫描。当收到UDP回复时，该端口为开启状态；否则即为关闭/过滤状态.

**CODE**

```python
from scapy.all import *
def udpscan(dst_ip, dst_port, dst_timeout=10):
    resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
    if (resp is None):
        print("Open|Filtered")
    elif (resp.haslayer(UDP)):
        print("Open")
    elif(resp.haslayer(ICMP)):
        if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
            print("Closed")
        elif(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            print("Filtered")
        elif(resp.haslayer(IP) and resp.getlayer(IP).proto == IP_PROTOS.udp):
            print("Open")
udpscan('10.0.2.6', 53)
```

#### 端口关闭

attacker端

![UDP scan A1](UDPscanA1.png)

victim代码

```shell
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-3.pcap && date -R
sudo tshark -r tcp-cnt-3.pcap -Y "tcp or udp or icmp"
```

![UDP scan V1](UDPscanV1.png)

#### 端口开放

attacker端

![UDP scan A2](UDPscanA2.png)

victim代码

```shell
systemctl start apache2
sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-cnt-2.pcap && date -R
sudo tshark -r tcp-cnt-2.pcap -Y "tcp or udp or icmp"
```

![UDP scan V2](UDPscanV2.png)

#### 端口过滤

attacker端

![image-20221017202315904](UDPscanA3.png)

victim代码

```shell
sudo ufw enable && sudo ufw deny 80/tcp && sudo ufw status
sudo netstat -anop | grep LISTEN | grep -v unix
sudo tcpdump -i eth3 -w tcp-stl-3.pcap && date -R
sudo tshark -r tcp-stl-3.pcap -Y "tcp or udp or icmp"
```

![UDP scan V3](UDPscanV3.png)

## 实验问题

- 问题最多的永远是虚拟机的响应与互联问题，经过不停的重新导入与更改网卡完成主机的互联
- 当Attacker端运行了python文件后，没有回馈，发现是两个主机没有互联的原因
- 输入命令进行端口状态查询时，没有显示，是因为没有手动打开对应的tcp与udp端口
- 遇到抓包0抓获的问题，重新调整代码输入顺序，反复尝试解决
- 对端口状态的模拟，刚刚开始总是无法正确区别。后来通过查阅资料利用监听端口和防火墙的结合来进行模拟

## 回顾课本

提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因
答：抓包以截图形式提供在每次扫描结果中，根据与课件学习的对比，完全相符。

## 参考资料

- [TCP Connect Scan (-sT) | Nmap Network Scanning](https://nmap.org/book/scan-methods-connect-scan.html)
- [TCP SYN (Stealth) Scan (-sS) | Nmap Network Scanning](https://nmap.org/book/synscan.html)
- [TCP FIN, NULL, and Xmas Scans (-sF, -sN, -sX) | Nmap Network Scanning](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html)
- [TCP UDP Scan (-sU) | Nmap Network Scanning](https://nmap.org/book/scan-methods-udp-scan.html)
