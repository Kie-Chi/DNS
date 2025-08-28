# TsuKING 攻击复现环境

## 说明
本仓库提供了基于 Docker 的环境，用于本地复现三种 **TsuKING** DNS 放大攻击变体：**DNSRETRY**, **DNSCHAIN**, 和 **DNSLOOP**。每种攻击变体都包含在独立的目录中，可以独立运行和测试

---

## 实验一：DNSRETRY 攻击

### 环境搭建
1.  进入 `dnsretry` 目录：
    ```shell
    cd dnsretry
    ```
2.  使用 Docker Compose 构建并启动所有服务（包括易受攻击的 DRS、恶意权威服务器、受害者）：
    ```shell
    docker compose up --build
    ```

### 攻击执行
攻击通过向易受攻击的 DRS 发送一次对 `example.com` 的 DNS 查询来触发。这将激活其激进的重试机制。

1.  在任意终端执行 `dig` 命令（或进入 `drs` 容器内执行）：
    ```shell
    # 向易受攻击的 DRS (10.5.0.2) 发送触发查询
    dig @10.5.0.2 example.com
    ```

### 观察攻击效果
`victim` 容器中运行了一个数据包计数器。您可以进入该容器来观察从 DRS 涌入的大量 DNS 查询流量。

1.  在受害者机器上启动数据包计数器脚本：
    ```shell
    docker compose exec victim python3 /app/count.py
    ```
2.  您将看到接收到的数据包数量迅速增加，这直观地展示了放大攻击的效果
    ```
    [*] Starting DNS packet counter on interface 'eth0'...
    [*] Listening for incoming DNS queries on UDP port 53.
    [*] Press Ctrl+C to stop and see the final count.
    Packets received: 532
    ```

---

## 实验二：DNSCHAIN 攻击

### 环境搭建
1.  进入 `dnschain` 目录：
    ```shell
    cd dnschain
    ```
2.  构建并启动多级解析器链、智能权威服务器和受害者：
    ```shell
    docker compose up --build
    ```

### 攻击执行
向攻击链的第一个入口解析器 (`forwarder-l1`) 发送单次查询，即可启动级联放大过程

1.  发送触发查询：
    ```shell
    dig @10.4.0.5 a.example.com
    ```

### 观察攻击效果
您可以在两个关键位置观察攻击：智能权威服务器的日志（显示攻击链的构建过程）和最终受害者的数据包计数

1.  **查看权威服务器日志**，实时观察路由决策：
    ```shell
    docker compose logs -f auth
    ```
    日志会显示是哪个级别的解析器正在查询，以及它被导向了何处

2.  **在受害者上观察最终的放大流量**：
    ```shell
    docker compose exec victim python3 /app/count.py
    ```
    此处的数据包计数将远高于初始查询，展示了整个攻击链的综合放大效应

---

## 实验三：DNSLOOP 攻击


### 环境搭建
1.  进入 `dnsloop` 目录：
    ```shell
    cd dnsloop
    ```
2.  构建并启动三个被配置为循环转发路径的解析器 (`unbound-a`, `unbound-b`, `unbound-c`)：
    ```shell
    docker compose up --build
    ```

### 攻击执行
向环路中的**任意一个**解析器注入单次 DNS 查询，查询便会开始循环

1.  向 `unbound-a` (`10.4.0.4`) 发送触发查询：
    ```shell
    dig @10.4.0.4 example.com
    ```

### 观察攻击效果
由于解析器本身就是受害者，观察攻击的最佳方式是查看它们的日志。您会看到由于查询的无限循环，日志会以极高的速度滚动输出

1.  同时追踪三个解析器容器的日志：
    ```shell
    docker compose logs -f unbound-a unbound-b unbound-c
    ```
2.  您将看到一条持续、高速滚动的日志流，显示相同的查询被反复接收和转发，确认攻击环路已被激活
