# packet_counter.py
import sys
import time
from scapy.all import sniff, DNS, DNSQR

# 全局变量来存储计数
packet_count = 0

def packet_callback(packet):
    """
    scapy每捕获一个数据包就会调用这个函数。
    """
    global packet_count
    # 检查数据包是否是DNS查询 (DNS层存在，并且QR标志位为0)
    if packet.haslayer(DNS) and packet[DNS].opcode == 0 and packet[DNS].qr == 0:
        packet_count += 1
        # 实时打印，方便观察 (可以注释掉以获得更干净的最终输出)
        sys.stdout.write(f"\rPackets received: {packet_count}")
        sys.stdout.flush()

def main():
    global packet_count
    
    print("[*] Starting DNS packet counter on interface 'eth0'...")
    print("[*] Listening for incoming DNS queries on UDP port 53.")
    print("[*] Press Ctrl+C to stop and see the final count.")

    # 设置信号处理，优雅地处理Ctrl+C
    try:
        # sniff()是scapy的核心函数，用于嗅探网络包
        # iface="eth0": 监听Docker容器内的eth0网卡
        # filter="udp port 53": 只捕获UDP 53端口的流量
        # prn=packet_callback: 指定回调函数
        # store=0: 不在内存中存储数据包，节省资源
        sniff(iface="eth0", filter="udp port 53", prn=packet_callback, store=0)
    
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user.")
        print("="*30)
        print(f"[*] Final packet count: {packet_count}")
        print("="*30)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        print("[!] Please ensure you are running this script with root privileges")
        print("[!] and that the 'eth0' interface exists.")

if __name__ == "__main__":
    main()