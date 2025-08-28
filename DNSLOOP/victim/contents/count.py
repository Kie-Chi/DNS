# counter.py (版本 Multi-threading)
import sys
import time
import threading
from scapy.all import sniff, DNS

# --- 共享资源 ---
# 使用 threading.Lock 来确保线程安全
packet_lock = threading.Lock()
packet_count = 0
# 使用一个Event来优雅地停止工作线程
stop_event = threading.Event()
# 从命令行参数获取接口名
INTERFACE_TO_MONITOR = sys.argv[1] if len(sys.argv) > 1 else "br-0ff9beaa2901"

def packet_callback(packet):
    """回调函数，在线程保护下更新计数器"""
    global packet_count
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        with packet_lock:
            packet_count += 1

def sniff_worker():
    """在后台运行的抓包工作线程"""
    try:
        # sniff 会一直运行，直到 stop_event 被设置
        sniff(iface=INTERFACE_TO_MONITOR, filter="udp port 53", prn=packet_callback, store=0, stop_filter=lambda p: stop_event.is_set())
    except Exception as e:
        # 如果接口不存在或权限不足，工作线程会在这里出错
        print(f"\n[!] Exception: {e}")
        stop_event.set() # 通知主线程也停止

def main():
    global packet_count
    
    print(f"[*] Iface '{INTERFACE_TO_MONITOR}' Listen...")
    print("[*] Ctrl+C to stop")

    # 创建并启动抓包线程
    worker = threading.Thread(target=sniff_worker, daemon=True)
    worker.start()
    
    start_time = time.time()
    last_count = 0

    try:
        while not stop_event.is_set():
            time.sleep(1) # 每秒打印一次
            
            with packet_lock:
                current_count = packet_count
                
            pps = current_count - last_count
            last_count = current_count
            elapsed_time = time.time() - start_time

            sys.stdout.write(
                f"packets: {current_count:<10d} | "
                f"rate: {pps:<8d} pps  "
            )
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n\n[*] stop the sniff thread...")
        stop_event.set()
        worker.join() # 等待工作线程完全停止
        
        elapsed_time = time.time() - start_time
        avg_pps = packet_count / elapsed_time if elapsed_time > 0 else 0
        
        print("="*50)
        print("[*] All Done：")
        print(f"    - Iface: {INTERFACE_TO_MONITOR}")
        print(f"    - Last: {elapsed_time:.2f} s")
        print(f"    - Packets: {packet_count}")
        print(f"    - Rate: {avg_pps:.2f} pps")
        print("="*50)

if __name__ == "__main__":
    main()