import base64


# ---------- 复制所有前面验证过的函数 ----------
def hamming_distance(s1: bytes, s2: bytes) -> int:
    xor_bytes = bytes(a ^ b for a, b in zip(s1, s2))
    return sum(bin(byte).count('1') for byte in xor_bytes)


def score_english(text: str) -> float:
    char_freq = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
        'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
        'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
        'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
        'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
        'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
        'y': 0.01974, 'z': 0.00074, ' ': 0.13000
    }
    score = 0.0
    for c in text.lower():
        if c in char_freq:
            score += char_freq[c]
        elif not c.isprintable():
            score -= 0.5
    return score


def break_single_byte_xor(ciphertext: bytes):
    best_score = -float('inf')
    best_key = 0
    best_plain = b''
    for key in range(256):
        plain = bytes(b ^ key for b in ciphertext)
        try:
            text = plain.decode('ascii')
            s = score_english(text)
            if s > best_score:
                best_score = s
                best_key = key
                best_plain = plain
        except:
            continue
    return best_key, best_plain, best_score


# --------------------------------------------

# 读取密文
with open("6.txt", "r") as f:
    b64_data = f.read().replace('\n', '')
ciphertext = base64.b64decode(b64_data)


def crack_with_keysize(ct: bytes, keysize: int):
    """根据密钥长度破解重复密钥异或"""
    # 分块
    blocks = [ct[i:i + keysize] for i in range(0, len(ct), keysize)]

    # 转置并破解每个位置的密钥字节
    key = []
    for i in range(keysize):
        transposed = bytes(block[i] for block in blocks if i < len(block))
        key_byte, _, _ = break_single_byte_xor(transposed)
        key.append(key_byte)

    key_bytes = bytes(key)

    # 解密全文
    plaintext = bytes(ct[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(ct)))
    return key_bytes, plaintext


# 用第三步找到的最佳候选长度尝试（例如 29）
key, plaintext = crack_with_keysize(ciphertext, 29)
print("密钥:", key.decode('ascii'))
print("=" * 60)
print(plaintext.decode('ascii'))