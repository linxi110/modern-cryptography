# modern-cryptography
现代密码学实验1
[1.1.py](https://github.com/user-attachments/files/27851544/1.1.py)

import base64


# ==================== 工具函数 ====================

def hamming_distance(s1: bytes, s2: bytes) -> int:
    """计算两个字节串的汉明距离（不同比特位数）"""
    xor_bytes = bytes(a ^ b for a, b in zip(s1, s2))
    distance = sum(bin(byte).count('1') for byte in xor_bytes)
    return distance


def score_english(text: str) -> float:
    """根据字符频率给英文文本打分，用于识别最像英文的明文"""
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
            score -= 0.5  # 不可打印字符扣分
    return score


def break_single_byte_xor(ciphertext: bytes):
    """破解单字节异或，返回 (密钥整数, 明文bytes, 评分)"""
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
        except UnicodeDecodeError:
            continue  # 跳过无法解码为ASCII的密钥

    return best_key, best_plain, best_score


# ==================== 核心破解逻辑 ====================

def guess_keysize(ciphertext: bytes, min_size=2, max_size=40, num_blocks=4):
    """
    推测最可能的密钥长度。
    对每个长度，取密文前 num_blocks 个块，计算两两之间的归一化汉明距离。
    返回距离最小的前 3 个候选长度。
    """
    distances = []

    for keysize in range(min_size, max_size + 1):
        # 确保密文足够长以取 num_blocks 个块
        if len(ciphertext) < keysize * num_blocks:
            continue

        blocks = [ciphertext[i * keysize:(i + 1) * keysize] for i in range(num_blocks)]
        total_dist = 0
        pair_count = 0

        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                total_dist += hamming_distance(blocks[i], blocks[j])
                pair_count += 1

        # 归一化：平均距离除以密钥长度
        normalized_dist = (total_dist / pair_count) / keysize
        distances.append((keysize, normalized_dist))

    # 按距离从小到大排序
    distances.sort(key=lambda x: x[1])
    # 返回前3个最可能的密钥长度
    return [keysize for keysize, _ in distances[:3]]


def crack_repeating_key_xor(ciphertext: bytes, keysize: int):
    """
    根据给定的密钥长度破解重复密钥异或。
    1. 将密文按密钥长度分块。
    2. 转置分块：把每个块的第一个字节组成新块，第二个字节组成新块……
    3. 对每个转置块用单字节异或破解，得到密钥的一个字节。
    4. 拼接密钥并解密全文。
    """
    # 1. 分块
    blocks = [ciphertext[i:i + keysize] for i in range(0, len(ciphertext), keysize)]

    # 2. 转置并破解每个位置的密钥字节
    key = []
    for i in range(keysize):
        # 取出每个块的第 i 个字节，组成新的“单字节异或密文”
        transposed_block = bytes(block[i] for block in blocks if i < len(block))
        # 破解这个单字节异或块
        key_byte, _, _ = break_single_byte_xor(transposed_block)
        key.append(key_byte)

    key_bytes = bytes(key)

    # 3. 用得到的密钥解密全文
    plaintext = bytes(
        ciphertext[i] ^ key_bytes[i % len(key_bytes)]
        for i in range(len(ciphertext))
    )

    return key_bytes, plaintext


# ==================== 主程序 ====================

def main():
    # 1. 读取并解码 Base64 密文文件
    try:
        with open("6.txt", "r") as f:
            b64_data = f.read().replace('\n', '')  # 去掉换行符
        ciphertext = base64.b64decode(b64_data)
    except FileNotFoundError:
        print("错误：找不到文件 6.txt，请确保它与本脚本在同一目录下。")
        return

    print("已加载密文，长度：{} 字节".format(len(ciphertext)))

    # 2. 推测密钥长度
    print("\n正在推测密钥长度...")
    candidates = guess_keysize(ciphertext)
    print("最佳候选密钥长度：", candidates)

    # 3. 依次尝试每个候选长度
    for keysize in candidates:
        print(f"\n===== 尝试密钥长度: {keysize} =====")
        key_bytes, plaintext = crack_repeating_key_xor(ciphertext, keysize)

        try:
            key_str = key_bytes.decode('ascii')
            plain_str = plaintext.decode('ascii')

            print(f"密钥: {key_str}")
            print("-" * 40)
            print(plain_str[:500])  # 打印前500个字符作为预览
            print("-" * 40)

        except UnicodeDecodeError:
            print(f"密钥长度 {keysize} 解密结果含不可解码字节，跳过。")


if __name__ == "__main__":
    main()

    
[1.py](https://github.com/user-attachments/files/27851549/1.py)
import base64

hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

# 将十六进制字符串解码为原始字节
raw_bytes = bytes.fromhex(hex_string)

# 将原始字节编码为 Base64
b64_encoded = base64.b64encode(raw_bytes).decode()

print(b64_encoded)


[2.py](https://github.com/user-attachments/files/27851552/2.py)
def fixed_xor(hex_str1, hex_str2):
    # 将十六进制字符串解码为原始字节
    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)

    # 逐字节异或
    xor_result = bytes(a ^ b for a, b in zip(bytes1, bytes2))

    # 编码回十六进制字符串
    return xor_result.hex()


# 测试
str1 = "1c0111001f010100061a024b53535009181c"
str2 = "686974207468652062756c6c277320657965"
expected = "746865206b696420646f6e277420706c6179"

result = fixed_xor(str1, str2)
print(result)
print("匹配:", result == expected)


[3.py](https://github.com/user-attachments/files/27851557/3.py)def single_byte_xor_crack(hex_str):
    ciphertext = bytes.fromhex(hex_str)

    # 英文字符频率权重（ETAOIN SHRDLU 顺序）
    char_freq = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
        'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
        'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
        'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
        'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
        'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
        'y': 0.01974, 'z': 0.00074, ' ': 0.13000
    }

    best_score = 0
    best_key = None
    best_plaintext = ""

    for key in range(256):
        # 解密：每个字节与密钥异或
        plaintext_bytes = bytes(b ^ key for b in ciphertext)

        # 评分
        score = 0
        for byte in plaintext_bytes:
            char = chr(byte).lower()
            if char in char_freq:
                score += char_freq[char]
            # 不可打印字符或控制字符扣分
            elif byte < 32 or byte > 126:
                score -= 0.5

        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext_bytes.decode('ascii', errors='replace')

    return best_key, best_plaintext


# 执行破解
hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
key, plaintext = single_byte_xor_crack(hex_str)
print(f"密钥: {key} ({chr(key)})")
print(f"明文: {plaintext}")


[4.py](https://github.com/user-attachments/files/27851564/4.py)
import requests
from typing import Tuple, Optional


# 第三题中的评分函数和破解逻辑可以复用
# 这是基于字符频率的评分函数
def score_english_text(text: str) -> float:
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


# 改进后的单字节异或破解，返回 (密钥, 明文, 评分)
def crack_single_byte_xor(hex_str: str) -> Tuple[int, str, float]:
    ciphertext = bytes.fromhex(hex_str)
    best_score = -float('inf')
    best_key = 0
    best_plain = ""

    for key in range(256):
        plain_bytes = bytes(b ^ key for b in ciphertext)
        try:
            plain_str = plain_bytes.decode('ascii')
        except UnicodeDecodeError:
            continue
        s = score_english_text(plain_str)
        if s > best_score:
            best_score = s
            best_key = key
            best_plain = plain_str

    return best_key, best_plain, best_score


# 第四题主逻辑
def challenge4():
    # 1. 下载文件内容
    url = "https://cryptopals.com/static/challenge-data/4.txt"
    response = requests.get(url)
    lines = response.text.strip().split('\n')

    best_overall_score = -float('inf')
    best_result = None  # 存储(行号, hex字符串, 密钥, 明文)

    for line_num, hex_line in enumerate(lines, 1):
        if not hex_line.strip():
            continue
        try:
            key, plain, score = crack_single_byte_xor(hex_line.strip())
            if score > best_overall_score:
                best_overall_score = score
                best_result = (line_num, hex_line.strip(), key, plain)
        except Exception:
            continue

    if best_result:
        line_num, hex_str, key, plain = best_result
        print(f"找到加密行号: {line_num}")
        print(f"原始十六进制: {hex_str}")
        print(f"密钥: {key} ('{chr(key)}')")
        print(f"明文: {plain}")
    else:
        pdef repeating_key_xor(plaintext: str, key: str) -> str:
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key.encode('utf-8')

    ciphertext = bytes(
        plaintext_bytes[i] ^ key_bytes[i % len(key_bytes)]
        for i in range(len(plaintext_bytes))
    )

    return ciphertext.hex()


# 测试给出的示例
plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"

expected = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
            "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

result = repeating_key_xor(plaintext, key)
print("结果:", result)
print("匹配:", result == expected)rint("没有找到有效的明文")


if __name__ == "__main__":
    challenge4()


[5.py](https://github.com/user-attachments/files/27851627/5.py)
def repeating_key_xor(plaintext: str, key: str) -> str:
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key.encode('utf-8')

    ciphertext = bytes(
        plaintext_bytes[i] ^ key_bytes[i % len(key_bytes)]
        for i in range(len(plaintext_bytes))
    )

    return ciphertext.hex()


# 测试给出的示例
plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"

expected = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
            "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

result = repeating_key_xor(plaintext, key)
print("结果:", result)
print("匹配:", result == expected)


[sha1.py](https://github.com/user-attachments/files/27851641/sha1.py)
import hashlib
import itertools
import time

start_time = time.time()

target_hash = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

# 每个按键的 [下档字符, 上档字符]
fingerprint_keys = [
    ['Q', 'q'],
    ['W', 'w'],
    ['I', 'i'],
    ['N', 'n'],
    ['*', '+'],  # + 键：下档是 +，上档是 *
    ['(', '8'],  # 8 键：下档是 8，上档是 (
    ['=', '0'],  # 0 键：下档是 0，上档是 =
    ['%', '5']  # 5 键：下档是 5，上档是 %
]


def crack_password(key_pairs, target):
    """
    key_pairs: 每个元素是 [下档字符, 上档字符]
    """
    n = len(key_pairs)

    # 枚举每个键选上档(索引1)还是下档(索引0) —— 共 2^n 种组合
    for mask in range(1 << n):  # 0 到 2^n - 1
        chosen_chars = []
        for i in range(n):
            if mask & (1 << i):  # 第 i 位为 1 选上档
                chosen_chars.append(key_pairs[i][1])
            else:  # 否则选下档
                chosen_chars.append(key_pairs[i][0])

        # 对选出的 n 个字符做全排列
        for perm in itertools.permutations(chosen_chars):
            password = ''.join(perm)
            sha1_hash = hashlib.sha1(password.encode()).hexdigest()

            if sha1_hash == target:
                return password

    return None


result = crack_password(fingerprint_keys, target_hash)

if result:
    print(f"找到密码: {result}")
else:
    print("未找到匹配的密码，请检查指纹键列表是否正确")

end_time = time.time()
elapsed = end_time - start_time
print(f"\n总运行时间: {elapsed:.2f} 秒 ({elapsed / 60:.2f} 分钟)")

现代密码学第一次实验
