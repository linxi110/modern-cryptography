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
        print("没有找到有效的明文")


if __name__ == "__main__":
    challenge4()