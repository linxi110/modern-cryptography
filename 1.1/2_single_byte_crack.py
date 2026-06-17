def score_english(text: str) -> float:
    """根据字符频率给英文文本打分"""
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
        except:
            continue

    return best_key, best_plain, best_score


# 用第3题的密文验证
hex_str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
ciphertext = bytes.fromhex(hex_str)
key, plain, score = break_single_byte_xor(ciphertext)
print(f"密钥: {key} ({chr(key)})")
print(f"明文: {plain.decode()}")