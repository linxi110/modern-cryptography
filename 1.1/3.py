def single_byte_xor_crack(hex_str):
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