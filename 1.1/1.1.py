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