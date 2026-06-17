def hamming_distance(s1: bytes, s2: bytes) -> int:
    """计算两个字节串的汉明距离（不同比特位数）"""
    xor_bytes = bytes(a ^ b for a, b in zip(s1, s2))
    distance = sum(bin(byte).count('1') for byte in xor_bytes)
    return distance

# 验证
s1 = b"this is a test"
s2 = b"wokka wokka!!!"
print(hamming_distance(s1, s2))  # 必须是 37