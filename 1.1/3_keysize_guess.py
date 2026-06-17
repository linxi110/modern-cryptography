import base64
# 把第一步的 hamming_distance 函数复制过来
def hamming_distance(s1: bytes, s2: bytes) -> int:
    xor_bytes = bytes(a ^ b for a, b in zip(s1, s2))
    return sum(bin(byte).count('1') for byte in xor_bytes)

# 读取并解码文件
with open("6.txt", "r") as f:
    b64_data = f.read().replace('\n', '')
ciphertext = base64.b64decode(b64_data)

def guess_keysize(ct: bytes, min_size=2, max_size=40):
    distances = []
    for keysize in range(min_size, max_size + 1):
        # 取前4个块
        blocks = [ct[i*keysize:(i+1)*keysize] for i in range(4)]
        total = 0
        pairs = 0
        for i in range(len(blocks)):
            for j in range(i+1, len(blocks)):
                total += hamming_distance(blocks[i], blocks[j])
                pairs += 1
        normalized = (total / pairs) / keysize
        distances.append((keysize, normalized))
    distances.sort(key=lambda x: x[1])
    return distances[:5]  # 多输出几个看看

candidates = guess_keysize(ciphertext)
print("候选密钥长度（长度，归一化距离）：")
for ks, dist in candidates:
    print(f"  {ks}: {dist:.4f}")