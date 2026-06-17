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