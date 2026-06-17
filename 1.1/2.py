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