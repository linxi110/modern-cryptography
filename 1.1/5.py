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