import base64

hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

# 将十六进制字符串解码为原始字节
raw_bytes = bytes.fromhex(hex_string)

# 将原始字节编码为 Base64
b64_encoded = base64.b64encode(raw_bytes).decode()

print(b64_encoded)
