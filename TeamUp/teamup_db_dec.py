"""
TeamUp 데이터베이스 키 추출 코드
"""
import hashlib as hash
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

and_id="2ef2fd8cf6a48253"

msg_digest=hash.sha256(and_id.encode()).digest()
str_Buffer=""
for b in msg_digest:
    str_Buffer+=format((b&255)+256,'x')[1:]

def m2(str):
    messageDigest = hash.sha256()
    bytes = str.encode("UTF-8")
    messageDigest.update(bytes)
    return messageDigest.digest()

m2131c = m2(str_Buffer)
iv=bytes([0]*16)
byte = str_Buffer.encode("UTF-8")
cipher = AES.new(m2131c, AES.MODE_CBC, iv)
encrypted_byte = cipher.encrypt(pad(byte, AES.block_size))
sql_key = base64.b64encode(encrypted_byte).decode("UTF-8")

print(sql_key)
