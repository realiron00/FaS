"""
Purple 메시지 복호화 코드
"""
import hashlib as hash
import base64
from Crypto.Cipher import AES

def dec_message(user_id, enc_msg):
    #[1] 키 생성
    #AES_Key <- SHA256(ncmop.user_id)
    key = hash.sha256(user_id.encode()).digest()

    #[2] IV 생성
    #IV <- 0
    iv = bytes([0] * 16)

    #[3] Base64로 디코딩
    #Decoded_Message <- Base64_Decode(Encrypted_Message)
    decode_msg = base64.b64decode(enc_msg)
    
    #[4] AES 복호화
    #Decrypted_Message <- AES256_Decrypt(Decoded_Message,AES_Key,IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec_msg = cipher.decrypt(decode_msg)

    return dec_msg

user_id="D0AC0866-E560-4989-8624-8BDA390E5B62"
enc_msg="hl0KyFPmY7y414MnAmQW7c1IqK/Q7sYIY7VHsgXLJ+A="
msg=dec_message(user_id, enc_msg)
print(msg.decode('utf-8'))
