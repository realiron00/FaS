"""
Session 데이터베이스 키 추출 코드
"""
from Crypto.Cipher import AES
import base64

#data, iv, key 값을 입력
encrypted_secret_data=base64.b64decode("o+rA3UoMqHHYQGDHT/uL2VthdcI4HzO22NAjbktozfzjhvBE1x5yXvyt5hOB95PU".encode())
encrypted_secret_iv=base64.b64decode("HBsSCZPFWQNVcsIx".encode())
Key=b'\x3F\x9F\x47\xA9\xDB\x8F\x51\x23\xB1\xD1\x85\xA7\x5B\x01\x93\xE1'

#얻은 데이터에서 필요한 값만 추출
data=encrypted_secret_data[:32]
iv=encrypted_secret_iv

#AES GCM 모드로 복호화
cipher=AES.new(Key, AES.MODE_GCM, iv)
dec_key=cipher.decrypt(data)

#키 출력
sql_key=dec_key.hex()
print(sql_key)
