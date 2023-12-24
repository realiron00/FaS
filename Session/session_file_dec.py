"""
Session 첨부 파일 복호화 코드
"""
from Crypto.Cipher import AES
from Crypto.Util import Counter
from binascii import hexlify
import base64
import hmac
import hashlib
import os

#정보 받기
dec_name=input("decrypt file name : ") #복호화된 파일의 이름 정하기
modernKey_v1=input("modernKey : ") #modernKey 입력
data_random_name=input("data_random file name : ") #data_random 값을 저장한 파일 경로 입력
mms_file_name=input("mms file name : ") #mms파일 경로 입력

#data_random 값 저장
with open(data_random_name, 'rb') as f:
    data_randon=f.read()
f.close()

#mms파일 값 저장
with open(mms_file_name, 'rb') as f:
    mms_file=f.read()
f.close()

#modernKey값을 base64로 저장
modernKey_v2 = modernKey_v1 + '=' * (4-len(modernKey_v1)%4)
modernKey=base64.b64decode(modernKey_v2)

#HmacSHA256으로 키 생성
AES_Key=hmac.new(modernKey,data_randon,hashlib.sha256).digest()

#AES_CTR로 파일 복호화
specific_IV = 0 
counter_value = Counter.new(128, initial_value=specific_IV)
cipher=AES.new(AES_Key, AES.MODE_CTR, counter=counter_value)
dec_file=cipher.decrypt(mms_file)

#복호화된 파일 저장
with open(os.path.join(os.path.dirname(mms_file_name), dec_name), 'wb') as f:
    f.write(dec_file)

print("\ndone")
