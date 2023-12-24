"""
Agit realm 복호화 코드
"""
from Crypto.Cipher import AES
#Input-Encryption Key
Enc_Key=[80, 109, 145, 210, 145, 208, 212, 178, 
         78, 243, 251, 128, 225,  84,  40,  96, 
         158, 180, 152, 122, 244, 144, 150, 223, 
         154, 205, 126, 165, 173, 209,  70,  95,  
         80, 141,  79,  71, 165, 158,  49,  52, 
         207, 253,  14, 141, 215, 168,  11, 129, 
         156, 117, 101, 193,  80, 229, 133, 129, 
         72, 215, 245,  81, 233, 139,  58,  98]
#=>f21046h

#Input-Encrypted Realm Database
Enc_Realm_name="default.realm"
f = open(Enc_Realm_name, 'rb')
Enc_Realm = f.read()
f.close()

#Pos<-0
Pos=0

#Aes Key<-Upper 32 bytes of Encryption Key
AES_Key=bytes(Enc_Key[:32])

Dec = []

#n: Database Block의 개수
n=len(Enc_Realm[0x1000:])// 4096
for i in range(0, n):
    #Get IV_Table from Decrypted Realm Database
    IV_Table=Enc_Realm[64*i:64*(i+1)]
    
    #Compute IV<-IV_Table.iv1||Pos||00000000
    IV=bytes(list(IV_Table[:4])+list((Pos).to_bytes(4,byteorder='big'))+[0]*8)
    
    #Decrypt D_i<-AES256-CBC(C_i, AES Key, IV)
    Enc_block=Enc_Realm[0x1000*(i+1):0x1000*(i+2)]
    cipher = AES.new(bytes(AES_Key), AES.MODE_CBC, IV)
    Dec_block=list(cipher.decrypt(Enc_block))

    #Write D_i in Decrypted Realm Database
    Dec += Dec_block
    
    #Pos<-Pos+4096
    Pos+=4096

f = open("Dec_Realm.realm", 'wb')
f.write(bytes(Dec))
f.close()
