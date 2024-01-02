#AES

from Crypto.Cipher import AES
from Crypto import Random
import base64

def Encrypt(massage):
    print ("encryp function")
    padding="*"
    block_size=16
    key=Random.new().read(16)
    iv=Random.new().read(16)
    q=lambda a : a +(block_size - len(a) % block_size ) * padding
    E=AES.new(key,AES.MODE_CBC,iv)
    ciphertext=base64.b64encode(iv + E.encrypt(q('asma').encode('utf-8')))
    data=[key,ciphertext]
    return data
    

a=Encrypt("asma ahmed")
key=a[0]
ciphertext=a[1]
print(ciphertext)

def Decrypt(key,cipher):
    iv=base64.b64decode(ciphertext)[:16]
    encrypted_massage=base64.b64decode(ciphertext)[16:]
    d=AES.new(key,AES.MODE_CBC,iv)
    plain_text=d.decrypt(encrypted_massage).decode('utf-8')
    return plain_text.rstrip("*")

g=Decrypt(key,ciphertext)
print(g)
    
    

