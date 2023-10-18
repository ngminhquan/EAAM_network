import random
from Crypto.Hash import SHA256
from chebyshev import cbs, Tnm2
import time

#xor function
def xor(a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for x, y in zip(a, b)])

#user generate its own key pair (i, ti)
#i = H(ID|PW + rb|Bio)

#generate random variable rb
rb = random.randbytes(3)

#user import ID and password
idi = input("Enter user's ID: ").encode('utf-8')
pw = input("Enter password: ").encode('utf-8')

#Enter biometric data
height = input("Enter your height: ").encode('utf-8')
weight = input("Enter your weight: ").encode('utf-8')
bio = height + weight

infor = idi + xor(pw, rb) + bio

#Calculate user's secret key i
# Compute secret key i by using SHA256
sha256 = SHA256.new()
sha256.update(infor)
i = sha256.digest()     

#Generate public key ti
#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        lines = para.readlines()
        x, p, ε = int(lines[0]), int(lines[1]), int(lines[2])

infor_int = int.from_bytes(infor, byteorder='big')
#print(infor_int, type(infor_int))
ti:int = Tnm2(infor_int, x, p)
#Generate user's cert
#Cert include user's id and public key and timestamp Ti
ti_byte = str(ti).encode()
usr = idi + ti_byte
Ti = time.time()
#print(infor)
sha256.update(usr + str(Ti).encode())
hash_i = sha256.digest()
#print(hash_i)
cert_i = idi + ti_byte + str(Ti).encode() + hash_i

# Save user's infor and cert
#user device
#Ei = H(PW⊕rb|Bio⊕rb|idi)
ei = xor(pw, rb) + xor(bio, rb) + idi
sha256.update(ei)
Ei = sha256.digest()
lines = [idi,b'\n', rb,b'\n', i,b'\n', ti_byte,b'\n',
          str(Ti).encode(),b'\n', cert_i,b'\n', Ei]
with open('user.txt', 'wb') as record:
      record.writelines(lines)