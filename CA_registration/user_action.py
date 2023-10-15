import random
from Crypto.Hash import SHA256
from chebyshev import cbs
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
#sha256 = SHA256.new()
#sha256.update(infor)
#i = sha256.digest()

#Generate public key ti
#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        x = para.readline()
        p = para.readline()
        ε = para.readline()

ti = cbs(int(infor), x, p)

#Generate user's cert
#Cert include user's id and public key and timestamp Ti
infor = idi + str(ti).encode('utf-8')
Ti = time.time()

#print(infor)

sha = SHA256.new()
sha.update(infor + str(Ti).encode('utf-8'))
hash_i = sha.digest()
#print(hash_i)

cert_i = idi + ti + Ti + hash_i



