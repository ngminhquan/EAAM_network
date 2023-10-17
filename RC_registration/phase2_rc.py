import time
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from chebyshev import cbs
import sys

#xor function
def xor(a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for x, y in zip(a, b)])
#RC has its own secret key
#Call secret key from rc_key.txt
with open('rc_key.txt') as rc:
      r, gk = rc.readlines()
#import parameters for chebyshev map
#and the infor of RC
with open('cbs_para.txt') as para:
        x, p, ε, tr = para.readlines()

#Read the message sent from user
with open('phase1_msg.txt') as phase1:
   c1, T1, tl, iv = phase1.readlines()
   
#Current timestamp T2
#Check the validity of the timestamp
#if T2 - T1 <= ε
T2 = time.time()
if T2 - T1 > ε:
      sys.exit()
#RC computes tri, trl and t_rl from data received from user
#find trl by using chebyshev Tr(tl) mod p
trl = cbs(r, tl, p)

sha256 = SHA256.new()
sha256.update(trl+ T1)  #chua xu ly dau vao
t_rl = sha256.digest()  #key co dai 128bit?

#Decrypt ciphertext c1 to receive message
#message includes k1|Fi|idi|ti|Ti|cert_i|tr
decipher = AES.new(t_rl, AES.MODE_CBC, iv)
message = decipher.decrypt(c1)

#Take each part of message to 
# find k1,Fi,idi,ti,Ti,cert_i,tr
k1 = message[:32]
Fi = message[32:64]
idi = message[6]    #how to identify lenghth of each para?
ti = message[1]     #
Ti = message[1]     #
cert_i = message    #32bytes
tr = message        #

#Find tri using chebyshev map
tri = cbs(r, ti, p)
#Check the validity of cert_i and k1
#Regenerate cert_i
infor = idi + str(ti).encode('utf-8')
sha = SHA256.new()
sha.update(infor + str(Ti).encode('utf-8'))
hash_i = sha.digest()
#print(hash_i)
cert_check = idi + ti + Ti + hash_i
if cert_check != cert_i:
      print("invalid user's certificate")
      sys.exit()
#Regenrate k1
#k1 = H(tir||T1||idi)
sha256.update(tri + T1 + idi)  #chua xu ly dau vao
k1_check = sha256.digest()
if k1 != k1_check:
      print('invalid key k1')
      sys.exit()

#All checks are positive
#RC computes parameters to send to user
#RC generate secret parameter y
y = input('Enter secret parameter y: ').encode('utf-8')
#n: the number of registrations performed by IDi
n = b''
#Ai = H(idi|GK|y|n)
#Bi = Ai XOR GK
#Ci = H(Ai) XOR H(Fi|ti|idi)
#k2 = H(trl|T1|T2|idi)
sha256.update(idi + gk + y + n) #chua xu ly dau vao
Ai = sha256.digest()
Bi = xor(Ai, gk)      #chua xu ly dau vao

sha256.update(Ai)
ci1 = sha256.digest()
sha256.update(Fi + ti + idi)
ci2 = sha256.digest()
Ci =xor(ci1, ci2)

sha256.update(trl + T1 + T2 + idi)
k2 = sha256.digest()
#Compute signature of RC over the message
#msg = H(T2|GK|Bi|ti)
sha256.update(T2 + gk + Bi + ti)    #chua xu ly dau vao
msg = sha256.digest()
#Sign the message using secret key r of RC
hash_obj = SHA256.new(msg)
sig = pkcs1_15.new(r).sign(hash_obj)

#Send C2, T2 to user
#message = Bi|Ci|T2|sig
#C2 = E(k2, message)
message = Bi + Ci + T2 + sig
#Also send iv for decrypt at RC
iv2 = get_random_bytes(16)
cipher = AES.new(t_rl, AES.MODE_CBC, iv)

#padding bit for data if necessary
block_size = 16
message += b' ' * (block_size - len(message) % block_size)
# Encrypt data
c2 = cipher.encrypt(message)

with open('phase2_msg.txt') as phase2:
      phase2.writelines(c2, T2, iv2)