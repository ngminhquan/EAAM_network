#Using the information (IDi, ti, Ti, certi), the user is now able to
#register with the RC without the need of a secure channel 

from Crypto.Hash import SHA256, SHA1
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
from chebyshev import cbs
import time

#import parameters for chebyshev map
#and the infor of RC
with open('cbs_para.txt') as para:
        x, p, ε, tr = para.readlines()
#User import cert, ID, i, ti
with open('user.txt', 'r') as user:
    idi, rb, i, ti, Ti, cert_i = user.readlines()
#Compute value Fi = H(i||IDi)
sha256 = SHA256.new()
sha256.update(i + idi)
Fi = sha256.digest()
#select random value l ∈ R and compute tl
l = random.randint(10**2, 10**4)
tl = cbs(l, x, p)
#Compute tlr and tir, use public key tr of RC
tlr = cbs(l, tr, p)
tir = cbs(i, tr, p)
#Current timestamp T1
T1 = time.time()
#derive  a dynamic secret k1 with the RC
#k1 = H(tir||T1||idi)
sha256.update(tir + T1 + idi)  #chua xu ly dau vao
k1 = sha256.digest()

#Encrypt message containing k1|Fi|idi|ti|Ti|cert_i|tr
#Use key t_lr = H(tlr||T1)
sha256.update(tlr+ T1)  #chua xu ly dau vao
t_lr = sha256.digest()  #key co dai 128bit?

message = k1 + Fi + idi + ti + Ti + cert_i + tr
#Send message C1, tl, T1 to RC 
#ciphertext = E(t_lr, message)
#Also send iv for decrypt at RC
iv = get_random_bytes(16)
cipher = AES.new(t_lr, AES.MODE_CBC, iv)

#padding bit for data if necessary
block_size = 16
message += b' ' * (block_size - len(message) % block_size)
# Encrypt data
c1 = cipher.encrypt(message)

with open('phase1_msg.txt', 'wb') as phase1:
      phase1.writelines(c1, T1, tl, iv)
#User save information for phase3
with open('p1_usr.txt', 'wb') as p1:
      p1.writelines(l, tl, tlr, t_lr, T1)