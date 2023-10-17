import time
import sys
import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from chebyshev import cbs

#xor function
def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])
#message received from user
with open('phase1_authen.txt') as phase1:
    tf, T3, Cidi, c3, iv3 = phase1.readlines()
#import parameters for chebyshev map
#and the infor of RC
with open('cbs_para.txt') as para:
    x, p, ε, tr = para.readlines()
#Server imports secret key, public key and groupkey
#with open ...
s = 1
ts = 1          #####
gk = 1


#Current timestamp T4
T4 = time.time()
#Check the validity of T3
if T4 - T3 > ε:
    sys.exit()
#Compute tsf and perform following operation
#Bi = Cidi ⊕ H(tsf|T3)
#Ai = Bi ⊕ gk
#k3 = H(T3|tsf) ⊕ H(Ai)
tsf = cbs(s, tf, p)
sha256 = SHA256.new()
sha256.update(tsf + T3) #chua xu li input
h = sha256.digest()
Bi = xor(Cidi, h)
Ai = xor(Bi, gk)

sha256.update(T3+tsf)
k3_1 = sha256.digest()
sha256.update(Ai)
k3_2 = sha256.digest()
k3 = xor(k3_1, k3_2)
#decrypt c3 to receive message sig|ti|T2
decipher = AES.new(k3, AES.MODE_CBC, iv3)
message = decipher.decrypt(c3)
sig = 1
ti = 1     ###
T2 = 1

#signature of RC over the message
#msg = H(T2|GK|Bi|ti)
sha256.update(T2 + gk + Bi + ti)    #chua xu ly dau vao
msg = sha256.digest()
# Verify the signature using the public key
hash_obj = SHA256.new(message)
try:
    pkcs1_15.new(tr).verify(hash_obj, sig)
    print("Signature is valid.")
except (ValueError, TypeError):
    print("Signature is invalid.")
    sys.exit()
#credentials are derived by the RC and not by a potential malicious server
#Generate symmetric shared key
# SK = H(tbf|tbi|tsf|T3|T4)
#b is a randomly chosen parameter
b = random.randint(10**2, 10**3)
tb = cbs(b, x, p)
tbf = cbs(b, tf, p)
tbi = cbs(b, ti, p)
sha256.update(tbf + tbi + tsf + T3 + T4)
sk = sha256.digest()
#Compute C4 = H(SK|tbf|tbi|tsf|T3|T4)
sha256.update(sk+tbf+tbi+tsf+T3+T4)
c4 = sha256.digest()

#send c4, tb, T4 to user
with open('phase2_authen.txt', 'wb') as phase2:
    phase2.writelines(c4, tb, T4)