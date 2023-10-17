from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
from chebyshev import cbs
import time

#xor function
def xor(a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for x, y in zip(a, b)])
#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        x, p, ε = para.readlines()
#Stored data of user
with open('user.txt') as user:
    idi, rb, i, ti, Ti, cert_i, Ei, \
    Bi, Ci, T2, sig = user.readlines()
#User computes Fi = H(i|idi)
sha256 = SHA256.new()
sha256.update(i + idi)
Fi = sha256.digest()
#look up public key ts of server S in 'server_record.txt'
ts = 1
#Pick up randomvalue f, compute tf and tfs
f = random.randint(10**2, 10**3)
tf = cbs(f, x, p)
tfs = cbs(f, ts, p)
#Compute data with current timestamp T3
T3 = time.time()
#H(Ai) = Ci ⊕ H(Fi, ti, idi)
#Cidi = Bi ⊕ H(tfs|T3)
#k3 = H(T3|tfs) ⊕ H(Ai)
sha256.update(Fi + ti + idi)
h1 = sha256.digest()
H_Ai = xor(Ci, h1)

sha256.update(tfs + T3)
h2 = sha256.digest()
Cidi = xor(Bi, h2)

sha256.update(T3 + tfs)
h3 = sha256.digest()
k3 = xor(h3, H_Ai)
#Encrypt message sig|ti|T2 using key
#c3 = E(k3, sig||ti||T2)
#Generate IV for encryption
iv3 = get_random_bytes(16)
msg = sig + ti + T2
cipher = AES.new(k3, AES.MODE_CBC, iv3)
#padding bit for data if necessary
block_size = 16
msg += b' ' * (block_size - len(msg) % block_size)
c3 = cipher.encrypt(msg)

#Transmit the message tf, T3, Cidi, c3
with open('phase1_authen.txt', 'wb') as phase1:
       phase1.writelines(tf, T3, Cidi, c3, iv3)

#User save information for phase3
with open('p1_usr_authen.txt', 'wb') as p1:
      p1.writelines(f, tf, T3, tfs)