from Crypto.Hash import SHA256
import random
from chebyshev import cbs

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