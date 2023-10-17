import time
import sys
from chebyshev import cbs
from Crypto.Hash import SHA256

#Stored data of user
with open('user.txt') as user:
    idi, rb, i, ti, Ti, cert_i, Ei, \
    Bi, Ci, T2, sig = user.readlines()
#import parameters for chebyshev map
#and the infor of RC
with open('cbs_para.txt') as para:
    x, p, ε, tr = para.readlines()
#message received from server
with open('phase2_authen.txt') as phase2:
    c4, tb, T4 = phase2.readlines()
#information from phase1
with open('p1_usr_authen.txt', 'wb') as p1:
      f, tf, T3, tfs = p1.readlines()

#Current timestamp T5
#Check the validity of timestamp
T5 = time.time()
if T5 - T4 > ε:
    print('invalid timestamp')
    sys.exit()
#Compute tib, tfb
tib = cbs(i, tb, p)
tfb = cbs(f, tb, p)
#Generate symmetric shared key
# SK = H(tbf|tbi|tsf|T3|T4)
sha256 = SHA256.new()
sha256.update(tfb + tib + tfs + T3 + T4)
sk = sha256.digest()
#Check the validity of C4
#Compute C4 = H(SK|tbf|tbi|tsf|T3|T4)
sha256.update(sk+tfb+tib+tfs+T3+T4)
c4_check = sha256.digest()
if c4 != c4_check:
    print('invalid message')
    sys.exit()
print('final symmetric key: ', sk)