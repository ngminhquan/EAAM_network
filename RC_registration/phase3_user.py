import time
import sys
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

#User import cert, ID, i, ti
with open('user.txt', 'r') as user:
    idi, i, ti, Ti, cert_i = user.readlines()
#information in phase1 of user:
with open('p1_usr.txt') as p1:
      l, tl, tlr, t_lr, T1 = p1.readlines()
#Read the message sent from RC
with open('phase2_msg.txt') as phase2:
    c2, T2, iv2 = phase2.readlines()
#import parameters for chebyshev map
#and the infor of RC
with open('cbs_para.txt') as para:
    x, p, ε, tr = para.readlines()

#Current timestamp T3
#Check the validity of the timestamp
#if T3 - T2 <= ε
T3 = time.time()
if T3 - T2 > ε:
      sys.exit()
#User compute k2 and decrypt C2
#k2 = H(tlr, T1, T2, idi)
sha256 = SHA256.new()
sha256.update(tlr + T1 + T2 + idi)
k2 = sha256.digest()
#Decrypt C2 to receive Bi|Ci|T2|sig
decipher = AES.new(t_lr, AES.MODE_CBC, iv2)
msg = decipher.decrypt(c2)
Bi = b''
Ci = b''
T2 = b''
sig = b''

#User stores Bi, Ci, T2, sig in device
with open('user.txt', 'ab') as record:
      record.writelines(Bi, Ci, T2, sig)