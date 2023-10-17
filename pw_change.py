#The user first logs in with identity and password.
#he device checks the entered information with Ei.
from Crypto.Hash import SHA256
import random
from chebyshev import cbs
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
#user import ID and password, enter biometric data
#computes Ei and check the validity of Ei
#Ei = H(PW⊕rb|Bio⊕rb|idi)
while(1):
    idi = input("Enter user's ID: ").encode('utf-8')
    pw = input("Enter password: ").encode('utf-8')

    height = input("Enter your height: ").encode('utf-8')
    weight = input("Enter your weight: ").encode('utf-8')
    bio = height + weight
    #Ei = H(PW⊕rb|Bio⊕rb|idi)
    sha256 = SHA256.new()
    ei = xor(pw, rb) + xor(bio, rb) + idi
    sha256.update(ei)
    Ei_check = sha256.digest()
    if Ei == Ei_check:
         print('login successfully')
         break
    print('wrong id/pw/bio, try again')

pw_new = input('Enter new password: ').encode('utf-8')
#Compute rbn = pw ⊕ pw_new ⊕ rb
rbn = xor(xor(pw, pw_new), rb)
#Update new Ein
#Ein =  H(PWn⊕rbn|Bio⊕rbn|idi)
sha256 = SHA256.new()
ein = xor(pw, rb) + xor(bio, rb) + idi
sha256.update(ein)
Ein = sha256.digest()
#Update Ein in the 'user.txt'?