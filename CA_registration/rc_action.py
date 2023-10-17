import time
import random
import math
from chebyshev import cbs
from Crypto.Hash import SHA256

#action to be performed by RC

'''
- x as the seed for generating the Chebyshev chaotic map
- p as a large prime number, defining the modulo operation on 
the output of the Chebyshev chaotic map
- tr = Tr(x), the public key of the RC, together with a certificate 
 on (I Dr, tr)
- ε is the predefined delay between submission and reception
 '''

#generate random large prime number with order length
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    for i in range(5, int(math.sqrt(n)) + 1, 6):
        if n % i == 0 or n % (i + 2) == 0:
            return False
    return True

def generate_random_prime(length):
    while True:
        num = random.getrandbits(length)
        if is_prime(num):
            return num
        

#generate x & p for chebyshev
#ε is delay between submission and reception
x = random.randint(10**3, 10**4)
p = generate_random_prime(32)
ε = 300


#Enter secret key r and public key tr of RC
r = input("Enter secret key of RC:")

tr = cbs(int(r), x, p)

#Create hash on RC and tr => cert
sha = SHA256.new()
sha.update(b'RC' + bytes(tr))
cert_r = sha.digest()
#print(cert_r)

#Save parameters for chebyshev and public key, cert of RC
with open('cbs_para.txt','w',encoding='utf-8') as para:
    para.write(str(x))
    para.write('\n' + str(p))
    para.write('\n' + str(ε))
    para.write('\n' + str(tr))


#RC share all validate server group key GK
gk ='group key'
with open('server_record.txt', 'w', encoding='utf-8') as record:
      record.write(gk)
#Save secret key of RC and group key GK (secure)
with open('rc_key.txt') as rc:
    rc.writelines(r, gk)

