#Using the information (IDi, ti, Ti, certi), the user is now able to
#register with the RC without the need of a secure channel 

from Crypto.Hash import SHA256
import random

#User import cert, ID, i, ti
with open('user_infor.txt', 'r', encode = 'utf-8') as user:
    pass

#Compute value Fi = H(i||IDi)

sha256 = SHA256.new()
#a = sha256.update(i + IDi)
#Fi = sha256.digest()

#select random value l ∈ R and compute tl
l = random.randint(10**2, 10**4) 