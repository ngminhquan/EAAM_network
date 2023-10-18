from chebyshev import cbs
from Crypto.Hash import SHA256

#import parameters for chebyshev map
with open('cbs_para.txt') as para:
        x = int(para.readline())
        p = int(para.readline())
#server generate its own secret key s and public key ts
ids = input("enter server's id: ").encode('utf-8')
s = input("server enter its secret key: ")
ts = cbs(int(s), x, p)
#Generate server's cert
#Cert include server's id and public key
infor = ids + str(ts).encode('utf-8')
#print(infor)

sha = SHA256.new()
sha.update(infor)
hash_s = sha.digest()
print(hash_s)
cert_s = infor + hash_s
# publish cert, IDs, ts in a publicly available repository
with open('server_record.txt', 'ab') as record:
      record.write(b'\n')
      record.write(cert_s)
      
