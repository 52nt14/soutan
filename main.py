import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
def rsa_enc(x,y):
    z = rsa.encrypt(x,y)
    return z
def aes_enc(x,y):
    x_byte = x.encode("utf-8")
    z = get_random_bytes(12)
    z = AES.new(y, AES.MODE_GCM, nonce=z)
    z, tag = z.encrypt_and_digest(x_byte)
    return z,tag
string = input("暗号化する文章を入力===>")
(pub_key, pri_key) = rsa.newkeys(4096)
p = pri_key.p
q = pri_key.q
d = pri_key.d
e = pub_key.e
n = pub_key.n
string_enc = rsa_enc(string,pub_key)
string_enc , tag = aes_enc(string_enc,n)
print("暗号化文" + string_enc)
print("TAG" + tag)