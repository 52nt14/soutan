import rsa
from Crypto.Cipher import AES
string = input("暗号化する文章を入力===>").encode("utf8")
(pub_key, pri_key) = rsa.newkeys(128)
n = pub_key.n
n_bytes = n.to_bytes(16, "big")
cipher = AES.new(n_bytes, AES.MODE_EAX)
str_enc, tag = cipher.encrypt_and_digest(string)
print(str_enc)
print(tag)
cipher_dec = AES.new(n_bytes, AES.MODE_EAX,cipher.nonce)
try:
    # 復号化
    string_enc = cipher_dec.decrypt_and_verify(str_enc,tag)
except (ValueError, KeyError) as ex:
    print(f"不正な復号 {ex}")
    string_enc = "Error"
print(string_enc)