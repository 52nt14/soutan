import rsa
from Crypto.Cipher import AES
def rsa_enc(x,y):
    z = rsa.encrypt(x,y)
    return z
def rsa_dec(x,y):
    z = rsa.decrypt(x,y)
    return z
def aes_enc(x,y):
    cipher = AES.new(y, AES.MODE_EAX)
    z, tag = cipher.encrypt_and_digest(x)
    return z,tag,cipher
def aes_dec(x,y,z,e):
    cipher_enc = AES.new(y, AES.MODE_EAX,e.nonce)
    try:
        # 復号化
        dec_string = cipher_enc.decrypt_and_verify(x,z)
    except (ValueError, KeyError) as ex:
        print(f"不正な復号 {ex}")
        dec_string = "Error"
    return dec_string
while(True):
    mode = input("暗号化: 0 復号化: 1 終了: 2\n実行するモードを選択===>")
    if mode == '0':
        string = input("暗号化する文章を入力===>").encode("utf8")
        (pub_key, pri_key) = rsa.newkeys(128)
        p = pri_key.p
        q = pri_key.q
        d = pri_key.d
        e = pub_key.e
        n = pub_key.n
        n_bytes = n.to_bytes(16, "big")
        string_enc = rsa_enc(string,pub_key)
        string_enc , tag, cih = aes_enc(string_enc,n_bytes)
        print(string_enc)
        print(pri_key)
        print(tag)
        string_dec = aes_dec(string_enc,n_bytes,tag,cih)
        print(string_dec)
        string_dec = rsa_dec(string_dec,pri_key)
        print(string_dec)
    elif mode == '1':
        aes_dec(string,n_bytes,tag)
    elif mode == '2':
        break
    else:
        print("正しいモードを選択してください.")