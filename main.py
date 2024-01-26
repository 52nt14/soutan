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
    return z,tag,cipher.nonce
def aes_dec(x,y,z,e):
    cipher = AES.new(y, AES.MODE_EAX, e)
    try:
        # 復号化
        dec_string = cipher.decrypt_and_verify(x,z)
    except (ValueError, KeyError) as ex:
        print(f"不正な復号 {ex}")
        dec_string = "Error"
    return dec_string
while(True):
    mode = input("暗号化: 0 復号化: 1 終了: 2\n実行するモードを選択===>")
    if mode == '0':
        string = input("暗号化する文章を入力===>").encode("utf8")
        if len(string) <= 0:
            print("文章を入力してください.")
        if len(string) > 5:
            print("文章は５文字以下にしてください.")
        else:
            (pub_key, pri_key) = rsa.newkeys(128)
            n = pub_key.n
            n_bytes = n.to_bytes(16, "big")
            string_enc = rsa_enc(string,pub_key)
            string_enc , tag, cih= aes_enc(string_enc,n_bytes)
            file_path = input("保存するファイル名を入力==>")
            with open(file_path+".pem", 'wb+') as f:
                private_str = pri_key.save_pkcs1('PEM')
                f.write(private_str)
            with open(file_path+".tag", "wb+") as f:
                print(tag)
                f.write(tag)
            with open(file_path+".cih", "wb+") as f:
                f.write(cih)
            with open(file_path+".enc", "wb+") as f:
                f.write(string_enc)
            print("保存が完了しました.")
    elif mode == '1':
        file_path = input("復号化するファイル名を入力==>")
        if file_path == "":
            print("ファイル名を入力してください.")
        else:
            with open(file_path+".tag", "rb+") as f:
                tag =f.read() 
            with open(file_path+".cih", "rb+") as f:
                cih = f.read()
            with open(file_path+".enc", "rb+") as f:
                string_enc = f.read()
            with open(file_path+".pem", mode='rb') as f:
                pri_str = f.read()
                pri_key = rsa.PrivateKey.load_pkcs1(pri_str)
            n = pri_key.n
            n_bytes = n.to_bytes(16, "big")
            string_dec = aes_dec(string_enc,n_bytes,tag,cih)
            string_dec = rsa_dec(string_dec,pri_key)
            print(string_dec)
    elif mode == '2':
        break
    else:
        print("正しいモードを選択してください.")