import rsa
(pub_key, pri_key) = rsa.newkeys(4096)
text = "Distroted_Fate".encode("utf8")
crypto = rsa.encrypt(text,pub_key)
decode = rsa.decrypt(crypto, pri_key)
print(pub_key.n)
print("\n")
print(pub_key.e)
print("\n")
print("\n")
print("\n")
print(pri_key.d)
print("\n")
print(pri_key.e)
print("\n")
print(pri_key.n)
print("\n")
print(pri_key.p)
print("\n")
print(pri_key.q)
print("\n")
print("\n")
print("\n")
print(crypto.hex())
print("\n")
print(decode.decode("utf8"))