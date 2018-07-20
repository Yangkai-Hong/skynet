import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def decrypt_valuables(f):
    # The file is encrypted using PKCS1_OAEP module
    # Decrypt the file using the private key
    key = RSA.importKey(open('botnet_master/master_rsa_private').read())
    cipher = PKCS1_OAEP.new(key)
    decrypted_master = cipher.decrypt(f)
    print(decrypted_master)

if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
