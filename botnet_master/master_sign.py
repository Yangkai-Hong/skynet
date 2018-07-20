import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_PSS

def sign_file(f):
    # Read private key
    key = RSA.importKey(open("botnet_master/master_rsa_private").read())
    # use SHA512 to hash the file
    h = SHA512.new()
    h.update(f)
    # sign using the RSASSA-PSS scheme
    signer = PKCS1_PSS.new(key)
    # create the signature and prepend it to the message
    signature = signer.sign(h)
    return signature + f


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
