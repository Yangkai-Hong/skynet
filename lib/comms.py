import struct
import time

from Crypto.Cipher import AES
from Crypto.Hash import HMAC

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.hmac = None
        self.timestamp = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Default XOR algorithm can only take a key of length 32
        #self.cipher = XOR.new(shared_hash[:4])
        self.cipher = AES.new(shared_hash[:32],AES.MODE_CBC, shared_hash[-16:])
        self.hmac = HMAC.new(bytes(shared_hash.encode()))
        self.timestamp = AES.new(shared_hash[:32],AES.MODE_CBC, shared_hash[-16:])

    def pad(self, data):
        length = 16
        count = len(data)
        add = length - (count % length)
        text = data + (b'\0' * add)
        return text

    def depad(self,data):
        return data.rstrip(b'\0')

    def send(self, data):
        if self.cipher:
            data = self.pad(data)
            encrypted_data = self.cipher.encrypt(data)

            timestamp = bytes(str(int(time.time())), "ascii")
            timestamp = self.pad(timestamp)
            encrypted_time = self.timestamp.encrypt(timestamp)

            encrypted_data = encrypted_time + encrypted_data
            self.hmac.update(encrypted_data)
            my_hmac = self.hmac.hexdigest().encode()

            # Append the HMAC to the encrypted data
            encrypted_data = encrypted_data + my_hmac

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
                #print("Length of HMAC: {}".format(len(my_hmac)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data[16:-32])
            data = self.depad(data)

            received_timestamp = self.timestamp.decrypt(encrypted_data[:16])
            received_timestamp = self.depad(received_timestamp)
            received_timestamp = int(received_timestamp.decode("ascii"))
            timestamp = int(time.time())
            time_difference = timestamp - received_timestamp
            if time_difference > 60:
                print("Replay attack detected!")
                self.conn.close()

            received_hmac = encrypted_data[-32:]
            # Calculate the HMAC of the encrypted data
            self.hmac.update(encrypted_data[:-32])
            my_hmac = self.hmac.hexdigest().encode()
            # Verify that the given and calculated HMACs actually agree
            if my_hmac != received_hmac:
                print("Attackers are tampering this message!")
                self.conn.close()

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
