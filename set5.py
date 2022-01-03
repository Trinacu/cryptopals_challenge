import os
import codecs

from util import *

#from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


run = [True, True, True]

key = None

print("SET 5")

def diffie_hellman_c33(p, g):
    a = np.random.randint(2**16) % p
    A = (g**a) % p
    b = np.random.randint(2**16) % p
    B = (g**b) % p

    return (B**a) % p, (A**b) % p

if run[0]:
    print("\n-----------")
    print("Challenge 33 - Diffie-Hellman")

    p = 37
    g = 5
    s1, s2 = diffie_hellman_c33(p, g)
    if s1 == s2:
        print('correct')
    else:
        print('incorrect')

class Entity():
    def __init__(self, channel, name):
        self.name = name
        self.p = None
        self.g = None
        self.priv_key = None
        self.own_publ_key = None
        self.other_publ_key = None
        
        self._data = None
        self.message = ""

        self.channel = channel

    def init_keys(self, p, g):
        self.p = p
        self.g = g
        # don't create keys for middle to imitate as being in the middle
        if self.name != 'middle':
            self.priv_key = np.random.randint(2**8) % self.p
            self.own_publ_key = (self.g ** self.priv_key) % self.p

    def send_message(self, msg):
        other = self.channel.A if self == self.channel.B else self.channel.B
        s = (self.other_publ_key ** self.priv_key) % self.p
        sha = SHA1Hash(s.to_bytes(256, 'little'))
        key = bytes.fromhex(sha.digest())[:16]
        IV = get_random_bytes(16)
        ciphertext = aes_cbc_encrypt(msg, key, IV)

        self.send_data(ciphertext + IV)

    def send_data(self, data):
        other = self.channel.A if self == self.channel.B else self.channel.B
        other.receive(data)

    def receive(self, data):
        # received p, g, publ_key
        if isinstance(data, list):
            if len(data) != 3:
                print('invalid message list length!')
                return
            self.init_keys(data[0], data[1])
            self.other_publ_key = data[2]
        # received key
        if isinstance(data, int):
            self.other_publ_key = data
        # received message
        if isinstance(data, bytes):
            self._data = data
            if self.priv_key != None:
                self.decrypt_msg()

    def decrypt_msg(self):
        # separate data and IV and decrypt
        IV = self._data[-16:]
        data = self._data[:-16]
        s = (self.other_publ_key ** self.priv_key) % self.p
        sha = SHA1Hash(s.to_bytes(256, 'little'))
        key = bytes.fromhex(sha.digest())[:16]
        self.message = aes_cbc_decrypt(data, key, IV)

class DH_Comm():
    def __init__(self, p, g, nameA, nameB):
        self.A = Entity(self, nameA)
        self.B = Entity(self, nameB)
        self.p = p
        self.g = g

if run[1]:
    print("\n-----------")
    print("Challenge 34 - Implement MITM key-fixing attack on Diffie-Hellman")
    
    p = big_p
    g = 2
    #p = 37
    #g = 5
    data = b'test'
    
    # M - middle man with 2 channels
    channelAM = DH_Comm(p, g, "Alice", "middle")
    channelMB = DH_Comm(p, g, "middle", "Bob")
    A = channelAM.A
    B = channelMB.B
    MA = channelAM.B
    MB = channelMB.A

    A.init_keys(p, g)
    print("A Message: {}".format(A.message))
    
    A.send_data([p, g, channelAM.A.own_publ_key])
    # sending p instead A (publ_key) forces B to get s = 0 due to "s = (p**b) % p"
    # meaning input to SHA1 is all zeroes so we can recreate the cbc key
    MB.send_data([p, g, p])
    B.send_data(B.own_publ_key)
    MA.send_data(p)
    A.send_message(data)
    # relay data received on channelAM to B
    MB.send_data(MA._data)
    B.send_message(B.message)
    MA.send_data(MA._data)
    print("A Message: {}".format(A.message))

    
    IV = MB._data[-16:]
    data = MB._data[:-16]
    sha = SHA1Hash((0).to_bytes(256, 'little'))
    key = bytes.fromhex(sha.digest())[:16]
    print("M Message: {}".format(aes_cbc_decrypt(data, key, IV)))


    







    
