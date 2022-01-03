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
    def __init__(self, channel, name, p, g):
        self.name = name
        self.p = p
        self.g = g
        self.priv_key = np.random.randint(2**8) % self.p
        self.own_publ_key = (self.g ** self.priv_key) % self.p
        self.other_publ_key = None
        
        self._data = None
        self.message = ""

        self.channel = channel

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
            self.p = data[0]
            self.g = data[1]
            self.other_publ_key = data[2]
        # received key
        if isinstance(data, int):
            self.other_publ_key = data
        # received message
        if isinstance(data, bytes):
            self._data = data
            # separate data and IV and decrypt
            IV = self._data[-16:]
            data = self._data[:-16]
            s = (self.other_publ_key ** self.priv_key) % self.p
            sha = SHA1Hash(s.to_bytes(256, 'little'))
            key = bytes.fromhex(sha.digest())[:16]
            self.message = aes_cbc_decrypt(data, key, IV)

class DH_Comm():
    def __init__(self, p, g, nameA, nameB):
        self.A = Entity(self, nameA, p, g)
        self.B = Entity(self, nameB, p, g)
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

    """
    channelAB = DH_Comm(p, g, "Alice", "Bob")
    print("Message: {}".format(channelAB.A.message))
    channelAB.A.send_data([p, g, channelAB.A.own_publ_key])
    channelAB.B.send_data(channelAB.B.own_publ_key)
    channelAB.A.send_message(b'test')
    channelAB.B.send_message(channelAB.B.message)
    print("Message: {}".format(channelAB.A.message))
    """
    
    # M - middle man with 2 channels
    channelAM = DH_Comm(p, g, "Alice", "middle")
    channelMB = DH_Comm(p, g, "middle", "Bob")
    A = channelAM.A
    B = channelMB.B
    MA = channelAM.B
    MB = channelMB.A
    print("A Message: {}".format(A.message))
    
    A.send_data([p, g, channelAM.A.own_publ_key])
    MB.send_data([p, g, p])
    B.send_data(B.own_publ_key)
    MA.send_data(p)
    A.send_message(data)
    # relay data received on channelAM to B
    MB.send_data(MA._data)
    B.send_message(B.message)
    MA.send_data(MA._data)
    print("A Message: {}".format(A.message))

    

    print("M Message: {}".format(channelAM.B.message))



    
