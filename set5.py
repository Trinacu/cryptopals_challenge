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



class DH_Comm():
    def __init__(self, p, g):
        self.A = self.Entity("Alice", p, g)
        self.B = self.Entity("Bob", p, g)
        self.M = self.Entity("attacker", p, g)

        self.p = p
        self.g = g

    def a2b(self, msg):
        # Alice sends her public key
        self.A.send(self.B, self.A.own_publ_key)
        self.B.other_publ_key = self.B._data

        # Bob sends his public key
        self.B.send(self.A, self.B.own_publ_key)
        self.A.other_publ_key = self.A._data

        # Alice sends message
        s = (self.A.other_publ_key ** self.A.priv_key) % self.p
        sha = SHA1Hash(s.to_bytes(256, 'little'))
        IV = get_random_bytes(16)
        key = bytes.fromhex(sha.digest())[:16]
        ciphertext = aes_cbc_encrypt(msg, key, IV)

        self.A.send(self.B, ciphertext + IV)
        

    def b2a(self, msg):
        # Bob sends her public key
        self.B.send(self.A, self.B.own_publ_key)
        self.A.other_publ_key = self.A._data

        # Alice sends his public key
        self.A.send(self.B, self.A.own_publ_key)
        self.B.other_publ_key = self.B._data

        # Alice sends message
        s = (self.B.other_publ_key ** self.B.priv_key) % self.p
        sha = SHA1Hash(s.to_bytes(256, 'little'))
        IV = get_random_bytes(16)
        key = bytes.fromhex(sha.digest())[:16]
        ciphertext = aes_cbc_encrypt(msg, key, IV)

        self.B.send(self.A, ciphertext + IV)

    class Entity():
        def __init__(self, name, p, g):
            self.name = name
            self.p = p
            self.priv_key = np.random.randint(2**8) % p
            self.own_publ_key = (g ** self.priv_key) % p
            self.other_publ_key = None
            
            self._data = None

        def send(self, other, data):
            other.receive(data)

        def receive(self, data):
            self._data = data

        def decrypt_msg(self):
            if not isinstance(self._data, bytes):
                print("{}'s _data is not bytes object!".format(self.name))
                return
            IV = self._data[-16:]
            self._data = self._data[:-16]
            s = (self.other_publ_key ** self.priv_key) % self.p
            sha = SHA1Hash(s.to_bytes(256, 'little'))
            key = bytes.fromhex(sha.digest())[:16]
            data = aes_cbc_decrypt(self._data, key, IV)
            return data
            
if run[1]:
    print("\n-----------")
    print("Challenge 34 - Implement MITM key-fixing attack on Diffie-Hellman")

    """
    s = diffie_hellman()
    data = s.to_bytes(256, 'little')
    tmp = SHA1Hash(data)
    print(tmp.digest())
    """
    
    #p = big_p
    #g = 2
    p = 37
    g = 5
    
    channel = DH_Comm(p, g)
    channel.a2b(b'test')
    print(channel.B.decrypt_msg())


    channel.b2a(b'asdasd')
    print(channel.A.decrypt_msg())


    
