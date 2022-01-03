import util

import numpy as np

#from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# how to make the middleman have a choice what to do with the data?

class Entity():
    def __init__(self, channel, name):
        self.channel = channel
        self.name = name

        self.p = None
        self.g = None

        self.private_key = None
        self.own_public_key = None
        self.other_public_key = None

        self._data = None

    def init_keys(self):
        self.private_key = np.random.randint(2**8) % self.p
        self.own_public_key = (self.g ** self.private_key) % self.p

    def receive(self, data):
        #print('{} received {}'.format(self.name, data))
        self._data = data

    def send_data(self, data):
        #print('{} sent {}'.format(self.name, data))
        self.channel.receiver = self.channel.B if self == self.channel.A else self.channel.A
        self.channel._data = data

    def send_message(self, msg):
        s = (self.other_public_key ** self.private_key) % self.p
        sha = util.SHA1Hash().update(s.to_bytes(128, 'little'))
        key = bytes.fromhex(sha.hexdigest())[:16]
        IV = get_random_bytes(16)
        ciphertext = util.aes_cbc_encrypt(msg, key, IV)
        self.send_data(ciphertext + IV)
        
    def decrypt_msg(self):
        # separate data and IV and decrypt
        IV = self._data[-16:]
        data = self._data[:-16]
        s = (self.other_public_key ** self.private_key) % self.p
        sha = util.SHA1Hash().update(s.to_bytes(128, 'little'))
        key = bytes.fromhex(sha.hexdigest())[:16]
        return util.aes_cbc_decrypt(data, key, IV)

class DH_Comm():
    def __init__(self, nameA, nameB):
        self.A = Entity(self, nameA)
        self.B = Entity(self, nameB)

        self._data = None
        self.receiver = None

    def relay(self):
        self.receiver.receive(self._data)



def decrypt_msg(data, s):
    IV = data[-16:]
    data = data[:-16]
    sha = util.SHA1Hash().update(s.to_bytes(128, 'little'))
    key = sha.digest()[:16]
    return util.aes_cbc_decrypt(data, key, IV)

def communicate(p, g, fakeg):
    channel = DH_Comm("Alice", "Bob")
    A = channel.A
    B = channel.B

    #A.p = util.big_p
    #A.g = 2
    A.p = p
    A.g = g

    # negotiate p
    ret = None
    while (ret != A.p or ret != B.p):
        A.send_data(A.p)
        channel.relay()
        B.p = B._data
        B.send_data(B.p)
        channel.relay()
        ret = A._data
        A.p = ret
    print("A.p:{}  B.p:{}".format(A.p, B.p))

    # negotiate g
    ret = None
    while (ret != A.g or ret != B.g):
        A.send_data(A.g)
        channel.relay()
        B.g = B._data
        B.send_data(B.g)
        # edit value before relaying
        channel._data = fakeg
        channel.relay()
        ret = A._data
        A.g = ret
    print("A.g:{}  B.g:{}".format(A.g, B.g))

    A.init_keys()
    B.init_keys()
    
    A.send_data(A.own_public_key)
    channel.relay()
    B.other_public_key = B._data
    B.send_data(B.own_public_key)
    channel.relay()
    A.other_public_key = A._data

    A.send_message(b'test')
    channel.relay()
    print(B.decrypt_msg())

    if A.g == 0:
        s = 1
    elif A.g == A.p:
        s = 0
    else:
        if A.own_public_key == A.p-1 and B.own_public_key == A.p-1:
            s = p - 1
        else:
            s = 1
    print(decrypt_msg(channel._data, s))
# with g = 1, both public keys will be equal to 1: (1**a) % p = 1   -> s = 1
# with g = p, both public keys will be equal to 0: (p**a) % p = 0   -> s = 0
# with g = p - 1, both public keys will be:
#   1) 1    if p is even                                            -> s = 1
#   2) p-1  if p is odd                                             -> s = p-1
    
p = 23
g = 5

communicate(p, g, 1)
communicate(p, g, p)
communicate(p, g, p-1)





