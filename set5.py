import os
import codecs

import util

import numpy as np

#from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import hashlib

run = [False, False, False, True]

key = None

# there are some problems with c35 with fakeg=p , sometimes we get invalid padding?
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
        
    def decrypt_message(self):
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

if run[1]:
    print("\n-----------")
    print("Challenge 34 - Implement MITM key-fixing attack on Diffie-Hellman")
    
    p = util.big_p
    g = 2
    p = 23
    g = 5
    data = b'test'

    
    channel = DH_Comm("Alice", "Bob")
    A = channel.A
    B = channel.B
    
    A.p = p
    A.g = g


    A.send_data(A.p)
    channel.relay()
    B.p = B._data
    
    A.send_data(A.g)
    channel.relay()
    B.g = B._data
    
    A.init_keys()
    B.init_keys()
    
    A.send_data(A.own_public_key)
    channel._data = p
    channel.relay()
    B.other_public_key = B._data
    B.send_data(B.own_public_key)
    channel._data = p
    channel.relay()
    A.other_public_key = A._data

    A.send_message(data)
    channel.relay()

    B.send_message(B.decrypt_message())
    channel.relay()
    print(A.decrypt_message())
    # middleman attacker can decrypt knowing s=0!
    print(decrypt_msg(channel._data, 0))

def communicate_c35(p, g, fakeg):
    channel = DH_Comm("Alice", "Bob")
    A = channel.A
    B = channel.B

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

    if A.g == 0:
        s = 1
    elif A.g == A.p:
        s = 0
    else:
        if A.own_public_key == A.p-1 and B.own_public_key == A.p-1:
            s = p - 1
        else:
            s = 1
    print(s, channel._data)
    print(B.decrypt_message())
    print(decrypt_msg(channel._data, s))

if run[2]:
    print("\n-----------")
    print("Challenge 35 - Break DH with malicious 'g' parameters")
    
    # with g = 1, both public keys will be equal to 1: (1**a) % p = 1   -> s = 1
    # with g = p, both public keys will be equal to 0: (p**a) % p = 0   -> s = 0
    # with g = p - 1, both public keys will be:
    #   1) 1    if p is even                                            -> s = 1
    #   2) p-1  if p is odd                                             -> s = p-1
        
    p = 23
    g = 5

    communicate_c35(p, g, 1)
    communicate_c35(p, g, p)
    communicate_c35(p, g, p-1)
    

class Server():
    passwd = {'test@email.com': '1337password'}
    def __init__(self, N, g, k):
        self.N = N
        self.g = g
        # required?
        self.k = k
    
    def get_client_ids(self, I, A):
        self.salt = get_random_bytes(4)
        P = self.passwd[I]
        xH = hashlib.sha256(self.salt+P.encode('utf-8')).hexdigest()
        x = int(xH, 16)
        v = pow(self.g, x, self.N)
    
        b = np.random.randint(2**16)
        exp_term = pow(self.g, b, self.N)
    
        B = (self.k * v + exp_term) % self.N
    
        uH = hashlib.sha256(str(A).encode() + str(B).encode()).hexdigest()
        u = int(uH, 16)
    
        base = A * pow(v, u, self.N)
        S = pow(base, b, self.N)
        self.K = hashlib.sha256(str(S).encode()).hexdigest()
    
        return self.salt, B

    def check_hmac(self, hmac):
        if hmac == self.K:
            return True
        else:
            return False
        


if run[3]:
    print("\n-----------")
    print("Challenge 36 - Implement Secure Remote Password")

    N = util.big_p
    g = 2
    k = 3
    server = Server(N, g, k)

    # client
    I = 'test@email.com'
    P = server.passwd[I]
    
    a = np.random.randint(2*16)
    A = pow(g, a, N)
    
    salt, B = server.get_client_ids(I, A)
    
    uH = hashlib.sha256(str(A).encode() + str(B).encode()).hexdigest()
    u = int(uH, 16)
    
    xH = hashlib.sha256(salt + P.encode()).hexdigest()
    x = int(xH, 16)
    base = B - k * pow(g, x, N)
    S = pow(base, a + u * x, N)
    K = hashlib.sha256(str(S).encode()).hexdigest()
    
    if server.check_hmac(K):
        print('authentication success!')
    else:
        print('failed authentication')
    
    






    
