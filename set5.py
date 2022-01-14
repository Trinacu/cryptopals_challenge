import os
import codecs

import util

import json
import numpy as np

import random

#from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import hashlib
import math

import requests

run = [False, False, False, False, False, False, True, True]

key = None

# there are some problems with c35 with fakeg=p , sometimes we get invalid padding?
print("SET 5")

def diffie_hellman_c33(p, g):
    a = np.random.randint(2**16) % p
    A = pow(g, a, p)
    b = np.random.randint(2**16) % p
    B = pow(g, b, p)

    return pow(B, a, p), pow(A, b, p)

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

    big_p = """ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff"""
    big_p = int(big_p, 16)
    s1, s2 = diffie_hellman_c33(big_p, g)
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


    os.system(os.path.join("auth_server","socket_server.py"))
    
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
    
    
if run[4]:
    print("\n-----------")
    print("Challenge 37 - Break SRP with a zero key")
    N = 123
    g = 2
    k = 3

    I = 'test@email.com'
    P = '1337password'
    # init N, g, k, mail, pwd - not the best way to send pwd in GET request :/
    ret = requests.get('http://localhost:5000',
                       params={'N':123, 'g':2, 'k':3,
                               'email':I,
                               'password':P})
    if ret.status_code == 200:
        d = json.loads(ret.content.decode())
        if (d['N']==N and d['g']==g and d['k']==k):
            # clientside processing?
            
            a = np.random.randint(2*16)
            A = pow(g, a, N)
            
            ret = requests.post('http://localhost:5000/login',
                                {'email':I, 'publ_key':A})
            d = json.loads(ret.content.decode())
            B = d['publ_key']
            salt = bytes(int(num) for num in d['salt'].split(','))

            uH = hashlib.sha256(str(A).encode() + str(B).encode()).hexdigest()
            u = int(uH, 16)

            #P = 'new stuff'
            xH = hashlib.sha256(salt + P.encode()).hexdigest()
            x = int(xH, 16)
            base = B - k * pow(g, x, N)
            S = pow(base, a + u * x, N)
            K = hashlib.sha256(str(S).encode()).hexdigest()
            
            ret = requests.post('http://localhost:5000/authenticate',
                                {'username':I, 'hmac':hashlib.sha256(K.encode()+salt).hexdigest()})
            
            #res = requests.post('http://localhost:5000/login',
            #                    {'username':'test@email.com', 'password':'1337password'})
        
    print('this is not solved ...')

    
if run[5]:
    print("\n-----------")
    print("Challenge 38 - ?")
    print('skipped ...')


primes = []
def gen_prime(start, num_primes):
    global primes
    if len(primes) < num_primes:
        num = start if len(primes) == 0 else primes[-1]+1
        while (len(primes) < num_primes):
            isPrime = True
            for x in range(2, int(np.sqrt(num))):
                if num % x == 0:
                    isPrime = False
                    break
            if isPrime:
                primes.append(num)
            num += 1
    print('choosing from list of {} primes [{}...{}]'.format(len(primes), primes[0], primes[-1]))
    return primes[np.random.randint(len(primes))]

def get_prime():
    with open('primes.txt', 'r') as f:
        data = f.read()
    if data == '':
        data = []
    else:
        data = [int(val) for val in data.split(',\n')]
    return data[np.random.randint(len(data))]

def modinv(a, m):
    for x in range(1, m):
        if ((a%m)*(x%m) % m == 1):
            return x
    raise Exception('modular inverse doesnt exist')

def rsa_encrypt(text, public_key):
    e, n = public_key
    #val = int(text.encode('utf-8').hex(), 16)
    val = int.from_bytes(text.encode('utf-8'), 'big')
    if val < 0 or val >= n:
        raise ValueError(str(val) + ' out of range!')
    return pow(val, e, n)

def rsa_decrypt(val, private_key):
    d, n = private_key
    if val < 0 or val >= n:
        raise ValueError(str(val) + ' out of range!')
    val = pow(val, d, n)
    #text = bytes.fromhex('{:x}'.format(val))
    text = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')#.decode()
    return text


def miller_rabin(n, k):
    if n == 2 or n == 3:
        return True
    # even numbers (less 2) are not prime
    if not n & 1:
        return False

    r, s = 0, n - 1
    while not s & 1:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

small_primes = [2,3,5,7,11,13,17,19]
def small_prime_factor(p):
    global small_primes
    for x in small_primes:
        if p % x == 0:
            return True
    return False

def get_probable_prime(bitcount):
    while True:
        p = random.randint(2**(bitcount - 1), 2**bitcount - 1)
        if not small_prime_factor(p) and miller_rabin(p, 16):
            return p

def get_rsa_keys(keysize):
    e = 3
    # seems like not doing the +1 gives correct keysize
    bitcount = (keysize + 1) // 2# + 1

    p = 7
    while (p - 1) % e == 0:
        p = get_probable_prime(bitcount)

    q = p
    while q == p or (q - 1) % e == 0:
        q = get_probable_prime(bitcount)

    n = p * q
    et = (p-1) * (q-1)
    d = pow(e, -1, et)
    #print('{:0256b}'.format(d))
    #print('key bit length: {} bits'.format(d.bit_length()))

    # return public key, private key
    return [e, n], [d, n]


if run[6]:
    print("\n-----------")
    print("Challenge 39 - Implement RSA")

    public_key, private_key = get_rsa_keys(256)

    text = 'encryption_test'
    print('plaintext length: {}'.format(len(text)))
    test = rsa_encrypt(text, public_key)
    test2 = rsa_decrypt(test, private_key)
    if text.encode() == test2:
        print('success')
    else:
        print('fail')


def floorRoot(n, s):
    b = n.bit_length()
    p = math.ceil(b/s)
    x = 2**p
    while x > 1:
        y = (((s - 1) * x) + (n // (x**(s-1)))) // s
        if y >= x:
            return x
        x = y
    return 1    

if run[7]:
    print("\n-----------")
    print("Challenge 40 - Implement E=3 RSA broadcast attack")
    
    text = 'encr. test'
    public_key0, private_key = get_rsa_keys(256)
    c0 = rsa_encrypt(text, public_key)
    n0 = public_key0[1]
    public_key1, private_key = get_rsa_keys(256)
    c1 = rsa_encrypt(text, public_key)
    n1 = public_key1[1]
    public_key2, private_key = get_rsa_keys(256)
    c2 = rsa_encrypt(text, public_key)
    n2 = public_key2[1]

    ms0 = n1 * n2
    ms1 = n0 * n2
    ms2 = n0 * n1

    N = n0 * n1 * n2

    r0 = c0 * ms0 * pow(ms0, -1, n0)
    r1 = c1 * ms1 * pow(ms1, -1, n1)
    r2 = c2 * ms2 * pow(ms2, -1, n2)

    
    res = (r0 + r1 + r2) % N

    r = floorRoot(res, 3)
    print(r)
    data = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    
    print(data)





