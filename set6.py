import random
import util

import re
import hashlib
import math
import itertools
import codecs

import os

import numpy as np

from tqdm import tqdm


def rsa_encrypt(data, public_key):
    e, n = public_key
    data = data.encode('utf-8') if isinstance(data, str) else data
    val = util.bytestonum(data)
    if val < 0 or val >= n:
        raise ValueError(str(val) + ' out of range!')
    return pow(val, e, n)

def rsa_decrypt(val, private_key):
    d, n = private_key
    if val < 0 or val >= n:
        raise ValueError(str(val) + ' out of range!')
    val = pow(val, d, n)
    text = util.numtobytes(val)
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


print("SET 6")

run = [False, False, False, False, False, False, False, True]

class DecryptServer():
    def __init__(self):
        self.msg_hist = []

    def decrypt(self, msg, key):
        sha1 = util.SHA1Hash()
        sha1.update(hex(msg).encode())
        digest = sha1.digest()
        if digest in self.msg_hist:
            print('duplicate message! refusing to decrypt')
            return None
        self.msg_hist.append(digest)
        return rsa_decrypt(msg, key)
        
        

if run[0]:
    print("\n-----------")
    print("Challenge 41 - unpadded message recovery")

    publ, priv = get_rsa_keys(256)


    text = 'asd asd'
    cipher = rsa_encrypt(text, publ)

    srv = DecryptServer()
    print(srv.decrypt(cipher, priv))
    print(srv.decrypt(cipher, priv))

    e, n = publ
    s = random.randint(1, n-1)
    # C' = ((S**E mod N) C) mod N
    cipher2 = (pow(s, e, n) * cipher) % n
    plain2 = srv.decrypt(cipher2, priv)
    # P = (P'/S) % N
    # Remember: you don't simply divide mod N; you multiply by
    # the multiplicative inverse mod N. So you'll need a modinv() function. 
    plain = (util.bytestonum(plain2) * pow(s, -1, n)) % n
    recovered = util.numtobytes(plain)
    print('orig:"{}"; recovered:"{}"'.format(text, recovered.decode()))
    if recovered.decode() == text:
        print('success')
    else:
        print('fail')

def generate_rsa_signature(msg, private_key, blocksize):
    sha1 = util.SHA1Hash()
    msg = msg.encode('utf-8') if isinstance(msg, str) else msg
    sha1.update(msg)
    digest = sha1.digest()
    data = b'\x00\x02' + (b'\xff' * (blocksize - len(digest) - 3)) + b'\x00' + digest
    return rsa_decrypt(util.bytestonum(data), private_key)

def verify_rsa_signature(msg, sig, publ_key):
    block = b'\x00' + util.numtobytes(rsa_encrypt(sig, publ_key))
    # digest is 20 bytes long
    r = re.compile(b'\x00\x01\xff+?\x00(.{20})', re.DOTALL)
    m = r.match(block)
    if not m:
        return False
    digest = m.group(1)
    sha1 = util.SHA1Hash()
    msg = msg.encode('utf-8') if isinstance(msg, str) else msg
    sha1.update(msg)
    return digest == sha1.digest()

def forge_signature(msg, blocksize):
    sha1 = util.SHA1Hash()
    msg = msg.encode('utf-8') if isinstance(msg, str) else msg
    sha1.update(msg)
    digest = sha1.digest()
    block = b'\x00\x01\xff\x00' + digest + (b'\x00' * (blocksize - len(digest) - 4))
    signum = floorRoot(util.bytestonum(block), 3) + 1
    return util.numtobytes(signum)
    
if run[1]:
    print("\n-----------")
    print("Challenge 42 - Bleichenbacher's e=3 RSA Attack")

    blocksize = 128

    publ, priv = get_rsa_keys(1024)
    e, n = publ

    data = 'hi mom'
    
    sig = generate_rsa_signature(data, priv, blocksize)
    fakesig = forge_signature(data, blocksize)

    print(verify_rsa_signature(data, sig, publ))
    print(verify_rsa_signature(data, fakesig, publ))


def get_dsa_param(L, N):
    q = util.get_probable_prime(N)
    minK = (2**(L-1)) // q
    maxK = (2**L - 1) // q
    while True:
        k = random.randint(minK, maxK)
        p = k*q + 1
        if util.miller_rabin(p, 8):
            break
    h = random.randint(2, p-2)
    g = pow(h, (p-1)//q, p)
    return p, q, g

def get_dsa_key(p, q, g):
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    # private, public key
    return x, y

def hash(msg):
    msg = msg.encode('utf-8') if isinstance(msg, str) else msg
    sha1 = util.SHA1Hash()
    sha1.update(msg)
    return int.from_bytes(sha1.digest(), 'big')

def sign_hash_with_k(H, pub, priv, k):
    (p, q, g, y) = pub
    x = priv
    r = pow(g, k, p) % q
    if r == 0:
        return None
    kInv = pow(k, -1, q)
    s = (kInv * (H + x * r)) % q
    if s == 0:
        return None
    return (r, s)

def sign_hash(H, pub, priv):
    (_, q, _, _) = pub
    while True:
        k = random.randint(1, q - 1)
        signature = sign_hash_with_k(H, pub, priv, k)
        if not signature:
            continue
        return signature

def dsa_sign(msg, pub, priv):
    return sign_hash(hash(msg), pub, priv)



def sign_hash_alt(H, pub, priv):
    (_, q, _, _) = pub
    while True:
        k = random.randint(1, q - 1)
        signature = sign_hash_with_k(H, pub, priv, k)
        if not signature:
            continue
        return H, *signature, k

def recover_private_key(H, r, s, k, pub):
    (p, q, g, y) = pub
    rInv = pow(r, -1, q)
    return (rInv * (s * k - H)) % q

def keys_valid(pub, priv):
    (p, _, g, y) = pub
    x = priv
    return y == pow(g, x, p)
    

def brute_force_private_key(H, r, s, pub, kMin, kMax):
    for k in range(kMin, kMax):
        priv = recover_private_key(H, r, s, k, pub)
        if keys_valid(pub, priv):
            return (k, priv)
    return None

if run[2]:
    print("\n-----------")
    print("Challenge 43 - DSA key recovery from nonce")

    tmp = 'test'
    p, q, g = get_dsa_param(1024, 160)
    x, y = get_dsa_key(p, q, g)
    pub = (p, q, g, y)
    
    H, r, s, k = sign_hash_alt(hash(tmp), pub, x)
    if (not (x == recover_private_key(H, r, s, k, pub))):
        print('private key recovery not working')

    text = """For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
"""
    # this last newline IS THERE in the original text of the challenge (check hash!)
    
    H_expected = int("d2d0714f014a9784047eaeccf956520045c45265", 16)
    if hash(text) != H_expected:
        raise Exception('plaintext hashes do not match!')


    # solve this
    y = "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17"
    y = int(y, 16)
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    
    pub = (p, q, g, y)
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    private_H_expected = 0x0954edd5e0afe5542a4adf012611a91912a3ec16

    k, priv = brute_force_private_key(hash(text), r, s, pub, 0, 2**16)
    priv_H = hash(hex(priv)[2:].encode('ascii'))
    if private_H_expected != priv_H:
        print('private key hashes do not match!')
        print(str(private_H_expected) + ' != ' + str(priv_H))
        #raise Exception('private key hashes do not match!')
        
    r2, s2 = sign_hash_with_k(hash(text), pub, priv, k)
    if r2 != r:
        print('r: ' + str(r2) + ' != ' + str(r))
        #raise Exception('r: ' + str(r2) + ' != ' + str(r))
    if s2 != s:
        print('s: ' + str(s2) + ' != ' + str(s))
        #raise Exception('s: ' + str(s2) + ' != ' + str(s))

    print('k, private_key:')
    print(k, priv)

class Msg():
    def __init__(self, msg, s, r, m):
        self.msg = msg[5:]
        self.r = int(r[3:])
        self.s = int(s[3:])
        # hash(msg)
        self.m = int(m[3:], 16)

def check_common_k(msg1, msg2, pub):
    (p, q, g, y) = pub
    s1, r1, m1 = msg1.s, msg1.r, msg1.m
    s2, r2, m2 = msg2.s, msg2.r, msg2.m
    ds = (s1 - s2) % q
    dsInv = pow(ds, -1, q)
    dm = (m1 - m2) % q
    k = (dm * dsInv) % q
    priv1 = recover_private_key(m1, r1, s1, k, pub)
    priv2 = recover_private_key(m2, r2, s2, k, pub)
    if priv1 == priv2 and keys_valid(pub, priv1) and keys_valid(pub, priv2):
        return (k, priv1)
    return (None, None)

def break_repeated_k(messages, pub):
    for comb in itertools.combinations(messages, 2):
        (k, priv) = check_common_k(comb[0], comb[1], pub)
        if k:
            return (k, priv)
    return (None, None)

def verify_dsa_signature(H, sig, pub):
    (r, s) = sig
    (p, q, g, y) = pub
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    w = pow(s, -1, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

if run[3]:
    print("\n-----------")
    print("Challenge 44 - DSA nonce recovery from repeated nonce")

    with open(os.path.join('txt', 'challenge44.txt'), 'r') as f:
        data = f.readlines()
    data = [line.strip('\n') for line in data]
    
    messages = []
    for i in range(0, len(data), 4):
        messages.append(Msg(data[i], data[i+1], data[i+2], data[i+3]))
        
    y = "2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821"
    y = int(y, 16)
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    pub = (p, q, g, y)


    k, priv = break_repeated_k(messages, pub)
    private_H_expected = 0xca8f6f7c66fa362d40760d135b763eb8527d3d52
    priv_H = hash(hex(priv)[2:].encode('ascii'))
    
    if priv_H != private_H_expected:
        print('private key hash does not match expected?')
    else:
        print('found private key hash: {}'.format(hex(priv_H)))

    for msg in messages:
        if not verify_dsa_signature(hash(msg.msg), (msg.r, msg.s), pub):
            print('msg {} failed signature check!'.format(msg.msg))

# doesn't check for r != 0 and s != 0
def dsa_sign_bad(msg, pub, priv):
    H = hash(msg)
    (p, q, g, y) = pub
    k = random.randint(1, q - 1)
    x = priv
    r = pow(g, k, p) % q
    kInv = pow(k, -1, q)
    s = (kInv * (H + x * r)) % q
    return (r, s)
# doesn't check for r != 0 and s != 0
def verify_dsa_signature_bad(H, sig, pub):
    (r, s) = sig
    (p, q, g, y) = pub
    if r < 0 or r >= q or s < 0 or s >= q:
        return False
    w = pow(s, -1, q)
    u1 = (H * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

if run[4]:
    print("\n-----------")
    print("Challenge 45 - DSA parameter tampering")

    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    # !!! TAMPER !!!
    g = 0
    x, y = get_dsa_key(p, q, g)
    pub = (p, q, g, y)

    text = 'test string'
    sig = dsa_sign_bad(text, pub, x)
    if verify_dsa_signature_bad(hash(text), sig, pub):
        print('g=0: success')
    else:
        print('g=0: fail')

    g = p + 1
    x, y = get_dsa_key(p, q, g)
    pub = (p, q, g, y)

    text1 = "Hello, world"
    text2 = "Goodbye, world"

    # generate 'magic signature' with arbitrary 'z'
    z = random.randint(2,12312412)
    invZ = pow(z, -1, q)
    r = pow(y, z, p) % q
    s = (invZ * r) % q
    fakesig = (r, s)

    if verify_dsa_signature_bad(hash(text1), fakesig, pub):
        print('g=p+1: magic signature success')
    else:
        print('g=p+1: magic signature fail')
    if verify_dsa_signature_bad(hash(text2), fakesig, pub):
        print('g=p+1: magic signature success')
    else:
        print('g=p+1: magic signature fail')

priv = None
def rsa_plaintext_odd(cipher):
    global priv
    text = rsa_decrypt(cipher, priv)
    # true for odd
    return util.bytestonum(text) & 1

def decode_valid(data):
    return ''.join([chr(byte) for byte in data if (byte > 31 and byte < 127)])

def break_rsa_with_parity(cipher, publ, hollywood_style=True):
    e, n = publ
    plain = util.numtobytes(0)
    low = 0
    high = 1
    denom = 1
    
    k = pow(2, e, n)
    txt = ""
    for _ in range(n.bit_length()):
    # double the ciphertext (or plain, actually?)
        cipher = (k * cipher) % n
        d = high - low
        low *= 2
        high *= 2
        denom *= 2
        # if plain is odd, we wrapped the modulus (large prime is odd!)
        if not rsa_plaintext_odd(cipher):
            high -= d
        else:
            low += d
        hightext = util.numtobytes(n * high // denom)
        if hollywood_style:
            decoded = decode_valid(hightext)
            if decoded != txt and decoded != None:
                txt = decoded
                print(txt)
    return hightext

if run[5]:
    print("\n-----------")
    print("Challenge 46 - RSA parity oracle")

    publ, priv = get_rsa_keys(1024)
    # [e, n], [d, n]
    
    text = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    text = codecs.decode(text.encode(), 'base64')
    cipher = rsa_encrypt(text, publ)
    odd = rsa_plaintext_odd(cipher)

    plaintext = break_rsa_with_parity(cipher, publ, False).decode()
    print(plaintext)

def pkcs1_conforming(cipher):
    global priv
    d, n = priv
    k = (n.bit_length() + 7) // 8
    data = rsa_decrypt(cipher, priv)
    # fill 'lost' zeroes? MSB zeros are dropped when we have a number
    data = (b'\x00' * (k - len(data))) + data
    if data[0] == 0 and data[1] == 2:
        return True
    return False

def pkcs1_pad(data, n):
    return b'\x00\x02' + ((n.bit_length()+7)//8 - 3 - len(data)) * b'\xff' + b'\x00' + data


def find_first_s(publ, B, c0):
    e, n = publ
    s1 = n // (3 * B)
    while True:
        if pkcs1_conforming((c0 * pow(s1, e, n)) % n):
            break
        s1 += 1
    return s1

def find_r_s(M, s_prev, B, publ, c0):
    e, n = publ
    a, b = M[0]
    r = (2 * (b*s_prev - 2*B) + n - 1) // n
    while True:
        sMin = (2*B + r*n + b - 1) // b
        sMax = (3*B + r*n + a - 1) // a
        #sMin = (2*B + r*n) // b
        #sMax = (3*B + r*n) // a
        for s in range(sMin, sMax):
            if pkcs1_conforming((c0 * pow(s, e, n)) % n):
                return r, s
        r += 1
        if r % 100000 == 0:
            print(r, s)
        

def get_new_interval(M, s, B, publ):
    e, n = publ
    a, b = M[0]
    # where does the "+ n - 1" come from? it guarantees 1 wide interval but is it right?
    minR = (a*s - 3*B + 1 + n - 1) // n
    maxR = (b*s - 2*B) //n
    intervals = []
    for r in range(minR, maxR+1):
        ai = max(a, (2*B + r*n + s - 1) // s)
        bi = min(b, (3*B - 1 + r*n) // s)
        intervals.append((ai, bi))
    return intervals

def break_PKCS1(c, publ):
    e, n = publ
    # Step 1
    while True:
        #s0 = random.randint(2, 2**(keysize-2))
        # if c is already pkcs conforming (which in this case shoul be) just set s0=1
        s0 = 1
        c0 = (c * pow(s0, e, n)) % n
        if pkcs1_conforming(c0):
            break
    # byte size
    k = (n.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 2))
    M0 = [(2*B, 3*B - 1)]
    i = 1

    while True:
        if i == 1:
            # Step 2.a
            s = find_first_s(publ, B, c0)
            M = M0
        else:
            if len(M) > 1:
                # Step 2.b (multiple intervals)
                print("Multiple intervals - shouldn't encounter this ...")
                i = 1
                M = M0
                continue
            else:
                # Step 2.c
                r, s = find_r_s(M, s, B, publ, c0)

        print('{}) interval size {}'.format(i, M[0][1]-M[0][0] + 1))
        # Step 3
        M = get_new_intervals(M, s, B, publ)

        # Step 4
        a, b = M[0]
        if a == b:
            return b'\x00' + util.numtobytes((a * pow(s0, e, n)) % n)
        else:
            i += 1

        
if run[6]:
    print("\n-----------")
    print("Challenge 47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)")
    #"Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
    # [e, n], [d, n]
    keysize = 256
    publ, priv = get_rsa_keys(keysize)

    e, n = publ

    m = pkcs1_pad(b'kick it, CC', n)
    c = rsa_encrypt(m, publ)
    

    m2 = break_PKCS1(c, publ)

    print(m, m2)

def find_next_s(publ, B, c0, s):
    e, n = publ
    while True:
        s += 1
        if pkcs1_conforming((c0 * pow(s, e, n)) % n):
            break
    return s

def get_new_intervals(M, s, B, publ):
    e, n = publ
    a, b = M[0]
    # where does the "+ n - 1" come from? it guarantees 1 wide interval but is it right?
    intervals = []
    for a,b in M:
        minR = (a*s - 3*B + 1 + n - 1) // n
        maxR = (b*s - 2*B) //n
        for r in range(minR, maxR+1):
            ai = max(a, (2*B + r*n + s - 1) // s)
            bi = min(b, (3*B - 1 + r*n) // s)
            if ai > bi:
                continue
            intervals.append((ai, bi))
    return intervals

def break_PKCS1_full(c, publ):
    e, n = publ
    # Skip Step 1 if c is already pkcs conforming (which in this case shoul be) just set s0=1 -> c0=c
    s0 = 1
    c0 = (c * pow(s0, e, n)) % n
    k = (n.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 2))
    M0 = [(2*B, 3*B - 1)]
    i = 1

    while True:
        if i == 1:
            # Step 2.a
            s = find_first_s(publ, B, c0)
            M = M0
        else:
            if len(M) > 1:
                # Step 2.b (multiple intervals)
                s = find_next_s(publ, B, c0, s)
                print('multiple intervals? calculated next s: {}'.format(s))
            else:
                # Step 2.c
                r, s = find_r_s(M, s, B, publ, c0)

        #print('{}) interval size {}'.format(i, M[0][1]-M[0][0] + 1))
        # Step 3
        M = get_new_intervals(M, s, B, publ)

        # Step 4
        a, b = M[0]
        if (len(M) == 1 and a == b):
            return b'\x00' + util.numtobytes((a * pow(s0, e, n)) % n)
        else:
            i += 1
    

if run[7]:
    print("\n-----------")
    print("Challenge 48 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)")
    #"Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"

    keysize = 256
    publ, priv = get_rsa_keys(keysize)

    e, n = publ

    m = pkcs1_pad(b'kick it, CC', n)
    c = rsa_encrypt(m, publ)
    

    m2 = break_PKCS1_full(c, publ)

    print(m, m2)






    
