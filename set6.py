import random
import util

import re

import set5

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


print("SET 6")

run = [True, True, True]

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

def generate_signature(msg, private_key, blocksize):
    sha1 = util.SHA1Hash()
    msg = msg.encode('utf-8') if isinstance(msg, str) else msg
    sha1.update(msg)
    digest = sha1.digest()
    data = b'\x00\x01' + (b'\xff' * (blocksize - len(digest) - 3)) + b'\x00' + digest
    return rsa_decrypt(util.bytestonum(data), private_key)

def verify_signature(msg, sig, publ_key):
    block = b'\x00' + util.numtobytes(rsa_encrypt(sig, publ))
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
    signum = set5.floorRoot(util.bytestonum(block), 3) + 1
    return util.numtobytes(signum)
    
if run[1]:
    print("\n-----------")
    print("Challenge 42 - Bleichenbacher's e=3 RSA Attack")

    blocksize = 128

    publ, priv = get_rsa_keys(1024)
    e, n = publ

    data = 'hi mom'
    
    sig = generate_signature(data, priv, blocksize)
    fakesig = forge_signature(data, blocksize)

    print(verify_signature(data, sig, publ))
    print(verify_signature(data, fakesig, publ))


def generate_dsa_key():
    L, N = 1024, 160
    sha1 = util.SHA1Hash()
    sha1.update(random.randint(0, (2**16)-1).to_bytes(128, 'big'))
    digest = sha1.digest()
    
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

if run[2]:
    print("\n-----------")
    print("Challenge 43 - Implement Digital Signature Algorithm")

    generate_dsa_key()











    
