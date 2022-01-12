import os
import io
import json
import numpy as np
from collections import Counter

import random
from itertools import zip_longest
from itertools import cycle
from Crypto.PublicKey.DSA import generate

from Crypto.Cipher import AES

import struct

ENG_CHAR_FREQ_TABLE = {
        b'a':    0.08167, b'b':    0.01492, b'c':    0.02782,
        b'd':    0.04253, b'e':    0.12700, b'f':    0.02228,
        b'g':    0.02015, b'h':    0.06094, b'i':    0.06966,
        b'j':    0.00153, b'k':    0.00772, b'l':    0.04025,
        b'm':    0.02406, b'n':    0.06749, b'o':    0.07507,
        b'p':    0.01929, b'q':    0.00095, b'r':    0.05987,
        b's':    0.06327, b't':    0.09056, b'u':    0.02758,
        b'v':    0.00978, b'w':    0.02360, b'x':    0.00150,
        b'y':    0.01974, b'z':    0.00074, b' ':    0.28
}

def dict_to_json(dictionary, filename):
    if filename[-5:] != '.json':
        filename = filename+'.json'
    with open(os.path.join('json', filename), 'w+') as json_file:
        json.dump(dictionary, json_file, indent=4)

def json_to_dict(filename):
    if filename[-5:] != '.json':
        filename = filename+'.json'
    with open(filename) as json_file:
        return json.load(json_file)

def transpose_bytearrays(data, fillvalue='%'):
    arr = [[chr(char) for char in line] for line in data]
    transposed = zip_longest(*arr, fillvalue=fillvalue)
    #transposed = zip(*arr)
    return [bytes([ord(char) for char in line]) for line in transposed]

def englishness(data):
    if isinstance(data, str):
        data = data.encode()
    json_file = os.path.join('json', 'eng_char_freq.json')
    if not os.path.exists(json_file):
        generate_char_freq_json()
    char_frequency = json_to_dict(json_file)
    
    #print(char_frequency)
    try:
        string_to_score = data.decode()
    except Exception:
        return 0
    
    c = Counter(string_to_score.lower())
    
    coefficient = sum(
        np.sqrt(char_frequency.get(char, 0) * y/len(string_to_score))
        for char, y in c.items()
        )
    return coefficient

def generate_char_freq_json():
    with open(os.path.join('txt', 'char_freq.txt'), 'r') as f:
        text = f.read()
    
    tmp = ''.join(list([val for val in text if \
                        (ord(val) == 32 or (ord(val) > 64 and ord(val) < 91)\
                         or (ord(val) > 96 and ord(val) < 123))]))
    
    c = Counter(tmp.lower())
    
    size = len(tmp)
    c = {char:occurence/size for char,occurence in c.items()}
    
    dict_to_json(c, 'eng_char_freq.json')



class InvalidPaddingException(Exception):
    def __init__(self, message='Invalid PKCS7 padding'):
        super(InvalidPaddingException, self).__init__(message)

class HighASCIIException(Exception):
    def __init__(self, message='Invalid ASCII symbol'):
        super(HighASCIIException, self).__init__(message)

def pkcs7_pad(data, blocksize):
    pad_len = (blocksize - (len(data) % blocksize)) % blocksize if len(data)%blocksize else blocksize
    return data + pad_len * bytes([pad_len])

def pkcs7_unpad(data):
    pad_len = 1
    last_byte = bytearray(data)[-pad_len]
    while True:
        if bytearray(data)[-pad_len] != last_byte:
            pad_len -= 1
            break
        pad_len += 1
    for i in range(1, pad_len+1):
        if data[-i] != pad_len:
            raise InvalidPaddingException
    return data[:-pad_len]

def get_blocks(data, blocksize):
    return [data[start:start+blocksize] for start in range(0, len(data), blocksize)]

def repeating_xor(bytearr1, bytearr2):
    if len(bytearr1) >= len(bytearr2):
        bytearr2 = cycle(bytearr2)
    else:
        bytearr1 = cycle(bytearr1)
    return bytes(a ^ b for a, b in zip(bytearr1, bytearr2))

def xor(data1, data2):
    if len(data1) >= len(data2):
        data2 = data2[:len(data1)]
    else:
        data1 = data1[:len(data2)]
    return bytes(a ^ b for a, b in zip(data1, data2))

def aes_ecb_encrypt(bytearr, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(bytearr)

def aes_ecb_decrypt(bytearr, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(bytearr)


def aes_cbc_encrypt(bytearr, key, IV=None, blocksize=16):
    if IV == None:
        IV = b'0' * blocksize
    bytearr = pkcs7_pad(bytearr, blocksize)
    blocks = [bytearr[start:start+blocksize] for start in range(0, len(bytearr), blocksize)]
    prev_encrypted = IV
    out_blocks = []
    for block in blocks:
        encrypted = aes_ecb_encrypt(repeating_xor(block, prev_encrypted), key)
        out_blocks.append(encrypted)
        prev_encrypted = encrypted
    return b''.join([block for block in out_blocks])

def aes_cbc_decrypt(bytearr, key, IV=None, blocksize=16):
    if IV == None:
        IV = b'0' * blocksize
    blocks = [bytearr[start:start+blocksize] for start in range(0, len(bytearr), blocksize)]
    prev_block = IV
    out_blocks = []
    for block in blocks:
        decrypted = repeating_xor(aes_ecb_decrypt(block, key), prev_block)
        out_blocks.append(decrypted)
        prev_block = block
    return pkcs7_unpad(b''.join([block for block in out_blocks]))

def generate_keystream(key, nonce):
    return aes_ecb_encrypt(bytes([0] * 8) + nonce.to_bytes(8, 'little'), key)

def aes_ctr(data, key, nonce):
    keystream = b''
    while len(keystream) < len(data):
        keystream += generate_keystream(key, nonce)
        nonce += 1
    return bytes([a ^ b for a,b in zip(data, keystream[:len(data)])])

# used in SHA1Hash
def _left_rotate(n, b):
    """Left rotate a 32-bit integer n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
def _process_chunk(chunk, h0, h1, h2, h3, h4):
    """Process a chunk of data and return the new digest variables."""
    assert len(chunk) == 64

    w = [0] * 80

    # Break chunk into sixteen 4-byte big-endian words w[i]
    for i in range(16):
        w[i] = struct.unpack(b'>I', chunk[i * 4:i * 4 + 4])[0]

    # Extend the sixteen 4-byte words into eighty 4-byte words
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    # Initialize hash value for this chunk
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    for i in range(80):
        if 0 <= i <= 19:
            # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
            f = d ^ (b & (c ^ d))
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        elif 60 <= i <= 79:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff,
                         a, _left_rotate(b, 30), c, d)

    # Add this chunk's hash to result so far
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff

    return h0, h1, h2, h3, h4

class SHA1Hash(object):
    """A class that mimics that hashlib api and implements the SHA-1 algorithm."""

    name = 'python-sha1'
    digest_size = 20
    block_size = 64

    def __init__(self):
        # Initial digest variables
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b''
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0

    def update(self, arg):
        """Update the current digest.
        This may be called repeatedly, even after calling digest or hexdigest.
        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = _process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self

    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        return b''.join(struct.pack(b'>I', h) for h in self._produce_digest())

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return '%08x%08x%08x%08x%08x' % self._produce_digest()

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # append the bit '1' to the message
        message += b'\x80'

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        message += struct.pack(b'>Q', message_bit_length)

        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = _process_chunk(message[:64], *self._h)
        if len(message) == 64:
            return h
        return _process_chunk(message[64:], *h)


    

big_p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff"
big_p = int(big_p, 16)

def diffie_hellman():
    p = big_p
    g = 2
    
    a = np.random.randint(2**16) % p
    A = (g**a) % p
    b = np.random.randint(2**16) % p
    B = (g**b) % p

    return (B**a) % p

def numtobytes(num):
    return num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')

def bytestonum(data):
    return int.from_bytes(data, 'big')


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
