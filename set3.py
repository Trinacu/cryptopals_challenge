import codecs

import struct

import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from util import *
from numpy.random.mtrand import seed

key = None
IV = None
seed = None

    

def aes_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def aes_cbc_encrypt(data, key, IV, blocksize=16):
    data = pkcs7_pad(data, blocksize)
    blocks = get_blocks(data, blocksize)
    prev_encrypted = IV
    out_blocks = []
    for block in blocks:
        xor = bytes(a ^ b for a, b in zip(block, prev_encrypted))
        encrypted = aes_ecb_encrypt(xor, key)
        out_blocks.append(encrypted)
        prev_encrypted = encrypted
    return b''.join(out_blocks)

def aes_cbc_decrypt(data, key, IV, blocksize=16):
    blocks = get_blocks(data, blocksize)
    prev_block = IV
    out_blocks = []
    for block in blocks:
        if len(block) != blocksize:
            print(len(block))
        decrypted = aes_ecb_decrypt(block, key)
        xor = bytes(a ^ b for a, b in zip(decrypted, prev_block))
        out_blocks.append(xor)
        prev_block = block
    return pkcs7_unpad(b''.join(out_blocks))

def get_affix_length(encryption_function):
    prev_len = len(encryption_function(b''))
    i = 1
    while True:
        encrypted = encryption_function(i * b'0')
        if len(encrypted) != prev_len:
            return len(encrypted) - i
        i += 1

def get_blocksize(encryption_function):
    prev_len = len(encryption_function(b''))
    i = 1
    while True:
        encrypted = encryption_function(i * b'0')
        if len(encrypted) != prev_len:
            return len(encrypted) - prev_len
        i += 1

lines = []

def generate_token():
    global key
    if key == None:
        key = get_random_bytes(16)
    global IV
    if IV == None:
        IV = get_random_bytes(16)
    global lines
    data = codecs.decode(lines[np.random.randint(len(lines))].encode(), 'base64')
    print('generated token from text: {}'.format(data))
    return IV, aes_cbc_encrypt(data, key, IV)

def cbc_padding_oracle(encrypted):
    global key
    global IV
    try:
        aes_cbc_decrypt(encrypted, key, IV)
    except InvalidPaddingException:
        return False
    return True

def xor_byte(data, idx, val):
    data = list(data)
    data[idx] ^= val
    return bytes(data)


def single_block_cbc_attack(data, IV, ecbDecrypted, text):
    for pad_len in range(1, 17):
        prefix = bytearray(get_random_bytes(blocksize - pad_len))
        suffix = bytes([ch ^ pad_len for ch in ecbDecrypted[:len(ecbDecrypted)%16]])
        for i in range(255, -1, -1):
            inject = prefix + bytes([i]) + suffix
            # current ecbDecrypted byte is XORed with previous block to get plaintext (IV for first block)
            prevBlock = data[-32:-16] if len(data) > 16 else IV
            # inject block into data at penultimate position (this will xor it with ecbDecrypted of current block)
            s = data[:-16] + inject + data[-16:]
            
            # TODO - problem here! why does this not always give 16 bytes long array?
            # if we cycle through all 256 bytes and don't find a match we get 15 long array!
            # how can we not find a match, though?

            # what if we stumble upon padding of length 2 and think it is '0x01'?
            # this would probably fail ...
            if cbc_padding_oracle(s):
                currByte = i ^ pad_len
                textByte = prevBlock[-pad_len] ^ currByte
                ecbDecrypted = bytes([currByte]) + ecbDecrypted
                text = bytes([textByte]) + text
                break
            # TODO - look comment ~10 lines earlier!
            if i == 0:
                print('oh wow')
    return ecbDecrypted, text

run = [True, False, False, False, False, False, False, False]
        
print("SET 3")
if run[0]:
    print("\n-----------")
    print("Challenge 17 - CBC padding oracle")
    # solution 'influenced' by
    # https://github.com/akalin/cryptopals-python3/blob/master

    with open(os.path.join('txt', 'challenge17.txt'), 'r') as f:
        lines = f.readlines()
    lines = [line.strip('\n') for line in lines]
    
    IV, data = generate_token()
    
    blocksize = 16
    
    ecbDecrypted = b''
    text = b''
    while len(data) > 0:
        ecbDecrypted, text = single_block_cbc_attack(data, IV, ecbDecrypted, text)
        data = data[:-16]
        print('len(data): ' + str(len(data)))
        
    print(pkcs7_unpad(text))

        
if run[1]:
    print("\n-----------")
    print("Challenge 18 - CTR: stream cipher mode")
    
    data = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    data = codecs.decode(data, 'base64')
    key = b'YELLOW SUBMARINE'
    print(aes_ctr(data, key, 0))
    
    
def aes_ctr_zerononce(data, key):
    nonce = 0
    keystream = b''
    while len(keystream) < len(data):
        keystream += generate_keystream(key, nonce)
    return bytes([a ^ b for a,b in zip(data, keystream[:len(data)])])


if run[2]:
    print("\n-----------")
    print("Challenge 19 - Break fixed-nonce CTR")
    # this works, but is not quite accurate? some bytes seem a bit off
    with open(os.path.join('txt', 'challenge19.txt'), 'r') as f:
        lines = f.readlines()
    lines = [codecs.decode(line.strip('\n').encode(), 'base64') for line in lines]

    key = get_random_bytes(16)
    ciphers = [aes_ctr_zerononce(line, key) for line in lines]
    
    transposed = transpose_bytearrays(ciphers, '%')
    keystream = bytearray(16)
    for pos in range(16):
        #print(pos, data)
        max_score = 0
        for i in range(256):
            line = repeating_xor(bytes([i]), transposed[pos])
            score = englishness(line)
            if score > max_score:
                keystream[pos] = i
                max_score = score
    for cipher in ciphers:
        print(repeating_xor(cipher, keystream))

def get_keystream_fixed_nonce_ctr(ciphers):
    min_len = 1000
    for cipher in ciphers:
        if len(cipher) < min_len:
            min_len = len(cipher)
    ciphers = [cipher[:min_len] for cipher in ciphers]
    transposed = transpose_bytearrays(ciphers, '%')
    #keystream = bytearray(len(ciphers[0]))
    #for pos in range(len(ciphers[0])):
    keystream = bytearray(16)
    for pos in range(16):
        max_score = 0
        for i in range(256):
            line = repeating_xor(bytes([i]), transposed[pos])
            score = englishness(line)
            if score > max_score:
                keystream[pos] = i
                max_score = score
    return keystream
    
def get_keystream_fixed_nonce_ctr2(ciphers):
    min_len = min([len(cipher) for cipher in ciphers])
    #ciphers = [cipher[:min_len] for cipher in ciphers]
    transposed = transpose_bytearrays(ciphers, '%')
    keystream = bytearray(16)
    for pos in range(16):
        scores = [englishness(repeating_xor(bytes([i]), transposed[pos])) for i in range(256)]
        keystream[pos] = scores.index(max(scores))
    return keystream

if run[3]:
    print("\n-----------")
    print("Challenge 20 - Break fixed-nonce CTR statistically")
    # seems like we solved a good portion of this in 19?
    with open(os.path.join('txt', 'challenge20.txt'), 'r') as f:
        lines = f.readlines()
    lines = [codecs.decode(line.strip('\n').encode(), 'base64') for line in lines]
    
    key = get_random_bytes(16)
    ciphers = [aes_ctr_zerononce(line, key) for line in lines]
    keystream = get_keystream_fixed_nonce_ctr2(ciphers)
    for cipher in ciphers:
        print(repeating_xor(cipher, keystream))




class MT19937:
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC6000
    l = 18
    f = 1812433253
    
    def __init__(self, seed):
        self.MT = np.zeros(MT19937.n, dtype=np.int64)
        self.index = MT19937.n + 1
        self.lower_mask = (1 << MT19937.r) - 1
        self.upper_mask = ~self.lower_mask & ((1 << MT19937.w) - 1)
        self.seed_mt(seed)
    
    def seed_mt(self, seed):
        self.index = MT19937.n
        self.MT[0] = seed
        for i in range(1, MT19937.n):
            # lowest w bits of (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i)
            self.MT[i] = ((1 << MT19937.w) - 1) & \
            (MT19937.f * (self.MT[i-1] ^ (self.MT[i-1] >> (MT19937.w-2))) + i)
            
    def temper(self):
        if self.index >= MT19937.n:
            if self.index > MT19937.n:
                raise Exception("generator was never seeded!")
                # or seed with a value (5489 is used in 'reference' C code)
            self.twist()
        y = self.MT[self.index]
        # MT19937.d is 0xFFFFFFFF so this & doesn't change anything
        y = y ^ ((y >> MT19937.u) & MT19937.d)
        y = y ^ ((y << MT19937.s) & MT19937.b)
        y = y ^ ((y << MT19937.t) & MT19937.c)
        y = y ^ (y >> MT19937.l)
        
        self.index += 1
        # return last w bits (also convert to int32?)
        return int(((1 << MT19937.w) - 1) & y)
        
            
    def twist(self):
        for i in range(MT19937.n-1):
            x = (self.MT[i] & self.upper_mask + self.MT[i+1] % MT19937.n) & self.lower_mask
            xA = x >> 1
            if (x % 2) != 0: # if lowest bit of x is 1
                xA = xA ^ MT19937.a
            self.MT[i] = self.MT[(i+MT19937.m) % MT19937.n] ^ xA
        self.index = 0


if run[4]:
    print("\n-----------")
    print("Challenge 21 - Implement MT19937 Mersenne Twister")
    
    gen = MT19937(123)
    print(gen.temper())
    
def generate_rand():
    min_time = 40
    max_time = 100
    time.sleep(np.random.randint(min_time, max_time))
    # this shouldnt be an int?
    seed = int(time.time())
    gen = MT19937(seed)
    time.sleep(np.random.randint(min_time, max_time))
    # return lowest 32 bits
    return gen.temper(), seed

def compare_seeds(seed1, seed2):
    N = 10000
    gen1 = MT19937(seed1)
    gen2 = MT19937(seed2)
    for i in range(N):
        if gen1.temper() != gen2.temper():
            return False
    return True

if run[5]:
    print("\n-----------")
    print("Challenge 22 - Crack an MT19937 seed")
    rng, seed = generate_rand()
    print('original seed: {}'.format(seed))
    for i in range(int(time.time()), int(time.time())-300, -1):
        gen = MT19937(i)
        if gen.temper() == rng:
            # first number matches, let's verify!
            if compare_seeds(i, seed):
                print('found seed! seed={}'.format(i))
                break


# these 2 functions are stolen from
# https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
def unshift_right_xor(value, shift):
    i = 0
    result = 0
    while (i * shift < 32):
        # MUST & with 0xFFFFFFFF so we don't get numbers higher than 32bit!
        partMask = ((((1 << MT19937.w) - 1) << (32 - shift)) & 0xFFFFFFFF) >> (shift * i)
        part = value & partMask
        value ^= part >> shift
        result |= part
        i += 1
    return result

def unshift_left_xor_mask(value, shift, mask):
    i = 0
    result = 0
    while (i * shift < 32):
        partMask = (((1 << MT19937.w) - 1) >> (32 - shift)) << (shift * i)
        part = value & partMask
        value ^= (part << shift) & mask
        result |= part
        i += 1
    return result

def untemper(val):
    val = unshift_right_xor(val, MT19937.l)
    val = unshift_left_xor_mask(val, MT19937.t, MT19937.c)
    val = unshift_left_xor_mask(val, MT19937.s, MT19937.b)
    val = unshift_right_xor(val, MT19937.u)
    return val

if run[6]:
    print("\n-----------")
    print("Challenge 23 - Clone MT19937 from its output")

    gen = MT19937(np.random.randint(1, 124245))
    X = np.zeros(MT19937.n, dtype=np.int64)
    for i in range(MT19937.n):
        X[i] = untemper(gen.temper())

    gen2 = MT19937(0)
    gen2.MT = X

    success = True
    for _ in range(1000):
        if (gen.temper() != gen2.temper()):
            success = False
    if success:
        print('successfully made a MT clone from {} outputs!'.format(MT19937.n))


class MT19937_cipher():
    def __init__(self, key):
        self._rng = MT19937(key)

    def encrypt(self, data):
        if len(data) == 0:
            return b''
        keystream = b''
        while len(keystream) < len(data):
            keystream += struct.pack('<L', self._rng.temper())
            
        keystream = keystream[:len(data)]
        return bytes([a ^ b for a, b in zip(keystream, data)])

def encrypt_c24(data):
    global seed
    if (seed == None):
        # 16-bit seed
        seed = np.random.randint(2**16)
    cipher = MT19937_cipher(seed)
    
    data = get_random_bytes(np.random.randint(4, 20)) + data
    return cipher.encrypt(data)

def find_seed(encryption_function):
    text = b'A' * 14
    cipher = encryption_function(text)
    prefix_len = len(cipher) - len(text)
    for seed in range(2**16):
        gen = MT19937_cipher(seed)
        if gen.encrypt(b'A' * len(cipher))[prefix_len:] == cipher[prefix_len:]:
            return seed
    raise Exception("not expected")

def generate_token(email):
    gen = MT19937_cipher(int(time.time()))
    return gen.encrypt(b'A' * np.random.randint(4, 20) + email.encode())

def find_token_timestamp(token, email):
    prefix_len = len(token) - len(email)
    for seed in range(int(time.time()), int(time.time())-600, -1):
        gen = MT19937_cipher(seed)
        if gen.encrypt(b'A' * prefix_len + email.encode())[prefix_len:] == token[prefix_len:]:
            return seed

if run[7]:
    print("\n-----------")
    print("Challenge 24 - Create MT19937 stream cipher and break it")

    seed = find_seed(encrypt_c24)
    print('found seed: {}'.format(seed))
    email = 'test@mail.com'
    token = generate_token(email)
    timestamp = find_token_timestamp(token, email)
    print('found timestamp: {}'.format(timestamp))




    
