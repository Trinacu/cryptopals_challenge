import codecs
import numpy as np

from itertools import cycle

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from util import *

key = None
IV = None

class InvalidPaddingException(Exception):
    def __init__(self, message='Invalid PKCS7 padding'):
        super(InvalidPaddingException, self).__init__(message)

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
    print(data)
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
            # inject p into data at penultimate position (this will xor it with ecbDecrypted of current block)
            s = data[:-16] + inject + data[-16:]
            if len(s) % 16:
                print(len(prefix), len(suffix), len(inject))
            # what if we stumble upon padding of length 2 and think it is '0x01'?
            # this would probably fail ...
            if cbc_padding_oracle(s):
                currByte = i ^ pad_len
                textByte = prevBlock[-pad_len] ^ currByte
                ecbDecrypted = bytes([currByte]) + ecbDecrypted
                text = bytes([textByte]) + text
                break
    return ecbDecrypted, text

run = [False, True, False, True]
        
print("SET 3")
if run[0]:
    print("\n-----------")
    print("Challenge 17 - CBC padding oracle")
    # solution 'influenced' by
    # https://github.com/akalin/cryptopals-python3/blob/master

    with open('challenge17.txt', 'r') as f:
        lines = f.readlines()
    lines = [line.strip('\n') for line in lines]
    
    IV, data = generate_token()
    
    blocksize = 16
    
    ecbDecrypted = b''
    text = b''
    while len(data) > 0:
        ecbDecrypted, text = single_block_cbc_attack(data, IV, ecbDecrypted, text)
        data = data[:-16]
        print(data)
        
    print(pkcs7_unpad(text))

def generate_keystream(nonce, key):
    return aes_ecb_encrypt(bytes([0] * 8) + nonce.to_bytes(8, 'little'), key)
        
def aes_ctr(data, key, nonce):
    keystream = b''
    while len(keystream) < len(data):
        keystream += generate_keystream(nonce, key)
        nonce += 1
    return bytes([a ^ b for a,b in zip(data, keystream[:len(data)])])

        
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
        keystream += generate_keystream(nonce, key)
    return bytes([a ^ b for a,b in zip(data, keystream[:len(data)])])


if run[2]:
    print("\n-----------")
    print("Challenge 19 - Break fixed-nonce CTR")
    # this works, but is not quite accurate? some bytes seem a bit off
    with open('challenge19.txt', 'r') as f:
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
            score = sum([englishness(repeating_xor(bytes([i]), bytes([transposed[k][pos]]))) for \
                         k in range(len(transposed))]) / len(transposed)
            if score > max_score:
                keystream[pos] = i
                max_score = score
    return keystream

if run[3]:
    print("\n-----------")
    print("Challenge 20 - Break fixed-nonce CTR statistically")
    # seems like we solved a good portion of this in 19?
    with open('challenge20.txt', 'r') as f:
        lines = f.readlines()
    lines = [codecs.decode(line.strip('\n').encode(), 'base64') for line in lines]
    
    key = get_random_bytes(16)
    ciphers = [aes_ctr_zerononce(line, key) for line in lines]
    keystream = get_keystream_fixed_nonce_ctr2(ciphers)
    print(repeating_xor(ciphers[0], keystream))


    
    
