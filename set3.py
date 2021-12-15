import codecs
import numpy as np

from copy import copy

from Crypto.Cipher import AES


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
    print('last bytes of padded data successfully unpadded')
    print(data[-(pad_len+1):])
    return data[:-pad_len]

def aes_ecb_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def aes_cbc_encrypt(data, key, IV, blocksize=16):
    data = pkcs7_pad(data, blocksize)
    blocks = [data[start:start+blocksize] for start in range(0, len(data), blocksize)]
    prev_encrypted = IV
    out_blocks = []
    for block in blocks:
        xor = bytes(a ^ b for a, b in zip(block, prev_encrypted))
        encrypted = aes_ecb_encrypt(xor, key)
        out_blocks.append(encrypted)
        prev_encrypted = encrypted
    return b''.join([block for block in out_blocks])

def aes_cbc_decrypt(data, key, IV, blocksize=16):
    blocks = [data[start:start+blocksize] for start in range(0, len(data), blocksize)]
    prev_block = IV
    out_blocks = []
    for block in blocks:
        decrypted = aes_ecb_decrypt(block, key)
        xor = bytes(a ^ b for a, b in zip(decrypted, prev_block))
        out_blocks.append(xor)
        prev_block = block
    return pkcs7_unpad(b''.join([block for block in out_blocks]))

def generate_rand_bytes(num_bytes):
    return b''.join([bytes([np.random.randint(256)]) for _ in range(num_bytes)])

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

def get_blocks(data, blocksize):
    return [bytearray(data[start:start+blocksize]) for start in range(0, len(data), blocksize)]


lines = []

def generate_token():
    global key
    if key == None:
        key = generate_rand_bytes(16)
    global IV
    if IV == None:
        IV = generate_rand_bytes(16)
    global lines
    data = codecs.decode(lines[np.random.randint(len(lines))].encode(), 'base64')
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

        
print("SET 3")
print("\n-----------")
print("Challenge 17 - CBC padding oracle")
with open('challenge17.txt', 'r') as f:
    lines = f.readlines()
lines = [line.strip('\n') for line in lines]

IV, data = generate_token()
print(data)

# IV (xor) decrypted = plaintext
# IV (xor) plaintext = decrypted


print(cbc_padding_oracle(data))

for i in range(1, 256):
    data2 = copy(data)
    data2 = xor_byte(data2, len(data2)-1, i)
    print(data[-3:], data2[-3:])
    if cbc_padding_oracle(data2):
        print(i)











