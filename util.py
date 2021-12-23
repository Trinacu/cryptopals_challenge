import os
import json
import numpy as np
from collections import Counter

from itertools import zip_longest
from itertools import cycle
from Crypto.PublicKey.DSA import generate

from Crypto.Cipher import AES

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

def generate_keystream(key, nonce):
    return aes_ecb_encrypt(bytes([0] * 8) + nonce.to_bytes(8, 'little'), key)
        
def aes_ctr(data, key, nonce):
    keystream = b''
    while len(keystream) < len(data):
        keystream += generate_keystream(key, nonce)
        nonce += 1
    return bytes([a ^ b for a,b in zip(data, keystream[:len(data)])])
