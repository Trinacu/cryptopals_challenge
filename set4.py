import os
import codecs

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from util import *

run = [False, True, True]

key = None

# MISSING SOME CHALLENGES: 29 - 32

print("SET 4")

def edit_ctr_ciphertext(ciphertext, offset, newtext):
    new_ciphertext = aes_ctr(b'0' * offset + newtext, key, 0)
    suffix = b'' if (len(newtext) > len(ciphertext) - offset) else ciphertext[len(new_ciphertext):]
    return ciphertext[:offset] + new_ciphertext[offset:] + suffix

if run[0]:
    print("\n-----------")
    print("Challenge 25 - 'Break random access r/w' AES CTR")

    with open(os.path.join('txt', 'challenge7.txt'), 'r') as f:
        strIn = f.read()
    strIn = codecs.decode(bytes(strIn, 'utf-8'), 'base64')
    key = "YELLOW SUBMARINE"
    cipher = AES.new(codecs.encode(key, 'utf-8'), AES.MODE_ECB)
    data = cipher.decrypt(strIn)

    key = get_random_bytes(16)
    ciphertext = aes_ctr(data, key, 0)

    plaintext = edit_ctr_ciphertext(ciphertext, 0, ciphertext)
    print(plaintext)


def encode_userdata_c26(string):
    global key
    prefix = 'comment1=cooking%20MCs;userdata='
    suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
    data = (prefix + string.replace(';', '%3B').replace('=', '%3D') + suffix).encode()
    return aes_ctr(data, key, 0)

def decode_userdata_c26(data):
    global key
    return aes_ctr(data, key, 0)

if run[1]:
    print("\n-----------")
    print("Challenge 26 - CTR bitflipping attack")

    key = get_random_bytes(16)

    data = encode_userdata_c26('tmp:admin<true')
    tmp = list(data)
    tmp[35] ^= 1
    tmp[41] ^= 1
    
    print(decode_userdata_c26(bytes(tmp)))


def encode_userdata_c27(string):
    global key
    prefix = 'comment1=cooking%20MCs;userdata='
    suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
    data = (prefix + string.replace(';', '%3B').replace('=', '%3D') + suffix).encode()
    return aes_cbc_encrypt(data, key, key)

def decode_userdata_c27(data):
    global key
    string = aes_cbc_decrypt(data, key, key)
    if any([x > 127 for x in string]):
        raise ValueError(string)
    return string
    

if run[1]:
    print("\n-----------")
    print("Challenge 27 - Recover CBC key with IV=key")
    
    key = get_random_bytes(16)

    data = bytearray(encode_userdata_c27('test'))
    tampered = data[:16] + bytes([0] * 16) + data[:16] + data[16:]
    
    try:
        plaintext = decode_userdata_c27(tampered)
    except ValueError as e:
        text = e.args[0]
        extracted_key = bytes(text[i] ^ text[32+i] for i in range(16))
        if key == extracted_key:
            print('found correct key: {}'.format(extracted_key))

def auth_SHA1(data, key):
    return SHA1Hash(key + data).digest()

def validate(message, digest):
    global key
    return auth_SHA1(message, key) == digest

if run[1]:
    print("\n-----------")
    print("Challenge 28 - SHA-1 keyed MAC")

    msg = b'test123123'
    msg_digest = auth_SHA1(msg, key)
    
    print(validate(msg, msg_digest))
    

def padSHA1(data):
    padding = b"\x80" + b"\x00" * (63 - (len(data) + 8) % 64)
    # '>Q' - big endian unsigned long long (8 bytes)
    padded_data = data + padding + struct.pack('>Q', 8 * len(data))
    return padded_data

def forgeHash(keylen, message, digest, suffix):
    paddedForgedMessageWithKey = padSHA1(key + message) + suffix
    forgedMessage = paddedForgedMessageWithKey[:keylen]
    h = struct.unpack('>5I', digest)
    forgedDigest = SHA1Hash(suffix, h[0], h[1], h[2], h[3], h[4], len(paddedForgedMessageWithKey)*8).digest()
    return (forgedMessage, forgedDigest)

def forgeValidatingHash(maxkeylen, message, digest, suffix):
    for i in range(maxkeylen):
        (forgedMessage, forgedDigest) = forgeHash(i, message, digest, suffix)
        if validate(forgedMessage, forgedDigest):
            return (forgedMessage, forgedDigest)
    raise Exception('unexpected')

    
if run[2]:
    print("\n-----------")
    print("Challenge 29 - Break SHA-1 keyed MAC using length extension")

    maxkeylen = 100
    keylen = np.random.randint(maxkeylen)
    key = get_random_bytes(keylen)
    
    msg = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    msg_digest = auth_SHA1(msg, key)

    print(forgeValidatingHash(maxkeylen, msg, msg_digest, b';admin=true'))
    

