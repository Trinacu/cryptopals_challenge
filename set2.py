import os
import codecs
import numpy as np
from collections import Counter

from util import *

import itertools

key = None
prefix = None
suffix = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""



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
        
def get_affix_length_str(encryption_function):
    prev_len = len(encryption_function(''))
    i = 1
    while True:
        encrypted = encryption_function(i * '0')
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

def encryption_oracle(bytearr, key=None, blocksize=16, return_mode=True):
    # prepend and append 5-10 bytes
    bytearr = generate_rand_bytes(np.random.randint(5,11)) + bytearr + generate_rand_bytes(np.random.randint(5,11))
    if len(bytearr) % blocksize:
        bytearr = pkcs7_pad(bytearr, blocksize)
    if key == None:
        key = generate_rand_bytes(blocksize)
    # use ECB half the time and CBC the other half
    if np.random.randint(2) > 0:
        if return_mode:
            return aes_ecb_encrypt(bytearr, key), 'ECB'
        else:
            return aes_ecb_encrypt(bytearr, key)
    else:
        if return_mode:
            return aes_cbc_encrypt(bytearr, key, generate_rand_bytes(blocksize), blocksize), 'CBC'
        else:
            return aes_cbc_encrypt(bytearr, key, generate_rand_bytes(blocksize), blocksize)

def detect_ecb_challenge11(encryption_function):
    ecb_confirmed = False
    # use repeating string to detect ECB
    strIn = "a" * 37
    # set return_mode=True to confirm our prediction
    bytearr, mode = encryption_function(strIn.encode())
    blocks = [bytearr[start:start+16] for start in range(0, len(bytearr), 16)]
    # blocks should be repeating if we are using ECB with repeating byte input (longer than 2*blocksize)
    for block in blocks:
        if blocks.count(block) > 1:
            ecb_confirmed = True
            break
    if ecb_confirmed:
        predict = 'ECB'
    else:
        predict = 'CBC'
    if mode == predict:
        return True, mode
    else:
        return False, mode

def detect_ecb(encryption_function):
    # use 3 identical blocks to guarantee 2 identical blocks of output regardless the alignment
    blocksize = get_blocksize(encryption_function)
    data = 3 * blocksize * b'0'
    encrypted = encryption_function(data)
    blocks = [encrypted[start:start+blocksize] for start in range(0, len(encrypted), blocksize)]
    # blocks should be repeating if we are using ECB with repeating byte input (longer than 2*blocksize)
    for block in blocks:
        if blocks.count(block) > 1:
            return True
    return False

def ecb_blackbox(bytearr, key=None, blocksize=16):
    # append this fixed prefix
    if key == None:
        key = glbFixedKey
    global suffix
    bytearr = bytearr + codecs.decode(bytes(suffix, 'utf-8'), 'base64')
    if len(bytearr) % blocksize:
        bytearr = pkcs7_pad(bytearr, blocksize)
    return aes_ecb_encrypt(bytearr, key)

# RUN ARRAY
run = [True, True, True, True, True, True, True, True]

print('SET 2')
if run[0]:
    print('\n---------------')
    print('Challenge 9: pkcs7 padding')
    print(pkcs7_pad(b'YELLOW SUBMAR', 16))

if run[1]:
    print('\n---------------')
    print('Challenge 10: decode CBC with known key')
    with open(os.path.join('txt', 'challenge10.txt'), 'r') as f:
        strIn = f.read()

    strIn = codecs.decode(bytes(strIn, 'utf-8'), 'base64')
    key = b"YELLOW SUBMARINE"
    bytearr = aes_cbc_decrypt(strIn, key)
    print(bytearr.decode())

    strIn = "to je le testni tekst da vidim ce dela ta predikcija ECB ali CBC, tu je se malo extra za ziher     "
    crypted = aes_cbc_encrypt(strIn.encode(), key)
    print(strIn + '\n' + aes_cbc_decrypt(crypted, key).decode())

if run[2]:
    print('\n---------------')
    print('Challenge 11: ECB/CBC detection')
    for _ in range(3):
        success, mode = detect_ecb_challenge11(encryption_oracle)
        if(success):
            print('successful prediction: ' + mode)

def find_next_byte_c12(encryption_function, blocksize, knownBytes):
    bytearr = bytes([0] * (blocksize - (len(knownBytes) % blocksize) - 1))
    d = {}
    for i in range(256):
        encrypted = encryption_function(bytearr + knownBytes + bytes([i]))
        # key=encrypted value; value = byte
        d[encrypted[0:len(bytearr) + len(knownBytes) + 1]] = i
    encrypted = encryption_function(bytearr)[0:len(bytearr) + len(knownBytes) + 1]
    if encrypted in d:
        return d[encrypted]
    return None

if run[3]:
    print('\n---------------')
    print('Challenge 12: ECB decryption')
    # have a fixed key
    glbFixedKey = generate_rand_bytes(16)

    blocksize = get_blocksize(ecb_blackbox)
        
    if(detect_ecb(ecb_blackbox)):
        text = bytes()
        while True:
            ret = find_next_byte_c12(ecb_blackbox, blocksize, text)
            if ret == None:
                break
            text += bytes([ret])
            
        print(text.decode())
    


def k_v_parse(string):
    return {key:val for key,val in [field.split('=') for field in string.split('&')]}

def profile_for(email):
    email = email.replace("&", "").replace("=", "")
    return k_v_parse('email={}&uid={}&role={}'.format(email, 10, 'user'))

def encode_user(user_dict):
    return '&'.join(['{}={}'.format(k, v) for k,v in user_dict.items()])

def encrypt_user(user_dict, key=None, blocksize=16):
    if key == None:
        key = glbFixedKey
    encoded = encode_user(user_dict).encode()
    if len(encoded) % blocksize:
        encoded = pkcs7_pad(encoded, blocksize)
    return aes_ecb_encrypt(encoded, key)

def decrypt_user(encrypted_user):
    global key
    return k_v_parse(pkcs7_unpad(aes_ecb_decrypt(encrypted_user, key)).decode())

def encrypted_profile(email):
    global key
    if key == None:
        key = generate_rand_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    
    usr = encode_user(profile_for(email.replace("&", "").replace("=", ""))).encode()
    if len(usr) % 16:
        usr = pkcs7_pad(usr, 16)
    return cipher.encrypt(usr)

def get_blocks(data, blocksize):
    return [data[start:start+blocksize] for start in range(0, len(data), blocksize)]
    
if run[4]:
    print('\n---------------')
    print('Challenge 13: ECB cut-and-paste')
    
    usr = encrypted_profile('test@email.com')
    print(decrypt_user(usr))

    prefix_len = blocksize - len('email=')
    suffix_len = blocksize - len('admin')
    roleadmin = encrypted_profile('0' * prefix_len + 'admin' + chr(suffix_len) * suffix_len)

    # why exactly +1?
    affix_len = get_affix_length_str(encrypted_profile) + 1
    email = 'x' * ((blocksize - (affix_len % blocksize)) % blocksize + len('user') - len('@mail.com')) + '@mail.com'
    profile = encrypted_profile(email)

    superuser = profile[0:32] + roleadmin[16:32]
    print(decrypt_user(superuser))


def ecb_blackbox_v2(data):
    global key
    if key == None:
        key = generate_rand_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    global prefix
    if prefix == None:
        prefix = generate_rand_bytes(np.random.randint(55))
    global suffix
    data = prefix + data + codecs.decode(bytes(suffix, 'utf-8'), 'base64')
    if len(data) % 16:
        data = pkcs7_pad(data, 16)
        
    return cipher.encrypt(data)

def find_prefix_block(encryption_function, blocksize):
    x1 = encryption_function(b'')
    x2 = encryption_function(b'0')
    blocks1 = get_blocks(x1, blocksize)
    blocks2 = get_blocks(x2, blocksize)
    for i in range(len(blocks1)):
        if blocks1[i] != blocks2[i]:
            return i

def find_prefix_size_mod_block_size(encryption_function, blocksize):
    def has_equal_block(blocks):
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                return True
        return False

    for i in range(blocksize):
        s = bytes([0] * (2*blocksize + i))
        encrypted = encryption_function(s)
        blocks = get_blocks(encrypted, blocksize)
        if has_equal_block(blocks):
            return blocksize - i


    raise Exception("Not using ECB!")

def find_prefix_size(encryption_function, blocksize):
    return blocksize * find_prefix_block(encryption_function, blocksize) + \
                 find_prefix_size_mod_block_size(encryption_function, blocksize)

def find_next_byte_c14(encryption_function, blocksize, prefixsize, knownBytes):
    p1 = blocksize - (prefixsize % blocksize)
    p2 = blocksize - (len(knownBytes) % blocksize) - 1
    p3 = prefixsize - (prefixsize % blocksize)
    s = bytes([0] * (p1 + p2))
    d = {}
    for i in range(256):
        encrypted = encryption_function(s + knownBytes + bytes([i]))
        d[encrypted[p3+p1:p3+p1+p2 + len(knownBytes) + 1]] = i
    encrypted = encryption_function(s)
    u = encrypted[p3+p1:p3+p1+p2 + len(knownBytes) + 1]
    if u in d:
        return bytes([d[u]])
    return None

if run[5]:
    print('\n---------------')
    print('Challenge 14: ECB decryption (harder)')

    blocksize = get_blocksize(ecb_blackbox_v2)
    prefixsize = find_prefix_size(ecb_blackbox_v2, 16)
    text = b''
    while True:
        b = find_next_byte_c14(ecb_blackbox_v2, blocksize, prefixsize, text)
        if b is None:
            break
        text += b
    print(text.decode())
    # find prefix size. not sure if a fixed length prefix is correct in the sense of the challenge?



if run[6]:
    print('\n---------------')
    print('Challenge 15: PKCS7 padding validation')

    print(pkcs7_unpad(pkcs7_pad(b'00000000', 16)))


def encode_userdata(string):
    global key
    prefix = 'comment1=cooking%20MCs;userdata='
    suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
    data = (prefix + string.replace(';', '%3B').replace('=', '%3D') + suffix).encode()
    return aes_cbc_encrypt(data, key)

def decrypt_userdata(data):
    global key
    return k_v_parse_c16(aes_cbc_decrypt(data, key).decode())

def decrypt_userdata_raw(data):
    global key
    return aes_cbc_decrypt(data, key)

def k_v_parse_c16(string):
    return {key:val for key,val in [field.split('=') for field in string.split(';')]}

def check_admin_c16(data):
    data = decrypt_userdata_raw(data)
    print(data)
    return data.find(b';admin=true;') != -1

if run[7]:
    print('\n---------------')
    print('Challenge 16: CBC bitflipping attacks')
    # break the decryption and set admin=true!

    key = generate_rand_bytes(16)
    
    offset = 16
    inject = ':admin<true:'
    encrypted = encode_userdata(offset * '0' + inject + ((offset - len(inject)) * '0'))
    print(check_admin_c16(encrypted))

    tmp = list(encrypted)
    tmp[32] ^= 1
    tmp[38] ^= 1
    tmp[43] ^= 1
    
    print(check_admin_c16(bytes(tmp)))











