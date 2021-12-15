import codecs
import numpy as np

from collections import Counter

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

def englishness(string_to_score):
    c = Counter(string_to_score.lower())
    
    coefficient = sum(
        np.sqrt(ENG_CHAR_FREQ_TABLE.get(char.encode(), 0) * y/len(string_to_score))
        for char, y in c.items()
        )
    return coefficient



target_bytes = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

key = None

def generate_rand_bytes(num_bytes):
    return bytes([np.random.randint(256) for _ in range(num_bytes)])


def pkcs7_pad(bytearr, blocksize):
    pad_len = blocksize if len(bytearr) == 0 else blocksize - (len(bytearr) % blocksize)
    return bytearr + pad_len * bytes([pad_len])

def ecb_blackbox(bytearr):
    global target_bytes
    global key
    if key == None:
        key = generate_rand_bytes(16)
    # append target bytes
    bytearr += codecs.decode(target_bytes.encode(), 'base64')
    
    if len(bytearr) % 16:
        bytearr = pkcs7_pad(bytearr, 16)
    
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(bytearr)

def get_blocksize(encryption_function):
    prev_len = len(encryption_function(b''))
    i = 1
    while True:
        encrypted = encryption_function(i * b'0')
        if len(encrypted) != prev_len:
            return len(encrypted) - i
        i += 1

def get_blocks(data, blocksize):
    return [data[start:start+blocksize] for start in range(0, len(data), blocksize)]

def find_next_byte(encryption_function, blocksize, knownBytes):
    s = b'0' * (blocksize - len(knownBytes) % blocksize - 1)
    d = {}
    for i in range(256):
        encrypted = encryption_function(s + knownBytes + bytes([i]))
        d[encrypted[0:len(s) + len(knownBytes) + 1]] = i
    encrypted = encryption_function(s)[0:len(s) + len(knownBytes) + 1]
    if encrypted in d:
        return bytes([d[encrypted]])
    else:
        return None
     
print("SET 2")
print("\n------------------")
print("Challenge 12 - ECB decryption byte at a time\n")

blocksize = get_blocksize(ecb_blackbox)
text = b''
while True:
    ret = find_next_byte(ecb_blackbox, 16, text)
    if ret == None:
        break
    text += ret
print(text)


def k_v_parse(string):
    strings = string.split('&')
    return {key: val for key,val in [string.split('=') for string in strings]}

def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return k_v_parse('email={}&uid={}&role=user'.format(email, 10))

def encode_user(usr):
    return 'email={}&uid={}&role={}'.format(usr['email'], usr['uid'], usr['role'])

def encrypted_profile(email):
    global key
    if key == None:
        key = generate_rand_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
           
    bytearr = encode_user(profile_for(email)).encode()
    if len(bytearr) % 16:
        bytearr = pkcs7_pad(bytearr, 16)
    
    return cipher.encrypt(bytearr)

def decrypt_profile(profile):
    global key
    cipher = AES.new(key, AES.MODE_ECB)
    
    return cipher.decrypt(profile)

print("\n------------------")
print("Challenge 13 - ECB cut and paste\n")

print(encode_user(profile_for('test=&@mail')))

usr = encrypted_profile('email@test.com')

print(usr)
print(decrypt_profile(usr))

# generate blocks like 'user[padding]' and 'admin[padding]' and then replace them
# overflow 4 characters to get 'user[padding]' block
prev_len = len(encrypted_profile(''))
i = 1
cnt = 0
while True:
    print(len(encrypted_profile(i * '0')))
    if len(encrypted_profile(i * '0')) != prev_len:
        cnt += 1
        if cnt == 4:
            encrypted_roleuser = encrypted_profile(i * '0')
            break
    i += 1

print(decrypt_profile(get_blocks(encrypted_roleuser, 16)[-1]))




