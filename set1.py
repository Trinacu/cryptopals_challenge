import codecs
import os
import numpy as np
import itertools

from util import *

from collections import Counter

from Crypto.Cipher import AES
from Crypto.Util import Padding

def hamming_dist(bytearr1, bytearr2):
    xor_bytes = repeating_xor(bytearr1, bytearr2)
    return sum(bin(byte).count("1") for byte in xor_bytes)
  

def hex2bytes(hexString):
    return codecs.decode(hexString, 'hex')


print("\n-----------")
print("Challenge 2")
xor1="1c0111001f010100061a024b53535009181c"
xor2="686974207468652062756c6c277320657965"
print(repeating_xor(hex2bytes(xor1), hex2bytes(xor2)).decode())

print("\n-----------")
print("Challenge 3")
encrypted_hex="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
for i in range(256):
    decrypted = repeating_xor(hex2bytes(encrypted_hex), [i])
    # nasty way of handling it?
    try:
        decrypted = decrypted.decode()
    except UnicodeDecodeError:
        continue
    score = englishness(decrypted.encode())
    if score > 0.8:
        print(decrypted)

print("\n-----------")
print("Challenge 4")
with open(os.path.join('txt', 'challenge4.txt'), 'r') as f:
    lines = f.readlines()
for line in lines:
    # get rid of whitespace
    line = line.rstrip()
    for i in range(256):
        decrypted = repeating_xor(hex2bytes(line), [i])
        # nasty way of handling it?
        try:
            decrypted = decrypted.decode()
        except UnicodeDecodeError:
            continue
        score = englishness(decrypted.encode())
        if score > 0.8:
            print(decrypted)

print("\n-----------")
print("Challenge 5")
inStr = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
encrypted = repeating_xor(codecs.encode(inStr, 'utf-8'), b"ICE")
print(codecs.encode(encrypted, 'hex').decode())

print("\n-----------")
print("Challenge 6: decrypt repeating xor")
with open(os.path.join('txt', 'challenge6.txt'), 'r') as f:
    strIn = f.read()
  
strIn = codecs.decode(bytes(strIn, 'utf-8'), 'base64')
  
num_blocks = 4
best_keysizes = []
for KEYSIZE in range(2, 41):
    strings = [strIn[i*KEYSIZE:(i+1)*KEYSIZE] for i in range(num_blocks)]
    dist_sum = 0
    # build all combinations and calculate average hamming distance
    dist = sum([hamming_dist(arr1, arr2) for arr1, arr2 in itertools.combinations(strings, 2)]) / KEYSIZE
    best_keysizes.append([KEYSIZE, dist])

best_keysizes = sorted(best_keysizes, key=lambda x:x[1])

for keysize, hamm_dist in best_keysizes[:1]:
    print("\nkeysize: {}\thamming dist: {:.3f}".format(keysize, hamm_dist))
    rows = [strIn[i*keysize:(i+1)*keysize] for i in range(int(len(strIn)/keysize))]
    #rows = [strIn[i*keysize:(i+1)*keysize] for i in range(30)]
    arr = [[chr(char) for char in row] for row in rows]
    key = []
    for transposed in zip(*arr):
        max_score = 0
        transposed = ''.join(transposed)
        #print(transposed)
        for i in range(256):
            decrypted = repeating_xor(transposed.encode(), [i])
            # nasty way of handling it?
            try:
                decrypted = decrypted.decode()
            except UnicodeDecodeError:
                continue
            score = englishness(decrypted.encode())
            if score > max_score:
                max_score = score
                char = i
        #print(max_score)
        key.append(chr(char))
    print(''.join(key))

print("\n-----------")
print("Challenge 7: AES-ECB")
with open(os.path.join('txt', 'challenge7.txt'), 'r') as f:
    strIn = f.read()
  
strIn = codecs.decode(bytes(strIn, 'utf-8'), 'base64')
key = "YELLOW SUBMARINE"

cipher = AES.new(codecs.encode(key, 'utf-8'), AES.MODE_ECB)

msg = cipher.decrypt(strIn)
print(msg.decode())


